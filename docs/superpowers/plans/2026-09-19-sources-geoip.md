# Sources 表 GeoIP 字段 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 5 个 pot 的 `*_sources` 表中增加 `country_code` / `country_name` / `asn` / `asn_org` 四列，新 IP 写入时自动查询 GeoIP 填充，老数据通过一次性迁移脚本回填。

**Architecture:** 新增 `core/geoip.py` 共享模块（`ensure_dbs` + `GeoIPResolver`），从 `alerter.py` 抽取复用；`DBBaseThread` 增加可选 `geoip_resolver` 参数，各 pot 的 `_add_attack` 创建新 Source 时填充 4 字段；独立 `migrate_geoip.py` 脚本由 docker-compose 启动时前置运行，ALTER TABLE 加列并回填 NULL 行。

**Tech Stack:** Python 3, SQLAlchemy ORM, geoip2 (mmdb), SQLite, Docker, pytest

**Spec:** `docs/superpowers/specs/2026-09-19-sources-geoip-design.md`

## Global Constraints

- Python venv 位于容器 `/opt/venv`，本地开发用 `~/ddospot-venv` 或系统 Python 3
- mmdb 文件路径优先取环境变量 `DDOSPOT_GEOIP_DB` / `DDOSPOT_GEOIP_ASN_DB`，默认 `db/GeoIP-Country.mmdb` / `db/GeoIP-ASN.mmdb`
- mmdb CDN: `https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release`，文件名 `Country-without-asn.mmdb` + `GeoLite2-ASN.mmdb`，配套 `.sha256sum` 校验
- 5 个 pot 的 sources 表名分别为：`ntpot_sources` / `dnspot_sources` / `ssdpot_sources` / `chargenpot_sources` / `genericpot_sources`
- `src_ip` 存为 INTEGER：DNS 的 `db_params['ip']` 是字符串（dblogger 内 `addr_to_int`），其余 4 个 pot 的 `db_params['ip']` 已是 int
- 4 个新列全部 nullable；GeoIP 查不到时存 NULL；mmdb 不可用时 resolver=None，蜜罐照常运行
- 所有 pot 的 `_create_dbthread(self, dbfile, new_attack_interval)` 通过 `self.geoip_resolver` 取值（PotLoader 属性），无需改方法签名
- 迁移脚本必须幂等：列已存在跳过 ALTER，已回填行不命中 WHERE NULL

---

## File Structure

| 文件 | 责任 | 变更 |
|---|---|---|
| `ddospot/core/geoip.py` | mmdb 下载校验 + IP→country/ASN 解析 | 新增 |
| `ddospot/migrate_geoip.py` | 一次性 schema 迁移 + NULL 回填 | 新增 |
| `tests/__init__.py` | 测试包标识 | 新增 |
| `tests/conftest.py` | pytest fixtures（tmp_db, fake_mmdb 等）| 新增 |
| `tests/test_geoip.py` | `core/geoip.py` 单元测试 | 新增 |
| `tests/test_migrate_geoip.py` | 迁移脚本单元测试 | 新增 |
| `ddospot/core/alerter.py` | 告警器，改用 geoip 模块 | 修改 |
| `ddospot/core/dbbase.py` | DB 线程基类，加 resolver 参数 | 修改 |
| `ddospot/core/potloader.py` | 创建 resolver 传给 DBThread | 修改 |
| `ddospot/pots/ntp/dblogger.py` | NTP ORM + _add_attack | 修改 |
| `ddospot/pots/dns/dblogger.py` | DNS ORM + _add_attack | 修改 |
| `ddospot/pots/ssdp/dblogger.py` | SSDP ORM + _add_attack | 修改 |
| `ddospot/pots/chargen/dblogger.py` | CHARGEN ORM + _add_attack | 修改 |
| `ddospot/pots/generic/dblogger.py` | GENERIC ORM + _add_attack | 修改 |
| `docker-compose.yml` | command 加迁移前置 | 修改 |

---

## Task 1: 测试基础设施

**Files:**
- Create: `tests/__init__.py` (空)
- Create: `tests/conftest.py`
- Create: `requirements-dev.txt`

**Interfaces:**
- Produces: pytest 可运行环境；fixtures `tmp_db_path`（临时 sqlite 路径）、`fake_old_schema_db`（含老 schema 的 *_sources 表，无 country_code 列）

- [ ] **Step 1: 创建 tests/ 与 requirements-dev.txt**

`tests/__init__.py` 空文件。

`requirements-dev.txt`:
```
pytest>=7.0
geoip2>=4.0
SQLAlchemy>=1.4
```

`tests/conftest.py`:
```python
import pytest
import sqlite3
import os
import tempfile


@pytest.fixture
def tmp_db_path(tmp_path):
    """返回临时 sqlite3 文件路径，测试结束后自动清理"""
    return str(tmp_path / "test.sqlite3")


@pytest.fixture
def fake_old_schema_sources_db(tmp_path):
    """构造一个含 ntpot_sources 老表的 sqlite 库（无 country_code 等新列）"""
    db_path = str(tmp_path / "ntpot.sqlite3")
    conn = sqlite3.connect(db_path)
    conn.executescript('''
        CREATE TABLE ntpot_sources (
            src_ip INTEGER PRIMARY KEY,
            src_port INTEGER,
            first_seen DATETIME,
            last_seen DATETIME
        );
        CREATE TABLE ntpot_attack (
            src_id INTEGER,
            mode SMALLINT,
            start DATETIME,
            latest DATETIME,
            count INTEGER,
            PRIMARY KEY (src_id, mode, start)
        );
        INSERT INTO ntpot_sources (src_ip, src_port, first_seen, last_seen) VALUES
            (134744072, 12345, '2026-09-01 10:00:00', '2026-09-01 10:00:00'),
            (0, 0, '2026-09-01 10:00:00', '2026-09-01 10:00:00');
    ''')
    conn.commit()
    conn.close()
    return db_path
```

注：`134744072` = `8.8.8.8`（用于后续测试 GeoIP 解析为 US/Google）；`0` 是无效 IP（测试 NULL 容错）。

- [ ] **Step 2: 安装 dev 依赖**

Run: `pip install -r requirements-dev.txt`
Expected: 安装成功，`pytest --version` 输出版本号

- [ ] **Step 3: 验证 pytest 可发现测试**

Run: `pytest tests/ -v`
Expected: `no tests ran`（无测试，但无 import 错误）

- [ ] **Step 4: Commit**

```bash
git add tests/__init__.py tests/conftest.py requirements-dev.txt
git commit -m "Add test scaffolding: pytest + fixtures for geoip migration"
```

---

## Task 2: 创建 `core/geoip.py` 共享模块（TDD）

**Files:**
- Create: `ddospot/core/geoip.py`
- Test: `tests/test_geoip.py`

**Interfaces:**
- Produces:
  - `ensure_dbs(country_path: str, asn_path: str) -> None`：mmdb 不存在时从 jsdelivr CDN 下载并 sha256 校验；存在则跳过；下载/校验失败抛 Exception
  - `class GeoIPResolver`:
    - `__init__(country_path: str, asn_path: str)`：打开两个 geoip2.database.Reader；任一打开失败时对应 reader=None
    - `resolve(ip_str: str) -> dict`：返回 `{'country_code': str|None, 'country_name': str|None, 'asn': int|None, 'asn_org': str|None}`；非法 IP / 查询失败返回全 None 字段，不抛异常
    - `GeoIPResolver.NONE = {'country_code': None, 'country_name': None, 'asn': None, 'asn_org': None}` 类常量

- [ ] **Step 1: 写失败测试 `tests/test_geoip.py`**

```python
import os
import pytest
from unittest.mock import patch, MagicMock

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'ddospot'))

from core.geoip import GeoIPResolver, ensure_dbs


class TestGeoIPResolver:
    def test_resolve_returns_all_none_for_invalid_ip(self):
        """非法 IP 应返回全 None 字段，不抛异常"""
        resolver = MagicMock(spec=GeoIPResolver)
        resolver.resolve = GeoIPResolver.resolve.__get__(resolver, GeoIPResolver)
        # 用真实 resolve 但 reader 为 None
        resolver.country_reader = None
        resolver.asn_reader = None
        result = resolver.resolve('not-an-ip')
        assert result == GeoIPResolver.NONE
        assert result['country_code'] is None
        assert result['country_name'] is None
        assert result['asn'] is None
        assert result['asn_org'] is None

    def test_resolve_returns_all_none_when_readers_none(self):
        """readers 为 None（mmdb 不可用）时返回全 None"""
        resolver = MagicMock(spec=GeoIPResolver)
        resolver.resolve = GeoIPResolver.resolve.__get__(resolver, GeoIPResolver)
        resolver.country_reader = None
        resolver.asn_reader = None
        result = resolver.resolve('8.8.8.8')
        assert result == GeoIPResolver.NONE

    def test_resolve_returns_none_for_private_ip(self):
        """私有 IP 不在 mmdb 中，应返回全 None"""
        # 此测试需要真实 mmdb 文件，标记为集成测试
        # 在没有 mmdb 的环境下跳过
        country_path = os.environ.get('DDOSPOT_GEOIP_DB', 'db/GeoIP-Country.mmdb')
        asn_path = os.environ.get('DDOSPOT_GEOIP_ASN_DB', 'db/GeoIP-ASN.mmdb')
        if not (os.path.exists(country_path) and os.path.exists(asn_path)):
            pytest.skip("mmdb files not available locally")
        resolver = GeoIPResolver(country_path, asn_path)
        result = resolver.resolve('192.168.1.1')
        assert result['country_code'] is None or result == GeoIPResolver.NONE

    def test_resolve_known_public_ip(self):
        """8.8.8.8 应解析为 US / Google ASN（需要 mmdb）"""
        country_path = os.environ.get('DDOSPOT_GEOIP_DB', 'db/GeoIP-Country.mmdb')
        asn_path = os.environ.get('DDOSPOT_GEOIP_ASN_DB', 'db/GeoIP-ASN.mmdb')
        if not (os.path.exists(country_path) and os.path.exists(asn_path)):
            pytest.skip("mmdb files not available locally")
        resolver = GeoIPResolver(country_path, asn_path)
        result = resolver.resolve('8.8.8.8')
        assert result['country_code'] == 'US'
        assert result['asn'] == 15169
        assert 'Google' in (result['asn_org'] or '')


class TestEnsureDbs:
    def test_ensure_dbs_skips_when_files_exist(self, tmp_path):
        """mmdb 已存在时不应下载"""
        country = tmp_path / 'Country.mmdb'
        asn = tmp_path / 'ASN.mmdb'
        country.write_bytes(b'fake')
        asn.write_bytes(b'fake')
        with patch('core.geoip.urllib.request.urlretrieve') as mock_dl, \
             patch('core.geoip.urllib.request.urlopen') as mock_open:
            ensure_dbs(str(country), str(asn))
            mock_dl.assert_not_called()

    def test_ensure_dbs_downloads_when_missing(self, tmp_path):
        """mmdb 缺失时应触发下载"""
        country = tmp_path / 'Country.mmdb'
        asn = tmp_path / 'ASN.mmdb'
        with patch('core.geoip.urllib.request.urlretrieve') as mock_dl, \
             patch('core.geoip.urllib.request.urlopen') as mock_open, \
             patch('core.geoip.hashlib.sha256') as mock_sha, \
             patch('core.geoip.shutil.move'):
            # 模拟 sha256 校验通过
            mock_open.return_value.read.return_value = b'abc123  Country-without-asn.mmdb'
            mock_sha.return_value.hexdigest.return_value = 'abc123'
            ensure_dbs(str(country), str(asn))
            # country 和 asn 各下载一次，各校验一次
            assert mock_dl.call_count == 2
```

- [ ] **Step 2: 运行测试确认失败**

Run: `pytest tests/test_geoip.py -v`
Expected: FAIL，`ModuleNotFoundError: No module named 'core.geoip'`

- [ ] **Step 3: 实现 `ddospot/core/geoip.py`**

```python
import hashlib
import logging
import os
import shutil
import urllib.request

import geoip2.database


LOGGER = logging.getLogger('geoip')

# CDN 基础路径与文件名
_CDN_BASE = 'https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release'
_COUNTRY_SRC = 'Country-without-asn.mmdb'
_ASN_SRC = 'GeoLite2-ASN.mmdb'


def ensure_dbs(country_path, asn_path):
    """确保两个 mmdb 文件存在；不存在则从 CDN 下载并 sha256 校验。

    已存在且非空：直接返回。
    下载或校验失败：抛 Exception。
    """
    for db_path, src_name in ((country_path, _COUNTRY_SRC), (asn_path, _ASN_SRC)):
        if os.path.exists(db_path) and os.path.getsize(db_path) > 0:
            continue
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        tmp = db_path + '.tmp'
        LOGGER.info('GeoIP mmdb not found at %s, downloading %s/%s' % (db_path, _CDN_BASE, src_name))
        urllib.request.urlretrieve('%s/%s' % (_CDN_BASE, src_name), tmp)
        expected = urllib.request.urlopen('%s/%s.sha256sum' % (_CDN_BASE, src_name)).read().decode().split()[0]
        actual = hashlib.sha256(open(tmp, 'rb').read()).hexdigest()
        if actual != expected:
            os.remove(tmp)
            raise Exception('GeoIP mmdb sha256 mismatch for %s: expected %s, got %s' % (src_name, expected, actual))
        shutil.move(tmp, db_path)
        LOGGER.info('GeoIP mmdb downloaded and verified (%d bytes): %s' % (os.path.getsize(db_path), db_path))


class GeoIPResolver:
    """持有 country + asn 两个 mmdb reader 的解析器。

    reader 初始化失败（mmdb 缺失或损坏）时对应 reader=None，
    resolve 仍可调用但返回全 None 字段。
    """

    NONE = {'country_code': None, 'country_name': None, 'asn': None, 'asn_org': None}

    def __init__(self, country_path, asn_path):
        self.country_reader = None
        self.asn_reader = None
        try:
            self.country_reader = geoip2.database.Reader(country_path)
        except Exception as e:
            LOGGER.error('Error initializing GeoIP country reader (%s): %s' % (country_path, e))
        try:
            self.asn_reader = geoip2.database.Reader(asn_path)
        except Exception as e:
            LOGGER.error('Error initializing GeoIP ASN reader (%s): %s' % (asn_path, e))

    def resolve(self, ip_str):
        """解析 IP 返回 {'country_code', 'country_name', 'asn', 'asn_org'} 字典。

        任一 reader 不可用、IP 非法、IP 不在库中：对应字段为 None。
        永不抛异常。
        """
        result = dict(self.NONE)
        if self.country_reader:
            try:
                resp = self.country_reader.country(ip_str)
                result['country_code'] = resp.country.iso_code
                result['country_name'] = resp.country.name
            except Exception:
                pass
        if self.asn_reader:
            try:
                resp = self.asn_reader.asn(ip_str)
                result['asn'] = resp.autonomous_system_number
                result['asn_org'] = resp.autonomous_system_organization
            except Exception:
                pass
        return result
```

- [ ] **Step 4: 运行测试确认通过**

Run: `pytest tests/test_geoip.py -v`
Expected: 4 个 test 通过（test_resolve_known_public_ip 和 test_resolve_returns_none_for_private_ip 若本地无 mmdb 则 SKIP）

如果有本地 mmdb（从 `db/` 目录拷贝或符号链接到测试路径），全部应 PASS。

- [ ] **Step 5: Commit**

```bash
git add ddospot/core/geoip.py tests/test_geoip.py
git commit -m "Add shared core/geoip.py module with ensure_dbs + GeoIPResolver"
```

---

## Task 3: 重构 `alerter.py` 使用 geoip 模块

**Files:**
- Modify: `ddospot/core/alerter.py`

**Interfaces:**
- Consumes: `core.geoip.ensure_dbs`, `core.geoip.GeoIPResolver`
- Produces: `Alerter` 不再有自己的 `_ensure_geoip_db`，行为不变（同样的 reader.country(ip) + reader.asn(ip) 调用路径）

- [ ] **Step 1: 阅读现有 alerter.py 的 GeoIP 部分**

Run: `cat ddospot/core/alerter.py | head -100`
重点看：
- L13 `import geoip2.database`
- L47-73 初始化两个 reader（调 `_ensure_geoip_db`）
- L86-100 `_ensure_geoip_db` 方法
- L110-129 `_do_alert` 中使用 reader

- [ ] **Step 2: 修改 alerter.py**

删除 `import geoip2.database`（改用 core.geoip）。
删除 `_ensure_geoip_db` 方法（L86-100）。
改写 L47-73 的初始化块为：

```python
        from core.geoip import ensure_dbs, GeoIPResolver

        try:
            db_path = os.environ.get('DDOSPOT_GEOIP_DB') or 'db/GeoIP-Country.mmdb'
            asn_path = os.environ.get('DDOSPOT_GEOIP_ASN_DB') or 'db/GeoIP-ASN.mmdb'
            ensure_dbs(db_path, asn_path)
            self.geoip_resolver = GeoIPResolver(db_path, asn_path)
            # 兼容旧代码：保留 country_reader/asn_reader 引用
            self.geoip_reader = self.geoip_resolver.country_reader
            self.geoip_asn_reader = self.geoip_resolver.asn_reader
        except Exception as msg:
            self.logger.error('Error initializing GeoIP: %s' % (msg))
            self.geoip_resolver = None
            self.geoip_reader = None
            self.geoip_asn_reader = None
```

`_do_alert` 中 `self.geoip_reader.country(ip)` 与 `self.geoip_asn_reader.asn(ip)` 调用保持不变（兼容旧引用）。

- [ ] **Step 3: 验证导入无误**

Run: `cd ddospot && python -c "import sys; sys.path.insert(0,'.'); from core.alerter import Alerter; print('OK')"`
Expected: 输出 `OK`，无 ImportError

- [ ] **Step 4: 运行所有现有测试**

Run: `pytest tests/ -v`
Expected: 所有已写测试通过

- [ ] **Step 5: Commit**

```bash
git add ddospot/core/alerter.py
git commit -m "Refactor alerter to use shared core/geoip module"
```

---

## Task 4: `dbbase.py` 加 geoip_resolver 参数

**Files:**
- Modify: `ddospot/core/dbbase.py`

**Interfaces:**
- Consumes: `core.geoip.GeoIPResolver`（可选）
- Produces: `DBBaseThread.__init__` 增加 `geoip_resolver=None` 参数；实例属性 `self.geoip_resolver`

- [ ] **Step 1: 修改 DBBaseThread.__init__ 签名**

`ddospot/core/dbbase.py` L20-46，在 `__init__` 参数列表末尾加 `geoip_resolver=None`，在方法体内加 `self.geoip_resolver = geoip_resolver`：

修改前（L21-30）：
```python
    def __init__(
                self,
                dbfile,
                decl_base,
                logger_name,
                log_queue,
                output_queue,
                stop_event,
                new_attack_interval
                ):
```

修改后：
```python
    def __init__(
                self,
                dbfile,
                decl_base,
                logger_name,
                log_queue,
                output_queue,
                stop_event,
                new_attack_interval,
                geoip_resolver=None
                ):
```

在 L38 `self.new_attack_interval = ...` 后加一行：
```python
        self.geoip_resolver = geoip_resolver
```

- [ ] **Step 2: 修改各 pot dblogger 的 DBThread.__init__ 传递 resolver**

5 个 `dblogger.py` 的 `DBThread.__init__` 调用 `dbbase.DBBaseThread.__init__` 时增加 `geoip_resolver` 参数。当前签名（以 ntp 为例 L44-62）：

```python
    def __init__(
                self,
                dbfile,
                logger_name,
                log_queue,
                output_queue,
                stop_event,
                new_attack_interval
                ):
        dbbase.DBBaseThread.__init__(
                                        self,
                                        dbfile,
                                        self.Base,
                                        logger_name,
                                        log_queue,
                                        output_queue,
                                        stop_event,
                                        new_attack_interval
                                    )
```

改为（5 个 pot 都同样改）：
```python
    def __init__(
                self,
                dbfile,
                logger_name,
                log_queue,
                output_queue,
                stop_event,
                new_attack_interval,
                geoip_resolver=None
                ):
        dbbase.DBBaseThread.__init__(
                                        self,
                                        dbfile,
                                        self.Base,
                                        logger_name,
                                        log_queue,
                                        output_queue,
                                        stop_event,
                                        new_attack_interval,
                                        geoip_resolver
                                    )
```

5 个文件位置：
- `ddospot/pots/ntp/dblogger.py:44-62`
- `ddospot/pots/dns/dblogger.py:60-78`
- `ddospot/pots/ssdp/dblogger.py:45-63`
- `ddospot/pots/chargen/dblogger.py:42-60`
- `ddospot/pots/generic/dblogger.py:44-62`

- [ ] **Step 3: 修改各 pot 的 *pot.py 的 _create_dbthread 传递 resolver**

5 个 `*pot.py` 的 `_create_dbthread` 方法当前形如（以 ntp 为例 `ddospot/pots/ntp/ntpot.py:32-40`）：

```python
    def _create_dbthread(self, dbfile, new_attack_interval):
        return DBThread(
                        dbfile,
                        self.name(),
                        self.log_queue,
                        self.output_queue,
                        self.stop_event,
                        new_attack_interval
                        )
```

改为：
```python
    def _create_dbthread(self, dbfile, new_attack_interval):
        return DBThread(
                        dbfile,
                        self.name(),
                        self.log_queue,
                        self.output_queue,
                        self.stop_event,
                        new_attack_interval,
                        getattr(self, 'geoip_resolver', None)
                        )
```

5 个文件：
- `ddospot/pots/ntp/ntpot.py:32-40`
- `ddospot/pots/dns/dnspot.py:42-?`（grep 确认行号）
- `ddospot/pots/ssdp/ssdpot.py:29-?`
- `ddospot/pots/chargen/chargenpot.py:30-?`
- `ddospot/pots/generic/genericpot.py:30-?`

用 `getattr(self, 'geoip_resolver', None)` 而非 `self.geoip_resolver`，避免在 PotLoader.setup 未创建 resolver 时 AttributeError。

- [ ] **Step 4: 修改 potloader.py 的 _setup_dbthread 创建 resolver**

`ddospot/core/potloader.py:252-260`：

```python
    def _setup_dbthread(self):
        attack_interval = self.conf.getint('attack', 'new_attack_detection_interval')
        self.log_queue = queue.Queue()
        self.output_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.stop_event.clear()
        dbfile = self.conf.get('logging', 'sqlitedb')
        self.dbthread = self._create_dbthread(dbfile, attack_interval)
        self.dbthread.start()
```

改为：
```python
    def _setup_dbthread(self):
        attack_interval = self.conf.getint('attack', 'new_attack_detection_interval')
        self.log_queue = queue.Queue()
        self.output_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.stop_event.clear()
        dbfile = self.conf.get('logging', 'sqlitedb')

        # 初始化 GeoIP resolver（可选增强；失败时 None，蜜罐照常运行）
        self.geoip_resolver = None
        try:
            import os
            from core.geoip import ensure_dbs, GeoIPResolver
            country_path = os.environ.get('DDOSPOT_GEOIP_DB') or 'db/GeoIP-Country.mmdb'
            asn_path = os.environ.get('DDOSPOT_GEOIP_ASN_DB') or 'db/GeoIP-ASN.mmdb'
            ensure_dbs(country_path, asn_path)
            self.geoip_resolver = GeoIPResolver(country_path, asn_path)
        except Exception as msg:
            if self.logger:
                self.logger.error('GeoIP resolver init failed (honeypot will run without geo data): %s' % msg)

        self.dbthread = self._create_dbthread(dbfile, attack_interval)
        self.dbthread.start()
```

- [ ] **Step 5: 验证导入与语法**

Run: `cd ddospot && python -c "import sys; sys.path.insert(0,'.'); import core.potloader; import core.dbbase; print('OK')"`
Expected: 输出 `OK`

Run: `pytest tests/ -v`
Expected: 已有测试仍全部通过

- [ ] **Step 6: Commit**

```bash
git add ddospot/core/dbbase.py ddospot/core/potloader.py \
        ddospot/pots/ntp/dblogger.py ddospot/pots/dns/dblogger.py \
        ddospot/pots/ssdp/dblogger.py ddospot/pots/chargen/dblogger.py \
        ddospot/pots/generic/dblogger.py \
        ddospot/pots/ntp/ntpot.py ddospot/pots/dns/dnspot.py \
        ddospot/pots/ssdp/ssdpot.py ddospot/pots/chargen/chargenpot.py \
        ddospot/pots/generic/genericpot.py
git commit -m "Wire geoip_resolver through DBBaseThread -> pot DBThreads"
```

---

## Task 5: NTP pot 加 GeoIP 列 + _add_attack 填充（原型）

**Files:**
- Modify: `ddospot/pots/ntp/dblogger.py`
- Test: `tests/test_ntp_dblogger_geoip.py`

**Interfaces:**
- Consumes: `core.geoip.GeoIPResolver.resolve(ip_str) -> dict`
- Produces: `ntpot_sources` 表含 4 个新列；`DBThread.Source` ORM 含 4 个新属性；`_add_attack` 创建 Source 时填充

- [ ] **Step 1: 写失败测试 `tests/test_ntp_dblogger_geoip.py`**

```python
import os
import sys
import datetime
import pytest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'ddospot'))

from core.geoip import GeoIPResolver
from pots.ntp.dblogger import DBThread as NTPDBThread


@pytest.fixture
def ntp_dbthread(tmp_db_path):
    """构造一个 NTP DBThread，注入 mock resolver"""
    resolver = MagicMock(spec=GeoIPResolver)
    resolver.resolve.return_value = {
        'country_code': 'US',
        'country_name': 'United States',
        'asn': 15169,
        'asn_org': 'Google LLC'
    }
    import queue
    import threading
    t = NTPDBThread(
        tmp_db_path,
        'test-ntp',
        queue.Queue(),
        queue.Queue(),
        threading.Event(),
        5,
        resolver
    )
    return t


class TestNTPSourceGeoIP:
    def test_source_table_has_geoip_columns(self, ntp_dbthread):
        """Source ORM 应有 4 个新属性"""
        from sqlalchemy import inspect
        mapper = inspect(NTPDBThread.Source)
        col_names = [c.key for c in mapper.columns]
        assert 'country_code' in col_names
        assert 'country_name' in col_names
        assert 'asn' in col_names
        assert 'asn_org' in col_names

    def test_add_attack_populates_geoip_for_new_source(self, ntp_dbthread):
        """新 Source 应被填充 GeoIP 字段"""
        db_params = {
            'ip': 134744072,  # 8.8.8.8
            'port': 12345,
            'time': datetime.datetime(2026, 9, 19, 12, 0, 0),
            'mode': 7,
            'request_pkt': b'',
            'response_pkt': b'',
            'input_size': 8,
            'output_size': 736,
        }
        ntp_dbthread._add_attack(db_params)

        # 验证 Source 被填充
        source = ntp_dbthread.session.query(NTPDBThread.Source).one()
        assert source.country_code == 'US'
        assert source.country_name == 'United States'
        assert source.asn == 15169
        assert source.asn_org == 'Google LLC'

    def test_add_attack_skips_geoip_for_existing_source(self, ntp_dbthread):
        """已存在的 Source 不应重新查询 GeoIP"""
        db_params = {
            'ip': 134744072,
            'port': 12345,
            'time': datetime.datetime(2026, 9, 19, 12, 0, 0),
            'mode': 7,
            'request_pkt': b'',
            'response_pkt': b'',
            'input_size': 8,
            'output_size': 736,
        }
        # 第一次：创建 Source
        ntp_dbthread._add_attack(db_params)
        # 第二次：Source 已存在，不应再调用 resolve
        ntp_dbthread.geoip_resolver.resolve.reset_mock()
        ntp_dbthread._add_attack(db_params)
        ntp_dbthread.geoip_resolver.resolve.assert_not_called()

    def test_add_attack_works_without_resolver(self, tmp_db_path):
        """resolver=None 时新 Source 的 geo 字段为 NULL，不崩"""
        import queue
        import threading
        t = NTPDBThread(
            tmp_db_path,
            'test-ntp',
            queue.Queue(),
            queue.Queue(),
            threading.Event(),
            5,
            None  # 无 resolver
        )
        db_params = {
            'ip': 134744072,
            'port': 12345,
            'time': datetime.datetime(2026, 9, 19, 12, 0, 0),
            'mode': 7,
            'request_pkt': b'',
            'response_pkt': b'',
            'input_size': 8,
            'output_size': 736,
        }
        t._add_attack(db_params)
        source = t.session.query(NTPDBThread.Source).one()
        assert source.country_code is None
        assert source.asn is None
```

- [ ] **Step 2: 运行测试确认失败**

Run: `pytest tests/test_ntp_dblogger_geoip.py -v`
Expected: FAIL，`AttributeError: country_code` 或类似（ORM 没这列）

- [ ] **Step 3: 修改 NTP dblogger.py 的 Source ORM**

`ddospot/pots/ntp/dblogger.py` L22-28 当前 Source 定义：

```python
    class Source(Base):
        __tablename__ = 'ntpot_sources'

        src_ip = Column(Integer, primary_key=True)
        src_port = Column(Integer)
        first_seen = Column(DateTime, default=datetime.datetime.now())
        last_seen = Column(DateTime, default=datetime.datetime.now())
```

改为：

```python
    class Source(Base):
        __tablename__ = 'ntpot_sources'

        src_ip = Column(Integer, primary_key=True)
        src_port = Column(Integer)
        first_seen = Column(DateTime, default=datetime.datetime.now())
        last_seen = Column(DateTime, default=datetime.datetime.now())
        country_code = Column(String(2))
        country_name = Column(String(64))
        asn = Column(Integer)
        asn_org = Column(String(255))
```

在 import 块（L7）增加 `String`：
```python
from sqlalchemy import Column, ForeignKey, Integer, SmallInteger, String, DateTime, LargeBinary
```

- [ ] **Step 4: 修改 NTP dblogger.py 的 _add_attack**

L64-91 当前 `_add_attack`：

```python
    def _add_attack(self, db_params):
        source = self.session.query(DBThread.Source).\
                filter(DBThread.Source.src_ip == db_params['ip']).one_or_none()
        if not source:
            source = DBThread.Source(
                                    src_ip=db_params['ip'],
                                    src_port=db_params['port'],
                                    first_seen=db_params['time'],
                                    last_seen=db_params['time']
                                    )
            self.session.add(source)
        else:
            # update last_seen timestamp for existing source
            source.last_seen = db_params['time']
        ...
```

改为：

```python
    def _add_attack(self, db_params):
        source = self.session.query(DBThread.Source).\
                filter(DBThread.Source.src_ip == db_params['ip']).one_or_none()
        if not source:
            # 查询 GeoIP（仅在新 Source 创建时查一次）
            geo = {'country_code': None, 'country_name': None, 'asn': None, 'asn_org': None}
            if self.geoip_resolver:
                try:
                    import core.utils as utils
                    ip_str = utils.int_to_addr(db_params['ip'])
                    geo = self.geoip_resolver.resolve(ip_str)
                except Exception as msg:
                    self.logger.error('GeoIP resolve failed for %s: %s' % (db_params['ip'], msg))
            source = DBThread.Source(
                                    src_ip=db_params['ip'],
                                    src_port=db_params['port'],
                                    first_seen=db_params['time'],
                                    last_seen=db_params['time'],
                                    country_code=geo['country_code'],
                                    country_name=geo['country_name'],
                                    asn=geo['asn'],
                                    asn_org=geo['asn_org']
                                    )
            self.session.add(source)
        else:
            # update last_seen timestamp for existing source
            source.last_seen = db_params['time']
        ...
```

- [ ] **Step 5: 运行测试确认通过**

Run: `pytest tests/test_ntp_dblogger_geoip.py -v`
Expected: 4 个测试全部 PASS

- [ ] **Step 6: Commit**

```bash
git add ddospot/pots/ntp/dblogger.py tests/test_ntp_dblogger_geoip.py
git commit -m "NTP pot: add GeoIP columns to sources, populate in _add_attack"
```

---

## Task 6: 其余 4 个 pot 加 GeoIP 列 + _add_attack 填充

**Files:**
- Modify: `ddospot/pots/dns/dblogger.py`
- Modify: `ddospot/pots/ssdp/dblogger.py`
- Modify: `ddospot/pots/chargen/dblogger.py`
- Modify: `ddospot/pots/generic/dblogger.py`
- Test: `tests/test_all_pots_geoip.py`

**Interfaces:**
- Consumes: 同 Task 5
- Produces: 4 个 pot 的 Source ORM 含 4 新列；DNS 的 _add_attack 因 db_params['ip'] 是字符串，无需 int_to_addr 转换

- [ ] **Step 1: 写测试 `tests/test_all_pots_geoip.py`**

```python
import os
import sys
import datetime
import pytest
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'ddospot'))

from core.geoip import GeoIPResolver


@pytest.fixture
def fake_resolver():
    r = MagicMock(spec=GeoIPResolver)
    r.resolve.return_value = {
        'country_code': 'US',
        'country_name': 'United States',
        'asn': 15169,
        'asn_org': 'Google LLC'
    }
    return r


@pytest.mark.parametrize('pot_module,table_prefix,db_params_ip_is_str', [
    ('pots.dns.dblogger', 'dnspot', True),
    ('pots.ssdp.dblogger', 'ssdpot', False),
    ('pots.chargen.dblogger', 'chargenpot', False),
    ('pots.generic.dblogger', 'genericpot', False),
])
def test_source_has_geoip_columns(pot_module, table_prefix, db_params_ip_is_str):
    """每个 pot 的 Source ORM 应有 4 个新列"""
    import importlib
    mod = importlib.import_module(pot_module)
    DBThread = mod.DBThread
    from sqlalchemy import inspect
    mapper = inspect(DBThread.Source)
    col_names = [c.key for c in mapper.columns]
    assert 'country_code' in col_names
    assert 'country_name' in col_names
    assert 'asn' in col_names
    assert 'asn_org' in col_names
    assert DBThread.Source.__tablename__ == '%s_sources' % table_prefix


@pytest.mark.parametrize('pot_module,extra_db_params', [
    ('pots.dns.dblogger', {'domain_name': 'test.com', 'dns_type': 'A', 'dns_class': 'IN', 'opcode': 0}),
    ('pots.ssdp.dblogger', {'st': 'upnp:rootdevice', 'mx': 1, 'request_pkt': b'', 'response_pkt': b''}),
    ('pots.chargen.dblogger', {'request_pkt': b''}),
    ('pots.generic.dblogger', {'dport': 161, 'request_pkt': b''}),
])
def test_add_attack_populates_geoip(pot_module, extra_db_params, fake_resolver, tmp_db_path):
    """每个 pot 的 _add_attack 创建新 Source 时应填充 GeoIP"""
    import importlib
    import queue
    import threading
    mod = importlib.import_module(pot_module)
    DBThread = mod.DBThread

    t = DBThread(
        tmp_db_path,
        'test-%s' % pot_module,
        queue.Queue(),
        queue.Queue(),
        threading.Event(),
        5,
        fake_resolver
    )

    # 8.8.8.8 = 134744072
    ip_value = '8.8.8.8' if 'dns' in pot_module else 134744072
    db_params = {
        'ip': ip_value,
        'port': 12345,
        'time': datetime.datetime(2026, 9, 19, 12, 0, 0),
        'input_size': 8,
        'output_size': 736,
    }
    db_params.update(extra_db_params)

    t._add_attack(db_params)

    source = t.session.query(DBThread.Source).one()
    assert source.country_code == 'US'
    assert source.asn == 15169
```

- [ ] **Step 2: 运行测试确认失败**

Run: `pytest tests/test_all_pots_geoip.py -v`
Expected: FAIL，4 个 pot 都缺 country_code 列

- [ ] **Step 3: 修改 DNS dblogger.py**

`ddospot/pots/dns/dblogger.py`：

import 块（L7）已有 `String`，无需加。

Source 定义（L42-48）加 4 列：
```python
    class Source(Base):
        __tablename__ = 'dnspot_sources'

        src_ip = Column(Integer, primary_key=True)
        src_port = Column(Integer)
        first_seen = Column(DateTime, default=datetime.datetime.now())
        last_seen = Column(DateTime, default=datetime.datetime.now())
        country_code = Column(String(2))
        country_name = Column(String(64))
        asn = Column(Integer)
        asn_org = Column(String(255))
```

`_add_attack` L80-103，创建 Source 的块（L93-100）改为：

```python
        if not source:
            # db_params['ip'] 是字符串（DNS pot 特有），直接用于 GeoIP 查询
            geo = {'country_code': None, 'country_name': None, 'asn': None, 'asn_org': None}
            if self.geoip_resolver:
                try:
                    geo = self.geoip_resolver.resolve(db_params['ip'])
                except Exception as msg:
                    self.logger.error('GeoIP resolve failed for %s: %s' % (db_params['ip'], msg))
            source = DBThread.Source(
                                    src_ip=addr_int,
                                    src_port=db_params['port'],
                                    first_seen=db_params['time'],
                                    last_seen=db_params['time'],
                                    country_code=geo['country_code'],
                                    country_name=geo['country_name'],
                                    asn=geo['asn'],
                                    asn_org=geo['asn_org']
                                    )
            self.session.add(source)
            self.session.commit()
```

注意：DNS 的 `addr_int = utils.addr_to_int(db_params['ip'])` 已在 L83 计算，Source 仍用 `addr_int`；GeoIP 查询用 `db_params['ip']`（字符串）。

- [ ] **Step 4: 修改 SSDP dblogger.py**

`ddospot/pots/ssdp/dblogger.py`：

import 块（L7）加 `String`：
```python
from sqlalchemy import Column, ForeignKey, Integer, SmallInteger, String, DateTime, LargeBinary
```

Source（L22-28）加 4 列：
```python
    class Source(Base):
        __tablename__ = 'ssdpot_sources'

        src_ip = Column(Integer, primary_key=True)
        src_port = Column(Integer)
        first_seen = Column(DateTime, default=datetime.datetime.now())
        last_seen = Column(DateTime, default=datetime.datetime.now())
        country_code = Column(String(2))
        country_name = Column(String(64))
        asn = Column(Integer)
        asn_org = Column(String(255))
```

`_add_attack` L65-93，创建 Source 块（L66-74）改为：
```python
        if not source:
            geo = {'country_code': None, 'country_name': None, 'asn': None, 'asn_org': None}
            if self.geoip_resolver:
                try:
                    import core.utils as utils
                    ip_str = utils.int_to_addr(db_params['ip'])
                    geo = self.geoip_resolver.resolve(ip_str)
                except Exception as msg:
                    self.logger.error('GeoIP resolve failed for %s: %s' % (db_params['ip'], msg))
            source = DBThread.Source(
                                    src_ip=db_params['ip'],
                                    src_port=db_params['port'],
                                    first_seen=db_params['time'],
                                    last_seen=db_params['time'],
                                    country_code=geo['country_code'],
                                    country_name=geo['country_name'],
                                    asn=geo['asn'],
                                    asn_org=geo['asn_org']
                                    )
            self.session.add(source)
```

- [ ] **Step 5: 修改 CHARGEN dblogger.py**

`ddospot/pots/chargen/dblogger.py`：

import 块（L7）加 `String`：
```python
from sqlalchemy import Column, ForeignKey, Integer, BigInteger, String, DateTime, LargeBinary
```

Source（L22-28）加 4 列（同 SSDP 的列定义，表名改为 `chargenpot_sources`）。

`_add_attack` L62-87 创建 Source 块（L63-71）改为（同 SSDP 模式）：
```python
        if not source:
            geo = {'country_code': None, 'country_name': None, 'asn': None, 'asn_org': None}
            if self.geoip_resolver:
                try:
                    import core.utils as utils
                    ip_str = utils.int_to_addr(db_params['ip'])
                    geo = self.geoip_resolver.resolve(ip_str)
                except Exception as msg:
                    self.logger.error('GeoIP resolve failed for %s: %s' % (db_params['ip'], msg))
            source = DBThread.Source(
                                    src_ip=db_params['ip'],
                                    src_port=db_params['port'],
                                    first_seen=db_params['time'],
                                    last_seen=db_params['time'],
                                    country_code=geo['country_code'],
                                    country_name=geo['country_name'],
                                    asn=geo['asn'],
                                    asn_org=geo['asn_org']
                                    )
            self.session.add(source)
```

- [ ] **Step 6: 修改 GENERIC dblogger.py**

`ddospot/pots/generic/dblogger.py`：

import 块（L7）加 `String`：
```python
from sqlalchemy import Column, ForeignKey, Integer, BigInteger, String, DateTime, LargeBinary
```

Source（L22-28）加 4 列（表名 `genericpot_sources`）。

`_add_attack` L64-90 创建 Source 块改为（同 SSDP/CHARGEN 模式）：
```python
        if not source:
            geo = {'country_code': None, 'country_name': None, 'asn': None, 'asn_org': None}
            if self.geoip_resolver:
                try:
                    import core.utils as utils
                    ip_str = utils.int_to_addr(db_params['ip'])
                    geo = self.geoip_resolver.resolve(ip_str)
                except Exception as msg:
                    self.logger.error('GeoIP resolve failed for %s: %s' % (db_params['ip'], msg))
            source = DBThread.Source(
                                    src_ip=db_params['ip'],
                                    src_port=db_params['port'],
                                    first_seen=db_params['time'],
                                    last_seen=db_params['time'],
                                    country_code=geo['country_code'],
                                    country_name=geo['country_name'],
                                    asn=geo['asn'],
                                    asn_org=geo['asn_org']
                                    )
            self.session.add(source)
```

- [ ] **Step 7: 运行测试确认通过**

Run: `pytest tests/test_all_pots_geoip.py tests/test_ntp_dblogger_geoip.py -v`
Expected: 全部 PASS

- [ ] **Step 8: 运行全部测试**

Run: `pytest tests/ -v`
Expected: 所有测试通过

- [ ] **Step 9: Commit**

```bash
git add ddospot/pots/dns/dblogger.py ddospot/pots/ssdp/dblogger.py \
        ddospot/pots/chargen/dblogger.py ddospot/pots/generic/dblogger.py \
        tests/test_all_pots_geoip.py
git commit -m "DNS/SSDP/CHARGEN/GENERIC pots: add GeoIP columns to sources"
```

---

## Task 7: 创建 `migrate_geoip.py` 迁移脚本（TDD）

**Files:**
- Create: `ddospot/migrate_geoip.py`
- Test: `tests/test_migrate_geoip.py`

**Interfaces:**
- Consumes: `core.geoip.ensure_dbs`, `core.geoip.GeoIPResolver`, `core.utils.int_to_addr`
- Produces: CLI 脚本 `python migrate_geoip.py [--db-dir db/]`；幂等；对 db/*.sqlite3 中所有 *_sources 表 ALTER + UPDATE

- [ ] **Step 1: 写失败测试 `tests/test_migrate_geoip.py`**

```python
import os
import sys
import sqlite3
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'ddospot'))

from migrate_geoip import migrate_db, main


def _create_old_schema_db(db_path, table_name, src_ips):
    """构造老 schema 库（无 country_code 列）"""
    conn = sqlite3.connect(db_path)
    conn.executescript('''
        CREATE TABLE %s (
            src_ip INTEGER PRIMARY KEY,
            src_port INTEGER,
            first_seen DATETIME,
            last_seen DATETIME
        );
    ''' % table_name)
    for ip, port in src_ips:
        conn.execute(
            'INSERT INTO %s (src_ip, src_port, first_seen, last_seen) VALUES (?, ?, ?, ?)' % table_name,
            (ip, port, '2026-09-01 10:00:00', '2026-09-01 10:00:00')
        )
    conn.commit()
    conn.close()


class TestMigrateDb:
    def test_adds_columns_when_missing(self, tmp_path):
        """列不存在时应 ALTER TABLE 加列"""
        db_path = str(tmp_path / 'ntpot.sqlite3')
        _create_old_schema_db(db_path, 'ntpot_sources', [(134744072, 12345)])

        fake_resolver = MagicMock()
        fake_resolver.resolve.return_value = {
            'country_code': 'US', 'country_name': 'United States',
            'asn': 15169, 'asn_org': 'Google LLC'
        }

        migrate_db(db_path, fake_resolver)

        conn = sqlite3.connect(db_path)
        cols = [r[1] for r in conn.execute('PRAGMA table_info(ntpot_sources)').fetchall()]
        assert 'country_code' in cols
        assert 'country_name' in cols
        assert 'asn' in cols
        assert 'asn_org' in cols

        row = conn.execute('SELECT country_code, asn FROM ntpot_sources WHERE src_ip=134744072').fetchone()
        assert row == ('US', 15169)
        conn.close()

    def test_backfills_null_rows(self, tmp_path):
        """已有 country_code=NULL 的行应被回填"""
        db_path = str(tmp_path / 'ntpot.sqlite3')
        # 直接构造含新列但值为 NULL 的库
        conn = sqlite3.connect(db_path)
        conn.executescript('''
            CREATE TABLE ntpot_sources (
                src_ip INTEGER PRIMARY KEY,
                src_port INTEGER,
                first_seen DATETIME,
                last_seen DATETIME,
                country_code TEXT,
                country_name TEXT,
                asn INTEGER,
                asn_org TEXT
            );
            INSERT INTO ntpot_sources VALUES (134744072, 12345, '2026-09-01', '2026-09-01', NULL, NULL, NULL, NULL);
        ''')
        conn.commit()
        conn.close()

        fake_resolver = MagicMock()
        fake_resolver.resolve.return_value = {
            'country_code': 'US', 'country_name': 'United States',
            'asn': 15169, 'asn_org': 'Google LLC'
        }

        migrate_db(db_path, fake_resolver)

        conn = sqlite3.connect(db_path)
        row = conn.execute('SELECT country_code, asn FROM ntpot_sources WHERE src_ip=134744072').fetchone()
        assert row == ('US', 15169)
        conn.close()

    def test_idempotent_second_run_noop(self, tmp_path):
        """二次运行不应再调用 resolve"""
        db_path = str(tmp_path / 'ntpot.sqlite3')
        _create_old_schema_db(db_path, 'ntpot_sources', [(134744072, 12345)])

        fake_resolver = MagicMock()
        fake_resolver.resolve.return_value = {
            'country_code': 'US', 'country_name': 'United States',
            'asn': 15169, 'asn_org': 'Google LLC'
        }

        migrate_db(db_path, fake_resolver)
        # 二次运行
        fake_resolver.resolve.reset_mock()
        migrate_db(db_path, fake_resolver)
        fake_resolver.resolve.assert_not_called()

    def test_skips_db_without_sources_tables(self, tmp_path):
        """无 *_sources 表的库应被跳过"""
        db_path = str(tmp_path / 'empty.sqlite3')
        conn = sqlite3.connect(db_path)
        conn.executescript('CREATE TABLE foo (id INTEGER);')
        conn.commit()
        conn.close()

        fake_resolver = MagicMock()
        # 不应抛异常
        migrate_db(db_path, fake_resolver)
        fake_resolver.resolve.assert_not_called()

    def test_handles_multiple_sources_tables_in_one_db(self, tmp_path):
        """一个库可能有多张 sources 表（实际不会，但脚本应通用）"""
        db_path = str(tmp_path / 'multi.sqlite3')
        conn = sqlite3.connect(db_path)
        conn.executescript('''
            CREATE TABLE ntpot_sources (src_ip INTEGER PRIMARY KEY, src_port INTEGER, first_seen DATETIME, last_seen DATETIME);
            CREATE TABLE dnspot_sources (src_ip INTEGER PRIMARY KEY, src_port INTEGER, first_seen DATETIME, last_seen DATETIME);
            INSERT INTO ntpot_sources VALUES (134744072, 12345, '2026-09-01', '2026-09-01');
            INSERT INTO dnspot_sources VALUES (134744072, 12345, '2026-09-01', '2026-09-01');
        ''')
        conn.commit()
        conn.close()

        fake_resolver = MagicMock()
        fake_resolver.resolve.return_value = {
            'country_code': 'US', 'country_name': 'United States',
            'asn': 15169, 'asn_org': 'Google LLC'
        }

        migrate_db(db_path, fake_resolver)
        assert fake_resolver.resolve.call_count == 2

    def test_resolver_none_still_alters_schema(self, tmp_path):
        """resolver=None 时仍应 ALTER TABLE（但跳过回填）"""
        db_path = str(tmp_path / 'ntpot.sqlite3')
        _create_old_schema_db(db_path, 'ntpot_sources', [(134744072, 12345)])

        migrate_db(db_path, None)

        conn = sqlite3.connect(db_path)
        cols = [r[1] for r in conn.execute('PRAGMA table_info(ntpot_sources)').fetchall()]
        assert 'country_code' in cols
        # 数据未回填
        row = conn.execute('SELECT country_code FROM ntpot_sources WHERE src_ip=134744072').fetchone()
        assert row == (None,)
        conn.close()


class TestMain:
    def test_main_processes_all_sqlite_in_dir(self, tmp_path):
        """main 应遍历 db_dir 下所有 .sqlite3 文件"""
        _create_old_schema_db(str(tmp_path / 'ntpot.sqlite3'), 'ntpot_sources', [(134744072, 12345)])
        _create_old_schema_db(str(tmp_path / 'dnspot.sqlite3'), 'dnspot_sources', [(134744072, 12345)])

        with patch('migrate_geoip.ensure_dbs'), \
             patch('migrate_geoip.GeoIPResolver') as MockResolver:
            MockResolver.return_value.resolve.return_value = {
                'country_code': 'US', 'country_name': 'United States',
                'asn': 15169, 'asn_org': 'Google LLC'
            }
            main(['--db-dir', str(tmp_path)])

        # 两个库都应被处理
        conn = sqlite3.connect(str(tmp_path / 'ntpot.sqlite3'))
        row = conn.execute('SELECT country_code FROM ntpot_sources WHERE src_ip=134744072').fetchone()
        assert row == ('US',)
        conn.close()
```

- [ ] **Step 2: 运行测试确认失败**

Run: `pytest tests/test_migrate_geoip.py -v`
Expected: FAIL，`ModuleNotFoundError: No module named 'migrate_geoip'`

- [ ] **Step 3: 实现 `ddospot/migrate_geoip.py`**

```python
#!/usr/bin/env python3
"""一次性迁移脚本：给 *_sources 表加 GeoIP 列并回填历史数据。

由 docker-compose 启动时在 ddospot.py 之前运行。幂等。
"""
import argparse
import glob
import logging
import os
import sqlite3
import sys

# 让脚本既能从容器内 /ddospot 目录运行，也能从仓库根运行
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.geoip import ensure_dbs, GeoIPResolver
from core.utils import int_to_addr


LOGGER = logging.getLogger('migrate_geoip')

NEW_COLUMNS = [
    ('country_code', 'TEXT'),
    ('country_name', 'TEXT'),
    ('asn', 'INTEGER'),
    ('asn_org', 'TEXT'),
]


def _get_sources_tables(conn):
    """返回库中所有以 _sources 结尾的表名"""
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%_sources'"
    ).fetchall()
    return [r[0] for r in rows]


def _existing_columns(conn, table):
    return {r[1] for r in conn.execute('PRAGMA table_info(%s)' % table).fetchall()}


def _alter_add_columns(conn, table):
    """对表加缺失的 GeoIP 列；返回是否加了任何列"""
    existing = _existing_columns(conn, table)
    added = False
    for col_name, col_type in NEW_COLUMNS:
        if col_name not in existing:
            conn.execute('ALTER TABLE %s ADD COLUMN %s %s' % (table, col_name, col_type))
            added = True
            LOGGER.info('  Added column %s %s to %s' % (col_name, col_type, table))
    if added:
        conn.commit()
    return added


def _backfill_null_rows(conn, table, resolver):
    """回填 country_code IS NULL 的行；返回回填行数"""
    rows = conn.execute(
        'SELECT src_ip FROM %s WHERE country_code IS NULL' % table
    ).fetchall()
    if not rows:
        return 0

    backfilled = 0
    for (src_ip,) in rows:
        ip_str = int_to_addr(src_ip)
        if ip_str == '-':
            # 无效 IP（src_ip=0 等），跳过
            continue
        geo = resolver.resolve(ip_str)
        conn.execute(
            'UPDATE %s SET country_code=?, country_name=?, asn=?, asn_org=? WHERE src_ip=?' % table,
            (geo['country_code'], geo['country_name'], geo['asn'], geo['asn_org'], src_ip)
        )
        backfilled += 1

    conn.commit()
    return backfilled


def migrate_db(db_path, resolver):
    """迁移单个 sqlite 库：加列 + 回填。

    resolver 为 None 时只加列不回填。
    """
    LOGGER.info('Processing %s' % db_path)
    conn = sqlite3.connect(db_path)
    try:
        tables = _get_sources_tables(conn)
        if not tables:
            LOGGER.info('  No *_sources tables, skipping')
            return

        for table in tables:
            _alter_add_columns(conn, table)
            if resolver is None:
                LOGGER.info('  No resolver, skipping backfill for %s' % table)
                continue
            n = _backfill_null_rows(conn, table, resolver)
            LOGGER.info('  Backfilled %d rows in %s' % (n, table))
    finally:
        conn.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description='Migrate *_sources tables: add GeoIP columns + backfill')
    parser.add_argument('--db-dir', default='db', help='Directory containing *.sqlite3 files (default: db)')
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

    country_path = os.environ.get('DDOSPOT_GEOIP_DB') or os.path.join(args.db_dir, 'GeoIP-Country.mmdb')
    asn_path = os.environ.get('DDOSPOT_GEOIP_ASN_DB') or os.path.join(args.db_dir, 'GeoIP-ASN.mmdb')

    resolver = None
    try:
        ensure_dbs(country_path, asn_path)
        resolver = GeoIPResolver(country_path, asn_path)
    except Exception as msg:
        LOGGER.warning('GeoIP unavailable, will only ALTER TABLE without backfill: %s' % msg)

    db_files = sorted(glob.glob(os.path.join(args.db_dir, '*.sqlite3')))
    if not db_files:
        LOGGER.info('No .sqlite3 files in %s' % args.db_dir)
        return

    for db_path in db_files:
        try:
            migrate_db(db_path, resolver)
        except Exception as msg:
            LOGGER.error('Error migrating %s: %s' % (db_path, msg))

    LOGGER.info('Migration complete')


if __name__ == '__main__':
    main()
```

- [ ] **Step 4: 运行测试确认通过**

Run: `pytest tests/test_migrate_geoip.py -v`
Expected: 7 个测试全部 PASS

- [ ] **Step 5: 运行全部测试**

Run: `pytest tests/ -v`
Expected: 所有测试通过

- [ ] **Step 6: Commit**

```bash
git add ddospot/migrate_geoip.py tests/test_migrate_geoip.py
git commit -m "Add migrate_geoip.py: idempotent schema migration + GeoIP backfill"
```

---

## Task 8: 更新 docker-compose.yml 启动命令

**Files:**
- Modify: `docker-compose.yml`
- Modify: `ddospot/Dockerfile`

**Interfaces:**
- Consumes: `ddospot/migrate_geoip.py`
- Produces: 容器启动时先跑迁移脚本再启动蜜罐

- [ ] **Step 1: 修改 docker-compose.yml**

在 `ddospot` service 下加 `command` 覆盖 Dockerfile CMD：

```yaml
services:
  ddospot:
    build:
      context: ./ddospot
    image: aelth/simpledns
    user: "0:0"
    cap_add:
      - CAP_NET_BIND_SERVICE
    command: sh -c "python3 migrate_geoip.py && python3 ddospot.py -n"
    environment:
      ...
```

在 `environment:` 块上方插入 `command:` 行（与 `cap_add:` 同级缩进）。

- [ ] **Step 2: 验证 Dockerfile 无需改**

`ddospot/Dockerfile` L19 `COPY . /ddospot` 已包含 `migrate_geoip.py`（在 `ddospot/` 目录下）。`WORKDIR /ddospot`（L33）使脚本路径正确。无需改 Dockerfile。

确认：`ls ddospot/migrate_geoip.py` 应存在（Task 7 已创建）。

- [ ] **Step 3: 本地构建测试镜像**

Run: `docker compose build`
Expected: 镜像构建成功，无报错

Run: `docker compose config` 验证 compose 语法
Expected: 输出含 `command: sh -c "python3 migrate_geoip.py && python3 ddospot.py -n"`

- [ ] **Step 4: Commit**

```bash
git add docker-compose.yml
git commit -m "compose: run migrate_geoip before ddospot on container start"
```

---

## Task 9: 本地集成验证

**Files:** 无代码变更，仅验证

- [ ] **Step 1: 拉取 ams01 真实 ntpot.sqlite3 作为测试数据**

```bash
ssh ams01.wentao.space 'docker cp ddospot-ddospot-1:/ddospot/db/ntpot.sqlite3 /tmp/ntpot_real.sqlite3'
scp ams01.wentao.space:/tmp/ntpot_real.sqlite3 /tmp/ntpot_real.sqlite3
```

- [ ] **Step 2: 拷贝到本地 db/ 目录并跑迁移**

```bash
mkdir -p ddospot/db
cp /tmp/ntpot_real.sqlite3 ddospot/db/ntpot.sqlite3
cd ddospot && python3 migrate_geoip.py --db-dir db
```

Expected: 输出 `Added column country_code TEXT to ntpot_sources` 等 4 行 + `Backfilled N rows in ntpot_sources`

- [ ] **Step 3: 验证回填结果**

```bash
sqlite3 ddospot/db/ntpot.sqlite3 "SELECT country_code, country_name, asn, asn_org, COUNT(*) FROM ntpot_sources GROUP BY country_code ORDER BY COUNT(*) DESC LIMIT 10;"
```

Expected: 看到具体国家如 US/CN/DE 等，asn 数字，asn_org 名称

- [ ] **Step 4: 验证幂等性**

```bash
cd ddospot && python3 migrate_geoip.py --db-dir db
```

Expected: 输出 `Backfilled 0 rows`，无 ALTER

- [ ] **Step 5: 清理测试数据**

```bash
rm ddospot/db/ntpot.sqlite3
```

注意：`db/` 目录在 `.gitignore` 中（`*.sqlite3`），不会被提交。

- [ ] **Step 6: Commit 验证记录（可选）**

如果发现 bug，修复后回到对应 Task 重新 commit。无 bug 则不提交。

---

## Task 10: 部署到生产

**Files:** 无代码变更，仅部署操作

- [ ] **Step 1: 推送所有变更到 GitHub**

```bash
git push origin master
```

确认：`git log --oneline -10` 显示所有 Task 的 commit。

- [ ] **Step 2: 部署到 hkg01（数据量最小）**

SSH 到 hkg01：
```bash
ssh hkg01.wentao.space
cd ~/ddospot
git pull origin master
docker compose down
docker compose build
docker compose up -d
docker compose logs -f ddospot 2>&1 | head -50
```

Expected: 日志含 `Migration complete` + `Backfilled N rows`，之后蜜罐正常启动

- [ ] **Step 3: 验证 hkg01 数据库**

```bash
docker exec ddospot-ddospot-1 sqlite3 /ddospot/db/ntpot.sqlite3 \
  "SELECT country_code, country_name, asn, asn_org, COUNT(*) FROM ntpot_sources GROUP BY country_code ORDER BY COUNT(*) DESC LIMIT 10;"
```

Expected: 看到具体国家数据

- [ ] **Step 4: 验证 hkg01 新包进来后新 IP 带 GeoIP**

等 5-10 分钟后查最新记录：
```bash
docker exec ddospot-ddospot-1 sqlite3 /ddospot/db/ntpot.sqlite3 \
  "SELECT src_ip, country_code, asn, first_seen FROM ntpot_sources ORDER BY first_seen DESC LIMIT 5;"
```

Expected: 最新 IP 的 country_code 不为 NULL（除非私有/未知 IP）

- [ ] **Step 5: 部署到 jkt01**

同 Step 2-4，SSH 到 jkt01。注意 jkt01 的 dnspot.sqlite3 是 842MB，回填可能需要 1-3 分钟。

- [ ] **Step 6: 部署到 ams01**

同 Step 2-4，SSH 到 ams01。ams01 的 dnspot.sqlite3 是 667MB。

- [ ] **Step 7: 三节点全部验证完成**

记录各节点回填行数与耗时，归档到 README 或部署日志。

---

## Self-Review 检查

**1. Spec coverage:**
- ✅ Schema 变更（4 列 × 5 pot）→ Task 5 (NTP) + Task 6 (4 个 pot)
- ✅ core/geoip.py 共享模块 → Task 2
- ✅ Alerter 重构 → Task 3
- ✅ DBBaseThread resolver 参数 → Task 4
- ✅ PotLoader 创建 resolver → Task 4 Step 4
- ✅ 5 个 pot 的 _create_dbthread 传递 → Task 4 Step 3
- ✅ migrate_geoip.py → Task 7
- ✅ docker-compose 启动前置 → Task 8
- ✅ 历史数据回填 → Task 7 + Task 9 + Task 10
- ✅ DNS 特殊处理（db_params['ip'] 是字符串）→ Task 6 Step 3
- ✅ 错误处理（resolver=None 降级）→ Task 5 test + Task 7 test
- ✅ 验证方案（单元 + 集成 + 生产）→ Task 9 + Task 10

**2. Placeholder scan:**
- 无 TBD/TODO
- 所有"appropriate error handling"都展开为具体 try/except
- 所有"similar to Task N"都重复了代码
- 所有 code step 都有完整代码块

**3. Type consistency:**
- `GeoIPResolver.NONE` 在 Task 2 定义，Task 5 测试中使用 ✓
- `resolve()` 返回 dict 的 4 个 key 在所有 Task 中一致 ✓
- `migrate_db(db_path, resolver)` 签名在 Task 7 定义和测试中使用一致 ✓
- `NEW_COLUMNS` 列定义在 Task 7 与 Task 5/6 ORM 列类型对齐（String(2)/String(64)/Integer/String(255) 在 SQLite 中都是 TEXT/INTEGER，ORM 层有具体长度但 SQLite 不强制）✓
