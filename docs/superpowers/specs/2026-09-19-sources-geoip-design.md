# DDoSPot Sources 表 GeoIP 字段设计

**日期**: 2026-09-19
**状态**: 已批准（方案 A / 回填 B / 迁移脚本独立 / DBThread 查询）

## 目标

在每个 pot 的 `*_sources` 表中记录 IP 的国家和 ASN 信息，使攻击数据可直接按地理/网络归属分析，无需查询时再做 GeoIP 解析。

## 决策记录

| 决策点 | 选择 | 理由 |
|---|---|---|
| 存储位置 | `*_sources` 表（方案 A）| country/ASN 是 IP 的属性，非攻击的属性；符合范式，避免冗余 |
| 历史数据 | 回填（方案 B）| 历史数据也要完整 |
| 查询层 | DBThread 内（方案 A）| GeoIP mmdb 查询 µs 级；DBThread 异步消费不影响吞吐；逻辑内聚 |
| 迁移方式 | 独立脚本 + compose 启动前置（方案 B 变体）| 一次性逻辑不留在业务代码里，compose 重启即自动执行，幂等 |

## Schema 变更

5 个 pot 的 `*_sources` 表（`ntpot_sources`、`dnspot_sources`、`ssdpot_sources`、`chargenpot_sources`、`genericpot_sources`）统一增加 4 列：

```sql
country_code VARCHAR(2)    -- ISO 3166-1 alpha-2，如 'CN'
country_name VARCHAR(64)   -- 如 'China'
asn          INTEGER       -- 如 4808
asn_org      VARCHAR(255)  -- 如 'China Unicom'
```

- 全部 nullable：GeoIP 查不到（私有 IP、库未覆盖）时留 NULL
- 现有表通过迁移脚本 `ALTER TABLE ADD COLUMN` 加列（新库由 `create_all` 自动含新列）
- IP 属性只查一次：Source 行首次创建时填充，之后不重查

## 组件设计

### 新增 `ddospot/core/geoip.py`（共享模块）

从 `alerter.py` 抽取 GeoIP 基础设施，消除重复：

```python
def ensure_dbs(country_path, asn_path) -> None
    # 下载+sha256 校验两个 mmdb（逻辑从 Alerter._ensure_geoip_db 迁移）
    # 路径默认取环境变量 DDOSPOT_GEOIP_DB / DDOSPOT_GEOIP_ASN_DB

class GeoIPResolver:
    # 持有 country + asn 两个 geoip2 reader
    def resolve(ip_str) -> dict
        # 返回 {'country_code':..., 'country_name':..., 'asn':..., 'asn_org':...}
        # 任一 reader 失败/未命中：对应字段为 None，不抛异常
        # resolve 本身失败（如非法 IP）：返回全 None 字段 dict
```

### 修改 `ddospot/core/alerter.py`

`Alerter` 改用 `core/geoip.py` 的 `ensure_dbs` 与 reader 初始化，删除自带的 `_ensure_geoip_db`，行为不变（告警消息格式、触发国家逻辑均不动）。

### 修改 `ddospot/core/dbbase.py`

`DBBaseThread.__init__` 增加可选参数 `geoip_resolver=None`，存为 `self.geoip_resolver`。子类用它填充新 Source。

### 修改 5 个 `ddospot/pots/*/dblogger.py`

1. ORM：Source 模型加 4 列定义（`String(2)`, `String(64)`, `Integer`, `String(255)`）
2. `_add_attack()`：创建新 Source 时：
   ```python
   geo = {'country_code': None, 'country_name': None, 'asn': None, 'asn_org': None}
   if self.geoip_resolver:
       ip_str = utils.int_to_addr(addr_int)   # 存整数的 pot 需转换
       geo = self.geoip_resolver.resolve(ip_str)
   source = DBThread.Source(..., **geo)
   ```
   注意各 pot 存 IP 形式不同：DNS/NTP/SSDP/chargen/generic 的 `db_params['ip']` 均已是整数（由 pot handler 的 `utils.addr_to_int()` 转换），DBThread 内需 `utils.int_to_addr()` 还原后查询。
3. `_create_dbthread` 调用处（各 pot 的 `*pot.py`）传入 resolver——resolver 在 PotLoader.setup 阶段创建一次，共享给 5 个 pot。

resolver 创建位置：`potloader.py` 的 `_setup_dbthread()` 中（在创建 DBThread 之前）：
```python
from core.geoip import GeoIPResolver, ensure_dbs
ensure_dbs(...)  # 失败时 resolver 为 None，蜜罐继续跑（GeoIP 是增强非必需）
self.geoip_resolver = GeoIPResolver(...)
```

### 新增 `ddospot/migrate_geoip.py`（一次性迁移脚本）

```
用法: python migrate_geoip.py [--db-dir db/]
流程:
  1. ensure_dbs() 确保 mmdb 存在
  2. glob db/*.sqlite3
  3. 对每个库:
     a. 找出 *_sources 表（sqlite_master 查询）
     b. 对每张 sources 表:
        - PRAGMA table_info 检查 4 列，缺的执行 ALTER TABLE ADD COLUMN
        - SELECT 主键 WHERE country_code IS NULL
        - 整数 IP → int_to_addr → resolve → UPDATE
  4. 打印每库回填统计（总数/成功/失败）
幂等性: 列已存在跳过 ALTER；已回填行不命中 WHERE NULL
```

### 修改 `docker-compose.yml`

```yaml
command: sh -c "python migrate_geoip.py && python ddospot.py -n"
```

迁移先于蜜罐运行；后续重启迁移幂等秒过（无 NULL 行时只做 PRAGMA 检查）。

## 数据流（变更后）

```
UDP 包 → handle() → log_queue.put(insert, db_params含整数IP)
  → DBThread._add_attack():
      1. 查 Source 是否存在
      2. 不存在 → int_to_addr(ip) → resolver.resolve() → 建 Source(含4字段)
      3. 建 Attack 行
```

## 错误处理

- mmdb 下载失败：resolver 为 None，新 Source 的 4 字段为 NULL，蜜罐正常运行（GeoIP 是增强功能，不阻塞启动）
- 单次 resolve 失败：该 IP 的字段为 NULL，不影响该行其他数据
- 迁移脚本对无 sources 表的库（如 ddospot.db）自动跳过
- 迁移脚本 GeoIP 全失败（mmdb 无法下载）：ALTER 仍执行，回填跳过，退出码 0 并打印警告——蜜罐可正常启动，下次重启再试回填

## 测试方案

- 单元测试（本地 pytest）：
  - `test_geoip.py`：resolver 返回结构、私有 IP 全 None、mmdb 缺失时 ensure 行为
  - 迁移脚本：构造旧 schema 测试库 → 跑迁移 → 断言列存在、值正确、幂等重跑
- 集成验证：
  - 本地起容器（docker compose up），发测试 UDP 包，查 sources 表新行含 4 字段
- 生产部署（顺序）：
  1. hkg01（数据最少）先上，观察迁移日志与蜜罐运行
  2. 无异常后 jkt01、ams01（大库回填预计 <1 分钟，mmdb 内存查询）

## 涉及文件清单

| 文件 | 变更类型 |
|---|---|
| `ddospot/core/geoip.py` | 新增 |
| `ddospot/migrate_geoip.py` | 新增 |
| `ddospot/core/alerter.py` | 重构（用 geoip 模块） |
| `ddospot/core/dbbase.py` | `__init__` 加 resolver 参数 |
| `ddospot/core/potloader.py` | `_setup_dbthread` 创建 resolver 并传入 |
| `ddospot/pots/ntp/dblogger.py` | ORM 列 + 填充 |
| `ddospot/pots/dns/dblogger.py` | 同上 |
| `ddospot/pots/ssdp/dblogger.py` | 同上 |
| `ddospot/pots/chargen/dblogger.py` | 同上 |
| `ddospot/pots/generic/dblogger.py` | 同上 |
| `docker-compose.yml` | command 加迁移前置 |
