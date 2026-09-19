import pytest
import sqlite3
import os
import sys
import tempfile
import types

# Python 3.12 removed the stdlib `imp` module; core/spf.py (pre-existing) still
# imports it at module load time. Tests that import the pots package pull in
# spf indirectly. Provide a minimal shim so the import chain succeeds.
# spf.load_plugins() is never invoked during tests, so stubs are sufficient.
if 'imp' not in sys.modules:
    _imp_shim = types.ModuleType('imp')

    def _imp_not_implemented(*args, **kwargs):
        raise NotImplementedError('imp shim: spf.load_plugins not supported in tests')

    _imp_shim.find_module = _imp_not_implemented
    _imp_shim.load_module = _imp_not_implemented
    sys.modules['imp'] = _imp_shim


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
