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
