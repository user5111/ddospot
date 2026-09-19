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
        db_params['time'] = datetime.datetime(2026, 9, 19, 12, 5, 0)
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
