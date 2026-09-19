import os
import pytest
from unittest.mock import patch, MagicMock, mock_open

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'ddospot'))

from core.geoip import GeoIPResolver, ensure_dbs


class TestGeoIPResolver:
    def test_resolve_returns_all_none_for_invalid_ip(self):
        """非法 IP 应返回全 None 字段，不抛异常"""
        resolver = MagicMock(spec=GeoIPResolver)
        resolver.NONE = GeoIPResolver.NONE
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
        resolver.NONE = GeoIPResolver.NONE
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
             patch('core.geoip.urllib.request.urlopen') as mock_url_open, \
             patch('core.geoip.hashlib.sha256') as mock_sha, \
             patch('core.geoip.shutil.move'), \
             patch('core.geoip.os.path.getsize', return_value=1), \
             patch('builtins.open', mock_open(read_data=b'fake')):
            # 模拟 sha256 校验通过
            mock_url_open.return_value.read.return_value = b'abc123  Country-without-asn.mmdb'
            mock_sha.return_value.hexdigest.return_value = 'abc123'
            ensure_dbs(str(country), str(asn))
            # country 和 asn 各下载一次，各校验一次
            assert mock_dl.call_count == 2
