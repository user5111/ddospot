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
