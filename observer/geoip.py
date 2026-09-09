import hashlib
import os
import shutil
import urllib.request

import geoip2.database

BASE = 'https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release'
FILES = {
    'GeoIP-Country.mmdb': 'Country-without-asn.mmdb',
    'GeoIP-ASN.mmdb': 'GeoLite2-ASN.mmdb',
}


def ensure_dbs(data_dir):
    os.makedirs(data_dir, exist_ok=True)
    for local_name, src_name in FILES.items():
        path = os.path.join(data_dir, local_name)
        if os.path.exists(path) and os.path.getsize(path) > 0:
            continue
        tmp = path + '.tmp'
        urllib.request.urlretrieve('%s/%s' % (BASE, src_name), tmp)
        expected = urllib.request.urlopen(
            '%s/%s.sha256sum' % (BASE, src_name)
        ).read().decode().split()[0]
        actual = hashlib.sha256(open(tmp, 'rb').read()).hexdigest()
        if actual != expected:
            os.remove(tmp)
            raise Exception('GeoIP sha256 mismatch for %s' % src_name)
        shutil.move(tmp, path)


def lookup(ip, country_reader, asn_reader):
    result = {
        'country_code': '??',
        'country_name': None,
        'asn': None,
        'asn_org': None,
    }
    try:
        c = country_reader.country(ip)
        result['country_code'] = c.country.iso_code
        result['country_name'] = c.country.name
    except Exception:
        pass
    try:
        a = asn_reader.asn(ip)
        result['asn'] = a.autonomous_system_number
        result['asn_org'] = a.autonomous_system_organization
    except Exception:
        pass
    return result
