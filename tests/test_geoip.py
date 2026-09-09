from observer.geoip import lookup


class _FakeCountryResp:
    class country:
        iso_code = 'US'
        name = 'United States'


class _FakeAsnResp:
    autonomous_system_number = 15169
    autonomous_system_organization = 'Google LLC'


class _FakeCountryReader:
    def country(self, ip):
        return _FakeCountryResp()


class _FakeAsnReader:
    def asn(self, ip):
        return _FakeAsnResp()


def test_lookup_success():
    r = lookup('8.8.8.8', _FakeCountryReader(), _FakeAsnReader())
    assert r['country_code'] == 'US'
    assert r['country_name'] == 'United States'
    assert r['asn'] == 15169
    assert r['asn_org'] == 'Google LLC'


def test_lookup_country_failure_keeps_asn():
    class _Boom:
        def country(self, ip):
            raise RuntimeError('boom')
    r = lookup('8.8.8.8', _Boom(), _FakeAsnReader())
    assert r['country_code'] == '??'
    assert r['country_name'] is None
    assert r['asn'] == 15169


def test_lookup_all_failure_returns_unknown():
    class _Boom:
        def country(self, ip):
            raise RuntimeError('boom')
        def asn(self, ip):
            raise RuntimeError('boom')
    r = lookup('8.8.8.8', _Boom(), _Boom())
    assert r['country_code'] == '??'
    assert r['asn'] is None
    assert r['asn_org'] is None
