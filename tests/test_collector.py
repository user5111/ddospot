from observer.collector import normalize_row, POT_QUERIES, _int_to_ip


class _CR:
    def country(self, ip):
        class c:
            class country:
                iso_code = 'CN'
                name = 'China'
        return c()


class _AR:
    def asn(self, ip):
        class a:
            autonomous_system_number = 4808
            autonomous_system_organization = 'China Unicom'
        return a()


def test_int_to_ip():
    assert _int_to_ip(16777216) == '1.0.0.0'
    assert _int_to_ip(76869804) == '4.148.240.172'


def test_normalize_dns_row():
    # dnspot: src_ip, start, latest, count, domain_name
    row = (76869804, '2026-09-10 10:00:00', '2026-09-10 10:00:05', 5, 'dhitc.com')
    ev = normalize_row('hkg01', 'dnspot', row, _CR(), _AR())
    assert ev['src_ip'] == '4.148.240.172'
    assert ev['node'] == 'hkg01'
    assert ev['pot'] == 'dnspot'
    assert ev['target'] == 'dhitc.com'
    assert ev['country_code'] == 'CN'
    assert ev['asn'] == 4808
    assert ev['req_size'] is None
    assert ev['resp_size'] is None
    assert ev['count'] == 5


def test_normalize_ntp_row():
    # ntp: src_ip, start, latest, count, mode, request_size, response_size
    row = (16777216, '2026-09-10 10:00:00', '2026-09-10 10:00:05',
           3, 'MONLIST', 8, 736)
    ev = normalize_row('jkt01', 'ntpot', row, _CR(), _AR())
    assert ev['src_ip'] == '1.0.0.0'
    assert ev['target'] == 'MONLIST'
    assert ev['req_size'] == 8
    assert ev['resp_size'] == 736
    assert ev['count'] == 3


def test_normalize_chargen_row():
    # chargen: src_ip, start, latest, count, request_size, response_size
    row = (16777216, '2026-09-10 10:00:00', '2026-09-10 10:00:05',
           1, 1, 1024)
    ev = normalize_row('ams01', 'chargenpot', row, _CR(), _AR())
    assert ev['target'] is None
    assert ev['req_size'] == 1
    assert ev['resp_size'] == 1024


def test_pot_queries_have_all_pots():
    assert set(POT_QUERIES.keys()) == {
        'chargenpot', 'dnspot', 'genericpot', 'ntpot', 'ssdpot'
    }
