import os, sqlite3, tempfile
from observer.warehouse import init_db, upsert_event, get_highwater, set_highwater

def _tmp():
    fd, p = tempfile.mkstemp(suffix='.sqlite3')
    os.close(fd)
    return p

def test_init_db_creates_tables():
    p = _tmp()
    init_db(p)
    c = sqlite3.connect(p)
    tables = {r[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert 'events' in tables
    assert 'pull_state' in tables
    c.close()
    os.remove(p)

def test_upsert_event_idempotent():
    p = _tmp()
    init_db(p)
    c = sqlite3.connect(p)
    ev = {
        'node': 'hkg01', 'pot': 'dnspot', 'src_ip': '1.2.3.4',
        'start': '2026-09-10 10:00:00', 'latest': '2026-09-10 10:00:05',
        'count': 5, 'req_size': 48, 'resp_size': 736,
        'country_code': 'US', 'country_name': 'United States',
        'asn': 15169, 'asn_org': 'Google LLC',
        'target': 'dhitc.com',
    }
    upsert_event(c, ev)
    upsert_event(c, ev)
    n = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert n == 1
    c.close()
    os.remove(p)

def test_highwater_get_set():
    p = _tmp()
    init_db(p)
    c = sqlite3.connect(p)
    assert get_highwater(c, 'hkg01', 'dnspot') is None
    set_highwater(c, 'hkg01', 'dnspot', '2026-09-10 10:00:00')
    assert get_highwater(c, 'hkg01', 'dnspot') == '2026-09-10 10:00:00'
    set_highwater(c, 'hkg01', 'dnspot', '2026-09-10 11:00:00')
    assert get_highwater(c, 'hkg01', 'dnspot') == '2026-09-10 11:00:00'
    c.close()
    os.remove(p)
