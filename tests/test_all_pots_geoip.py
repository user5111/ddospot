import os
import sys
import types
import datetime
import pytest
from unittest.mock import MagicMock

# DNS pot's dns.py imports twisted at module load time. Tests import
# pots.dns.dblogger, which triggers pots.dns.__init__ -> dnspot -> dns.
# Twisted is not installed in the test env; provide stub shims so the import
# chain succeeds. The stubs are never used by dblogger code paths under test.


class _StubModule(types.ModuleType):
    """Module stub that returns a dummy class for any attribute access,
    satisfying `from X import Y` and `class Z(Y)` statements at import time."""
    def __getattr__(self, name):
        return type('Stub_' + name, (), {})


# Build the stub package hierarchy. Submodules must be linked as attributes on
# their parent package so `from twisted.names import server` resolves to the
# submodule (which has __getattr__) rather than a fresh stub on the parent.
_twisted = types.ModuleType('twisted')
_twisted_internet = _StubModule('twisted.internet')
_twisted_names = types.ModuleType('twisted.names')
_twisted_names_dns = _StubModule('twisted.names.dns')
_twisted_names_client = _StubModule('twisted.names.client')
_twisted_names_server = _StubModule('twisted.names.server')
_twisted.internet = _twisted_internet
_twisted.names = _twisted_names
_twisted_names.dns = _twisted_names_dns
_twisted_names.client = _twisted_names_client
_twisted_names.server = _twisted_names_server
for _mod_name, _mod in (
    ('twisted', _twisted),
    ('twisted.internet', _twisted_internet),
    ('twisted.names', _twisted_names),
    ('twisted.names.dns', _twisted_names_dns),
    ('twisted.names.client', _twisted_names_client),
    ('twisted.names.server', _twisted_names_server),
):
    if _mod_name not in sys.modules:
        sys.modules[_mod_name] = _mod

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'ddospot'))

from core.geoip import GeoIPResolver


@pytest.fixture
def fake_resolver():
    r = MagicMock(spec=GeoIPResolver)
    r.resolve.return_value = {
        'country_code': 'US',
        'country_name': 'United States',
        'asn': 15169,
        'asn_org': 'Google LLC'
    }
    return r


@pytest.mark.parametrize('pot_module,table_prefix,db_params_ip_is_str', [
    ('pots.dns.dblogger', 'dnspot', True),
    ('pots.ssdp.dblogger', 'ssdpot', False),
    ('pots.chargen.dblogger', 'chargenpot', False),
    ('pots.generic.dblogger', 'genericpot', False),
])
def test_source_has_geoip_columns(pot_module, table_prefix, db_params_ip_is_str):
    """每个 pot 的 Source ORM 应有 4 个新列"""
    import importlib
    mod = importlib.import_module(pot_module)
    DBThread = mod.DBThread
    from sqlalchemy import inspect
    mapper = inspect(DBThread.Source)
    col_names = [c.key for c in mapper.columns]
    assert 'country_code' in col_names
    assert 'country_name' in col_names
    assert 'asn' in col_names
    assert 'asn_org' in col_names
    assert DBThread.Source.__tablename__ == '%s_sources' % table_prefix


@pytest.mark.parametrize('pot_module,extra_db_params', [
    ('pots.dns.dblogger', {'dns_name': 'test.com', 'dns_type': 'A', 'dns_class': 'IN', 'opcode': 0}),
    ('pots.ssdp.dblogger', {'st': 'upnp:rootdevice', 'mx': 1, 'request_pkt': b'', 'response_pkt': b''}),
    ('pots.chargen.dblogger', {'request_pkt': b''}),
    ('pots.generic.dblogger', {'dport': 161, 'request_pkt': b''}),
])
def test_add_attack_populates_geoip(pot_module, extra_db_params, fake_resolver, tmp_db_path):
    """每个 pot 的 _add_attack 创建新 Source 时应填充 GeoIP"""
    import importlib
    import queue
    import threading
    mod = importlib.import_module(pot_module)
    DBThread = mod.DBThread

    t = DBThread(
        tmp_db_path,
        'test-%s' % pot_module,
        queue.Queue(),
        queue.Queue(),
        threading.Event(),
        5,
        fake_resolver
    )

    # 8.8.8.8 = 134744072
    ip_value = '8.8.8.8' if 'dns' in pot_module else 134744072
    db_params = {
        'ip': ip_value,
        'port': 12345,
        'time': datetime.datetime(2026, 9, 19, 12, 0, 0),
        'input_size': 8,
        'output_size': 736,
    }
    db_params.update(extra_db_params)

    t._add_attack(db_params)

    source = t.session.query(DBThread.Source).one()
    assert source.country_code == 'US'
    assert source.asn == 15169
