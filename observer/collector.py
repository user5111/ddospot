import ipaddress
import os
import sys

import geoip2.database
import paramiko
import yaml

from observer.geoip import ensure_dbs, lookup
from observer.warehouse import (
    get_highwater,
    init_db,
    set_highwater,
    upsert_event,
)

POT_QUERIES = {
    'chargenpot': (
        "SELECT s.src_ip, a.start, a.latest, a.count, "
        "a.request_size, a.response_size "
        "FROM chargenpot_attack a "
        "JOIN chargenpot_sources s ON a.src_id=s.src_ip "
        "WHERE a.start > ?",
        None,
    ),
    'dnspot': (
        "SELECT s.src_ip, a.start, a.latest, a.count, d.domain_name "
        "FROM dnspot_attack a "
        "JOIN dnspot_sources s ON a.src_id=s.src_ip "
        "LEFT JOIN dnspot_domains d ON a.domain_id=d.id "
        "WHERE a.start > ?",
        'domain_name',
    ),
    'genericpot': (
        "SELECT s.src_ip, a.start, a.latest, a.count, "
        "a.dst_port, a.request_size, a.response_size "
        "FROM genericpot_attack a "
        "JOIN genericpot_sources s ON a.src_id=s.src_ip "
        "WHERE a.start > ?",
        'dst_port',
    ),
    'ntpot': (
        "SELECT s.src_ip, a.start, a.latest, a.count, "
        "a.mode, a.request_size, a.response_size "
        "FROM ntpot_attack a "
        "JOIN ntpot_sources s ON a.src_id=s.src_ip "
        "WHERE a.start > ?",
        'mode',
    ),
    'ssdpot': (
        "SELECT s.src_ip, a.start, a.latest, a.count, "
        "a.st, a.request_size, a.response_size "
        "FROM ssdpot_attack a "
        "JOIN ssdpot_sources s ON a.src_id=s.src_ip "
        "WHERE a.start > ?",
        'st',
    ),
}

_POT_COLS = {
    'chargenpot': ['src_ip', 'start', 'latest', 'count',
                   'request_size', 'response_size'],
    'dnspot': ['src_ip', 'start', 'latest', 'count', 'domain_name'],
    'genericpot': ['src_ip', 'start', 'latest', 'count',
                   'dst_port', 'request_size', 'response_size'],
    'ntpot': ['src_ip', 'start', 'latest', 'count',
              'mode', 'request_size', 'response_size'],
    'ssdpot': ['src_ip', 'start', 'latest', 'count',
               'st', 'request_size', 'response_size'],
}


def _int_to_ip(n):
    try:
        return str(ipaddress.ip_address(int(n)))
    except Exception:
        return str(n)


def normalize_row(node, pot, row, country_reader, asn_reader, target=None):
    cols = _POT_COLS[pot]
    d = dict(zip(cols, row))
    ip = _int_to_ip(d['src_ip'])
    geo = lookup(ip, country_reader, asn_reader)
    tgt = target
    if tgt is None:
        for tcol in ('domain_name', 'dst_port', 'mode', 'st'):
            if tcol in d:
                tgt = str(d[tcol]) if d[tcol] is not None else None
                break
    return {
        'node': node,
        'pot': pot,
        'src_ip': ip,
        'start': d['start'],
        'latest': d.get('latest'),
        'count': d.get('count'),
        'req_size': d.get('request_size'),
        'resp_size': d.get('response_size'),
        'country_code': geo['country_code'],
        'country_name': geo['country_name'],
        'asn': geo['asn'],
        'asn_org': geo['asn_org'],
        'target': tgt,
    }


_REMOTE_SCRIPT_TEMPLATE = (
    "import sqlite3\n"
    "c=sqlite3.connect({db_path!r})\n"
    "for r in c.execute({sql!r}, ({hw!r},)):\n"
    "    print('\\t'.join('' if x is None else str(x) for x in r))\n"
)


def pull_node(node_cfg, wh_conn, country_reader, asn_reader):
    name = node_cfg['name']
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        node_cfg['host'],
        port=node_cfg['port'],
        username=node_cfg['user'],
        key_filename=os.path.expanduser(node_cfg['key']),
        timeout=15,
    )
    total = 0
    try:
        for pot, (sql, _target_col) in POT_QUERIES.items():
            hw = get_highwater(wh_conn, name, pot) or '1970-01-01 00:00:00'
            db_path = '%s/%s.sqlite3' % (node_cfg['db_dir'], pot)
            script = _REMOTE_SCRIPT_TEMPLATE.format(db_path=db_path, sql=sql, hw=hw)
            stdin, stdout, stderr = client.exec_command(
                "python3 -c '%s'" % script.replace("'", "'\"'\"'")
            )
            err = stderr.read().decode()
            if err:
                sys.stderr.write('[%s/%s] remote error: %s\n' % (name, pot, err))
                continue
            count = 0
            max_ts = hw
            for line in stdout:
                line = line.strip()
                if not line:
                    continue
                row = tuple(line.split('\t'))
                ev = normalize_row(name, pot, row, country_reader, asn_reader)
                upsert_event(wh_conn, ev)
                count += 1
                if ev['start'] and ev['start'] > max_ts:
                    max_ts = ev['start']
            if count > 0 or max_ts > hw:
                set_highwater(wh_conn, name, pot, max_ts)
            total += count
            wh_conn.commit()
    finally:
        client.close()
    return total


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--config', default='observer/config.yaml')
    ap.add_argument('--once', action='store_true')
    args = ap.parse_args()
    cfg = yaml.safe_load(open(args.config))
    init_db(cfg['warehouse_path'])
    ensure_dbs(cfg['geoip_dir'])
    cr = geoip2.database.Reader(
        os.path.join(cfg['geoip_dir'], 'GeoIP-Country.mmdb'))
    ar = geoip2.database.Reader(
        os.path.join(cfg['geoip_dir'], 'GeoIP-ASN.mmdb'))
    import sqlite3
    wh = sqlite3.connect(cfg['warehouse_path'])
    for node in cfg['nodes']:
        try:
            n = pull_node(node, wh, cr, ar)
            print('[%s] %d new events' % (node['name'], n))
        except Exception as e:
            sys.stderr.write('[%s] ERROR: %s\n' % (node['name'], e))
    wh.close()
    cr.close()
    ar.close()


if __name__ == '__main__':
    main()
