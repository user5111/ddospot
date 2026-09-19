#!/usr/bin/env python3
"""一次性迁移脚本：给 *_sources 表加 GeoIP 列并回填历史数据。

由 docker-compose 启动时在 ddospot.py 之前运行。幂等。
"""
import argparse
import glob
import logging
import os
import sqlite3
import sys

# 让脚本既能从容器内 /ddospot 目录运行，也能从仓库根运行
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.geoip import ensure_dbs, GeoIPResolver
from core.utils import int_to_addr


LOGGER = logging.getLogger('migrate_geoip')

NEW_COLUMNS = [
    ('country_code', 'TEXT'),
    ('country_name', 'TEXT'),
    ('asn', 'INTEGER'),
    ('asn_org', 'TEXT'),
]


def _get_sources_tables(conn):
    """返回库中所有以 _sources 结尾的表名"""
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%_sources'"
    ).fetchall()
    return [r[0] for r in rows]


def _existing_columns(conn, table):
    return {r[1] for r in conn.execute('PRAGMA table_info(%s)' % table).fetchall()}


def _alter_add_columns(conn, table):
    """对表加缺失的 GeoIP 列；返回是否加了任何列"""
    existing = _existing_columns(conn, table)
    added = False
    for col_name, col_type in NEW_COLUMNS:
        if col_name not in existing:
            conn.execute('ALTER TABLE %s ADD COLUMN %s %s' % (table, col_name, col_type))
            added = True
            LOGGER.info('  Added column %s %s to %s' % (col_name, col_type, table))
    if added:
        conn.commit()
    return added


def _backfill_null_rows(conn, table, resolver):
    """回填 country_code IS NULL 的行；返回回填行数"""
    rows = conn.execute(
        'SELECT src_ip FROM %s WHERE country_code IS NULL' % table
    ).fetchall()
    if not rows:
        return 0

    backfilled = 0
    for (src_ip,) in rows:
        ip_str = int_to_addr(src_ip)
        if ip_str == '-':
            # 无效 IP（src_ip=0 等），跳过
            continue
        geo = resolver.resolve(ip_str)
        conn.execute(
            'UPDATE %s SET country_code=?, country_name=?, asn=?, asn_org=? WHERE src_ip=?' % table,
            (geo['country_code'], geo['country_name'], geo['asn'], geo['asn_org'], src_ip)
        )
        backfilled += 1

    conn.commit()
    return backfilled


def migrate_db(db_path, resolver):
    """迁移单个 sqlite 库：加列 + 回填。

    resolver 为 None 时只加列不回填。
    """
    LOGGER.info('Processing %s' % db_path)
    conn = sqlite3.connect(db_path)
    try:
        tables = _get_sources_tables(conn)
        if not tables:
            LOGGER.info('  No *_sources tables, skipping')
            return

        for table in tables:
            _alter_add_columns(conn, table)
            if resolver is None:
                LOGGER.info('  No resolver, skipping backfill for %s' % table)
                continue
            n = _backfill_null_rows(conn, table, resolver)
            LOGGER.info('  Backfilled %d rows in %s' % (n, table))
    finally:
        conn.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description='Migrate *_sources tables: add GeoIP columns + backfill')
    parser.add_argument('--db-dir', default='db', help='Directory containing *.sqlite3 files (default: db)')
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

    country_path = os.environ.get('DDOSPOT_GEOIP_DB') or os.path.join(args.db_dir, 'GeoIP-Country.mmdb')
    asn_path = os.environ.get('DDOSPOT_GEOIP_ASN_DB') or os.path.join(args.db_dir, 'GeoIP-ASN.mmdb')

    resolver = None
    try:
        ensure_dbs(country_path, asn_path)
        resolver = GeoIPResolver(country_path, asn_path)
    except Exception as msg:
        LOGGER.warning('GeoIP unavailable, will only ALTER TABLE without backfill: %s' % msg)

    db_files = sorted(glob.glob(os.path.join(args.db_dir, '*.sqlite3')))
    if not db_files:
        LOGGER.info('No .sqlite3 files in %s' % args.db_dir)
        return

    for db_path in db_files:
        try:
            migrate_db(db_path, resolver)
        except Exception as msg:
            LOGGER.error('Error migrating %s: %s' % (db_path, msg))

    LOGGER.info('Migration complete')


if __name__ == '__main__':
    main()
