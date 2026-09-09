import sqlite3


def init_db(path):
    c = sqlite3.connect(path)
    c.execute("""
        CREATE TABLE IF NOT EXISTS events (
            node TEXT NOT NULL, pot TEXT NOT NULL, src_ip TEXT NOT NULL,
            start TEXT NOT NULL, latest TEXT, count INTEGER,
            req_size INTEGER, resp_size INTEGER,
            country_code TEXT, country_name TEXT,
            asn INTEGER, asn_org TEXT, target TEXT,
            pulled_at TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY(node, pot, src_ip, start)
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_events_start ON events(start)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_events_node_pot ON events(node, pot)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_events_country ON events(country_code)")
    c.execute("""
        CREATE TABLE IF NOT EXISTS pull_state (
            node TEXT NOT NULL, pot TEXT NOT NULL, last_pull_ts TEXT,
            PRIMARY KEY(node, pot)
        )
    """)
    c.commit()
    c.close()


def upsert_event(conn, ev):
    conn.execute("""
        INSERT INTO events (node, pot, src_ip, start, latest, count,
                            req_size, resp_size, country_code, country_name,
                            asn, asn_org, target)
        VALUES (:node, :pot, :src_ip, :start, :latest, :count,
                :req_size, :resp_size, :country_code, :country_name,
                :asn, :asn_org, :target)
        ON CONFLICT(node, pot, src_ip, start) DO UPDATE SET
            latest=excluded.latest, count=excluded.count,
            req_size=excluded.req_size, resp_size=excluded.resp_size,
            country_code=excluded.country_code, country_name=excluded.country_name,
            asn=excluded.asn, asn_org=excluded.asn_org, target=excluded.target
    """, ev)


def get_highwater(conn, node, pot):
    row = conn.execute(
        "SELECT last_pull_ts FROM pull_state WHERE node=? AND pot=?", (node, pot)
    ).fetchone()
    return row[0] if row else None


def set_highwater(conn, node, pot, ts):
    conn.execute("""
        INSERT INTO pull_state (node, pot, last_pull_ts) VALUES (?, ?, ?)
        ON CONFLICT(node, pot) DO UPDATE SET last_pull_ts=excluded.last_pull_ts
    """, (node, pot, ts))
