# DDoSPot Observer Dashboard — Design (core view)

## Goal

Give real-time visibility into DDoS attack trends observed by the deployed
DDoSPot honeypots (hkg01, jkt01, ams01). **Core view first**: a time-series
of attack events across all nodes, filterable by pot (DNS/NTP/SNMP/SSDP/CHARGEN)
and source country. Everything else (map, event wall, health ranking, drilldown)
is explicitly deferred — additive later, no re-architecture.

## Non-goals (this iteration)

- Geographic map, event-stream alert wall, node-health ranking, per-IP drilldown.
- Retention/rollups, multi-tenant auth, alerting.
- Touching honeypot code or config (honeypots stay bit-for-bit unchanged).

## Architecture

```
hkg01 sqlite ─┐
jkt01 sqlite ─┼─ SSH (wentao.pem, per-node port) ─→ collector (cron 1m)
ams01 sqlite ─┘                                        │
                                                       ├─ GeoIP lookup (local mmdb)
                                                       ▼
                                          warehouse.sqlite3 (flat events table)
                                                       │
                                            Grafana (SQLite datasource plugin)
                                                       ▼
                                          browser (http://192.168.1.9:3000, LAN only)
```

Dashboard host: **192.168.1.9** (Ubuntu 24.04, Python 3.12, 23G RAM, `~/.ssh/wentao.pem`
present). Docker not yet installed — install as part of setup. Honeypots are
untouched; the collector reaches them over SSH from 192.168.1.9.

## Components

### 1. Collector (`observer/collector.py`)

Runs via cron every 1 minute on 192.168.1.9. Idempotent — safe to re-run.

**Per-node, per-pot pull:**
- SSH with Paramiko using `~/.ssh/wentao.pem`, user `root`, per-node port
  (hkg01=59934, jkt01=59934, ams01=22).
- Maintains a high-water mark `last_pull_ts` per `(node, pot)` in a small
  `state.sqlite` so only new attack rows are fetched each cycle.
- Query template (common columns across all pots; pot-specific target column
  fetched when present):
  ```sql
  SELECT s.src_ip, a.start, a.latest, a.count, a.request_size, a.response_size
  FROM <pot>_attack a JOIN <pot>_sources s ON a.src_id = s.src_ip
  WHERE a.start > ?
  ```
  - `src_ip` is a true INTEGER (numeric IP). Normalize with
    `ipaddress.ip_address(int(src_ip))` → dotted-quad.
  - Column names vary slightly per pot (`request_size`/`req_size`); collector
    handles with a per-pot column map. Missing columns → NULL.
- Resolves country + ASN for each new src_ip via **local** GeoIP mmdb
  (auto-downloaded on first run from the same Loyalsoldier CDN as the honeypots,
  stored under `observer/data/`).
- Upserts into warehouse by natural key `(node, pot, src_ip, start)`.

**Caveat to surface in UI:** in reflection-amplification attacks the src_ip is
spoofed (it's the victim, not the attacker). Country attribution therefore
reflects "where the response was sent to," not necessarily "who launched it."
The Grafana panel carries a tooltip stating this.

### 2. Warehouse (`observer/warehouse.py` + `warehouse.sqlite3`)

One flat denormalized table — keeps Grafana queries trivial.

```sql
CREATE TABLE IF NOT EXISTS events (
  node          TEXT NOT NULL,
  pot           TEXT NOT NULL,
  src_ip        TEXT NOT NULL,        -- dotted-quad
  start         TEXT NOT NULL,        -- ISO timestamp from honeypot
  latest        TEXT,
  count         INTEGER,
  req_size      INTEGER,
  resp_size     INTEGER,
  country_code  TEXT,                 -- e.g. CN
  country_name  TEXT,                 -- e.g. China
  asn           INTEGER,
  asn_org       TEXT,
  target        TEXT,                 -- dns_name / ntp mode / ssdp st / dst_port (or NULL)
  pulled_at     TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (node, pot, src_ip, start)
);
CREATE INDEX IF NOT EXISTS idx_events_start ON events(start);
CREATE INDEX IF NOT EXISTS idx_events_node_pot ON events(node, pot);
CREATE INDEX IF NOT EXISTS idx_events_country ON events(country_code);
```

`state.sqlite` (tiny, separate) holds `(node, pot, last_pull_ts)`.

### 3. Grafana (`observer/docker-compose.yml` + provisioning)

- `grafana/grafana` image, port mapping `192.168.1.9:3000:3000` so Grafana
  listens only on the LAN interface (not 0.0.0.0).
- SQLite datasource plugin `frser-sqlite-datasource`, provisioned via
  `observer/grafana/provisioning/datasources/sqlite.yaml` pointing at
  `/var/lib/grafana/warehouse.sqlite3` (mounted from host
  `observer/warehouse.sqlite3`).
- Dashboard JSON provisioned via `observer/grafana/provisioning/dashboards/`.
- Anonymous read access enabled (LAN-only, no auth friction); can lock down later.

**Core panel (the one panel we build first):**
- Type: time-series.
- Query:
  ```sql
  SELECT
    strftime('%Y-%m-%d %H:%M:00', start) AS time,
    pot AS metric,
    count(*) AS value
  FROM events
  WHERE $__timeFilter(start)
    AND ($node = 'all' OR node = $node)
    AND ($country = 'all' OR country_code = $country)
  GROUP BY time, pot
  ```
- Variables: `node` (all/hkg01/jkt01/ams01), `country` (all + top-N from data),
  `pot` (all/dns/ntp/ssdp/chargen/generic).
- Auto-refresh: 1m. Panel tooltip carries the reflection-spoofing caveat.

## Data flow & idempotency

1. cron fires `collector.py` every 1m.
2. For each (node, pot): read `last_pull_ts` from `state.sqlite`; query remote
   sqlite for `start > last_pull_ts`; update `last_pull_ts` to max(start) fetched.
3. Resolve GeoIP for each new src_ip (cache lookups in-process for the run).
4. Upsert rows into `warehouse.sqlite3` by PK — re-runs after a crash or a
   duplicate cron fire produce no duplicates and no data loss.
5. Grafana reads warehouse on each panel refresh (1m) — never touches honeypots.

Failure modes: a honeypot unreachable this cycle → skip it, log, keep
`last_pull_ts` unchanged (will catch up next cycle). Warehouse write is one
transaction per cycle. GeoIP mmdb missing → auto-download once; if download
fails, fall back to `country_code='??'` so the trend still renders.

## Deployment (on 192.168.1.9)

Pre-reqs (one-time):
1. `curl -fsSL https://get.docker.com | sh`
2. `pip install paramiko geoip2` (collector deps; or use a venv).
3. `cd ~/ddospot-observer && cp config.example.yaml config.yaml` (edit if needed).

Run:
1. `python collector.py --once` to bootstrap (pulls history + downloads GeoIP).
2. Install cron: `*/1 * * * * cd ~/ddospot-observer && python collector.py >> collector.log 2>&1`
3. `docker compose up -d` (Grafana).
4. Open `http://192.168.1.9:3000`.

## Files added (all under `observer/`, honeypot code untouched)

```
observer/
  collector.py            # SSH pull + GeoIP + upsert
  warehouse.py            # schema create + upsert helpers
  geoip.py                # shared ensure_db (Loyalsoldier mmdb download)
  config.example.yaml     # nodes: [{name, host, port, user, key}] + paths
  config.yaml             # gitignored, real node list
  docker-compose.yml      # Grafana
  grafana/
    provisioning/
      datasources/sqlite.yaml
      dashboards/observer.yml
      dashboards/observer-core.json
  README.md
.gitignore additions: observer/config.yaml, observer/data/, observer/*.sqlite3, observer/collector.log
```

## Verification

- `collector.py --once` exits 0, `warehouse.sqlite3` non-empty, `state.sqlite`
  has a row per (node, pot).
- Grafana datasource test returns rows.
- Core panel renders a multi-line time-series; changing `node` variable filters
  lines; changing `country` variable filters rows.
- Re-running `collector.py --once` changes no row count (idempotency).
- Stopping cron for 5 min then restarting catches up all missed events with no
  duplicates.

## Future (explicitly deferred, additive)

Map panel (country bubbles), event-stream wall, node-health ranking, per-IP
drilldown, retention rollups, alerting, auth.
