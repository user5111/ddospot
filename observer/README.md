# DDoSPot Observer

Real-time DDoS attack trend dashboard for DDoSPot honeypots.

## Architecture

A Python collector (cron, 1m) SSHes into each honeypot, reads new attack rows
from each pot's sqlite, resolves GeoIP (country+ASN) locally, and upserts into
`warehouse.sqlite3`. Grafana (Docker) reads the warehouse via the SQLite
datasource plugin and renders a time-series of attack events.

Honeypots are never modified.

## Dashboard

Visit `http://192.168.1.9:3001/d/ddospot-observer-core`

Panels:
- **Attack events over time by pot** — time-series, one line per pot
- **Total events** — stat counter (filtered)
- **Unique attacker IPs** — stat counter (filtered)
- **Top 10 source countries** — table with event count + unique IPs

Variables: `node` (hkg01/jkt01/ams01), `country`, `pot` — all multi-select.

## Setup (on dashboard host 192.168.1.9)

### 1. Install Docker
```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
# log out and back in for group change
```

### 2. Install collector deps
```bash
python3 -m venv ~/ddospot-observer-venv
~/ddospot-observer-venv/bin/pip install paramiko geoip2 pyyaml pytest
```

### 3. Deploy observer code
```bash
mkdir -p ~/ddospot-observer
# copy observer/ and tests/ dirs here
cd ~/ddospot-observer
cp observer/config.example.yaml observer/config.yaml
# edit config.yaml if node ports/paths differ
```

### 4. Run tests
```bash
~/ddospot-observer-venv/bin/pytest tests/ -v
```

### 5. Bootstrap collector (pulls history + downloads GeoIP mmdb)
```bash
~/ddospot-observer-venv/bin/python -m observer.collector --once
```

### 6. Install cron
```bash
(crontab -l 2>/dev/null | grep -v observer.collector; echo "*/1 * * * * cd ~/ddospot-observer && ~/ddospot-observer-venv/bin/python -m observer.collector >> observer/collector.log 2>&1") | crontab -
```

### 7. Start Grafana
```bash
cd ~/ddospot-observer/observer
docker compose up -d
```

### 8. Open dashboard
Visit `http://192.168.1.9:3001/d/ddospot-observer-core`.

## Caveat

In reflection-amplification attacks, the source IP is spoofed (it's the victim,
not the attacker). Country attribution reflects where the DNS/NTP response was
sent to, not necessarily who launched the attack.

## Update GeoIP mmdb (weekly)
```bash
rm ~/ddospot-observer/observer/data/GeoIP-*.mmdb
~/ddospot-observer-venv/bin/python -m observer.collector --once
```

## Files
- `collector.py` — SSH pull + GeoIP + upsert
- `warehouse.py` — schema + idempotent upsert
- `geoip.py` — mmdb download + lookup
- `docker-compose.yml` — Grafana 11.5.2
- `grafana/provisioning/` — datasource + dashboard
