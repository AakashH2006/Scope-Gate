# Deploying the demo (build-plan step 10)

Target shape from section 5 of the plan: one EC2 free-tier instance running
Caddy, the gateway and the mock internal site; Postgres on RDS (or SQLite on the
instance); a free subdomain pointing at the instance.

Only ports **80** and **443** are open to the internet. The gateway listens on
`127.0.0.1:8000`, the mock site on `127.0.0.1:9000`, and neither is in the
security group.

## 1. Instance

```bash
sudo apt update && sudo apt install -y python3-venv git
sudo useradd --system --home /opt/vendorgate vendorgate
sudo useradd --system --no-create-home mocksite
sudo mkdir -p /opt/vendorgate /var/lib/vendorgate /etc/vendorgate
sudo chown vendorgate:vendorgate /var/lib/vendorgate
```

Copy the project to `/opt/vendorgate`, then:

```bash
cd /opt/vendorgate
sudo -u vendorgate python3 -m venv .venv
sudo -u vendorgate .venv/bin/pip install -r requirements.txt
```

## 2. Secrets

```bash
.venv/bin/python -m vendorgate.cli keys        # prints SECRET_KEY and TOTP_ENC_KEY
sudo install -m 600 -o root -g vendorgate /dev/null /etc/vendorgate/vendorgate.env
sudo nano /etc/vendorgate/vendorgate.env       # see .env.example for every key
```

The file must stay `0600` and owned so that only the service user can read it
(section 6.7). Set at minimum `PUBLIC_URL`, `SECRET_KEY`, `TOTP_ENC_KEY`,
`DATABASE_URL`, `UPSTREAM_URL`, `ALLOWED_PAGES` and the SMTP block.

The gateway **refuses to start** if `PUBLIC_URL` is not local and `SECRET_KEY`,
`TOTP_ENC_KEY`, HTTPS or `SECURE_COOKIES` are missing or off.

## 3. Database

SQLite (simplest):

```
DATABASE_URL=sqlite+aiosqlite:////var/lib/vendorgate/vendorgate.db
```

RDS Postgres (free tier, not publicly accessible, same VPC, security group open
only to the instance):

```
DATABASE_URL=postgresql+asyncpg://vendorgate:PASSWORD@your-db.rds.amazonaws.com:5432/vendorgate
```

Then create the schema and the admin account:

```bash
# fresh database -- creates the tables and stamps the Alembic revision
sudo -u vendorgate .venv/bin/python -m vendorgate.cli init-db

# on every later deploy, before restarting the service
sudo -u vendorgate .venv/bin/python -m vendorgate.cli migrate

sudo -u vendorgate .venv/bin/python -m vendorgate.cli create-admin --email you@company.example
```

That prints the password and the authenticator provisioning URI **once**. Add it
to an authenticator app before closing the terminal.

## 4. Services

```bash
sudo cp deploy/vendorgate.service deploy/mocksite.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mocksite vendorgate
sudo systemctl status vendorgate
```

## 5. Caddy and DNS

Point a free subdomain (DuckDNS or similar) at the instance's public IP, put the
hostname into `deploy/Caddyfile`, then:

```bash
sudo apt install -y caddy
sudo cp deploy/Caddyfile /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

Caddy obtains the certificate automatically. Moving to a customer domain later
means changing `PUBLIC_URL`, the Caddy hostname and the DNS record.

## 6. Check it

```bash
curl -sS https://your-host/healthz                 # ok
curl -sS -o /dev/null -w '%{http_code}\n' https://your-host/   # 404, reveals nothing
curl -sS http://INSTANCE_PUBLIC_IP:9000/           # must fail: mock site is private
```

Then walk the demo script in section 12 of the main README, or run
`python scripts/demo_run.py` locally, which drives the same sequence headlessly.

## Operational notes

- **One process.** Admin sessions and the login rate limiter live in memory, and
  the expiry job runs in-process. Running several uvicorn workers would give each
  worker its own copy of all three; move them to the database or Redis first.
- **Schema upgrades**: run `vendorgate.cli migrate` before restarting the
  service after a deploy. The app itself does not migrate on startup, so a
  rollback never finds a schema from the future.
- **Log retention** is enforced by the hourly job inside the gateway
  (`LOG_RETENTION_DAYS`), not by cron.
- **Backups**: the audit log is the record of who saw what. Back up the database
  if the retention period matters to the customer.
- **Patching**: the gateway is internet-facing and bridges to the internal site
  (section 17). Keep the instance and the Python dependencies updated.
- **`/admin` exposure**: still on the same hostname as the vendor routes. Section
  6.4 flags restricting it by IP or moving it to its own hostname as the next
  step past a pitch.
