# Deploying the demo (build-plan step 10)

Target shape from section 5 of the plan: one EC2 free-tier instance running
Caddy, the gateway and the mock internal site; Postgres on RDS (or SQLite on the
instance); a free subdomain pointing at the instance.

Only ports **80** and **443** are open to the internet. The gateway listens on
`127.0.0.1:8000`, the mock site on `127.0.0.1:9000`, and neither is in the
security group.

Everything below is the console path. It needs no AWS access keys on your
machine, which is one less long-lived secret to look after than installing the
CLI for a single instance.

## 0. The instance and the way in

1. **EC2 -> Launch instance.** Ubuntu 24.04 LTS, `t3.micro`, 20 GB gp3.
2. **Key pair:** create one, download the `.pem`, `chmod 400` it. It is the only
   way in; AWS will not show it again.
3. **Security group** -- three inbound rules and nothing else:

   | Port | Source | Why |
   |---|---|---|
   | 22 | **your own IP only** | SSH. Never `0.0.0.0/0`. |
   | 80 | `0.0.0.0/0` | Caddy's HTTP-01 certificate challenge, then redirect |
   | 443 | `0.0.0.0/0` | the vendor and the admin |

   Ports 8000 and 9000 are deliberately absent: the gateway and the mock site
   bind loopback, so the security group does not need to defend them.
4. **Elastic IP:** allocate one and associate it, or a stop/start changes the
   public IP and breaks DNS and the certificate.
5. **DNS:** point a free subdomain (DuckDNS or similar) at that IP and wait for
   it to resolve *before* starting Caddy -- the certificate challenge needs the
   name to already answer.

Then `ssh -i key.pem ubuntu@your-host` for everything below.

**Cost.** On an account created on or after 15 July 2025 there is no 750
free-hours-a-month allowance any more: EC2 draws down a $200 credit that expires
after six months. Set a billing alert, and stop the instance when you are not
demoing. Skip RDS for the demo -- SQLite on the instance (section 3) is one less
thing to pay for and one less thing to configure.

## 1. Instance

```bash
sudo apt update && sudo apt install -y python3-venv git
sudo useradd --system --user-group --home /opt/scopegate scopegate
sudo useradd --system --user-group --no-create-home mocksite
sudo mkdir -p /opt/scopegate /var/lib/scopegate /etc/scopegate
sudo chown scopegate:scopegate /var/lib/scopegate
```

Copy the project to `/opt/scopegate`, then:

```bash
cd /opt/scopegate
sudo -u scopegate python3 -m venv .venv
sudo -u scopegate .venv/bin/pip install -r requirements.txt
```

## 2. Secrets

```bash
.venv/bin/python -m scopegate.cli keys         # prints SECRET_KEY and TOTP_ENC_KEY
sudo install -m 600 -o root -g scopegate /dev/null /etc/scopegate/scopegate.env
sudo nano /etc/scopegate/scopegate.env        # see .env.example for every key
```

The file must stay `0600` and owned so that only the service user can read it
(section 6.7). Set at minimum `PUBLIC_URL`, `SECRET_KEY`, `TOTP_ENC_KEY`,
`DATABASE_URL`, `UPSTREAM_URL`, `ALLOWED_PAGES` and the SMTP block.

The gateway **refuses to start** when `PUBLIC_URL` is not a local address and
any of `SECRET_KEY`, `TOTP_ENC_KEY` or an `https://` `PUBLIC_URL` is missing
(`_startup_checks` in `app.py`). `SECURE_COOKIES` is *not* part of that check --
it defaults to on for an `https://` `PUBLIC_URL`, so leave it unset rather than
setting it to anything.

Leave `MAIL_BACKEND=smtp` in a deployment. The `file` backend writes into
`MAIL_OUTBOX_DIR`, and `ProtectSystem=strict` in the unit makes that fail unless
the directory is added to `ReadWritePaths`.

## 3. Database

SQLite (simplest):

```
DATABASE_URL=sqlite+aiosqlite:////var/lib/scopegate/scopegate.db
```

RDS Postgres (free tier, not publicly accessible, same VPC, security group open
only to the instance):

```
DATABASE_URL=postgresql+asyncpg://scopegate:PASSWORD@your-db.rds.amazonaws.com:5432/scopegate
```

Then create the schema and the admin account:

```bash
# fresh database -- creates the tables and stamps the Alembic revision
sudo -u scopegate .venv/bin/python -m scopegate.cli init-db

# on every later deploy, before restarting the service
sudo -u scopegate .venv/bin/python -m scopegate.cli migrate

sudo -u scopegate .venv/bin/python -m scopegate.cli create-admin --email you@company.example
```

That prints the password and the authenticator provisioning URI **once**. Add it
to an authenticator app before closing the terminal.

## 4. Services

```bash
sudo cp deploy/scopegate.service deploy/mocksite.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mocksite scopegate
sudo systemctl status scopegate
```

## 5. Caddy and DNS

Point a free subdomain (DuckDNS or similar) at the instance's public IP, put the
hostname into `deploy/Caddyfile`, then:

Caddy is not in the Ubuntu archive; add its own apt repository first
(<https://caddyserver.com/docs/install>):

```bash
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
  | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
  | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg
sudo chmod o+r /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt install -y caddy

sudo cp deploy/Caddyfile /etc/caddy/Caddyfile   # hostname edited first
sudo systemctl reload caddy
sudo journalctl -u caddy -n 30                  # watch the certificate arrive
```

Caddy obtains the certificate automatically. Moving to a customer domain later
means changing `PUBLIC_URL`, the Caddy hostname and the DNS record.

## 5a. Mail

Two things bite here, and neither shows up until a vendor is waiting:

- **EC2 blocks outbound port 25.** Use **587** with STARTTLS. `SMTP_PORT=587` is
  already the default.
- **Gmail** needs an *app password*, not the account password, and it rewrites
  `From` to match `SMTP_USER` -- so set `MAIL_FROM` to the same address or the
  header the vendor sees will not be the one you configured.
- **Amazon SES** starts in *sandbox*: it accepts the message and delivers only to
  **verified** addresses, silently dropping the rest. Verify the vendor address
  you will demo with, or request production access first.

Check the credentials before anything depends on them -- this connects, logs in
and sends nothing:

```bash
sudo -u scopegate .venv/bin/python -m scopegate.cli check-mail
```

Then send one real invite to yourself before the demo. A failure writes an
`email_failed` audit row and the dashboard flags it; the grant's **Resend**
button issues a new link and password once the cause is fixed.

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
- **Schema upgrades**: run `scopegate.cli migrate` before restarting the
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
