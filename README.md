# ScopeGate

[![CI](https://github.com/AakashH2006/Scope-Gate/actions/workflows/ci.yml/badge.svg)](https://github.com/AakashH2006/Scope-Gate/actions/workflows/ci.yml)

A second, restricted gateway that lets an outside vendor use a few specific pages of an internal web application for a limited time, **without ever getting access to the company network**.

> **Status:** planning document for a **demo build**. Everything marked *(later)* is intentionally out of scope for the demo and is listed again in [Future / client version](#15-future--client-version).
>
> **The demo is built.** See [RUNNING.md](RUNNING.md) to run it, and
> [deploy/README.md](deploy/README.md) to deploy it. Build-plan steps 1-9 and 11
> are done; step 10 is scripted but not yet run on real AWS infrastructure.
> `python -m pytest` covers every box in [section 14](#14-test-checklist);
> `python scripts/demo_run.py` walks the [section 12](#12-demo-setup) demo script
> end to end.

---

## Table of contents

1. [Overview](#1-overview)
2. [Goals and non-goals](#2-goals-and-non-goals)
3. [How it works (end to end)](#3-how-it-works-end-to-end)
4. [Grant life cycle](#4-grant-life-cycle)
5. [Architecture](#5-architecture)
6. [Security design](#6-security-design)
7. [Data model](#7-data-model)
8. [Routes](#8-routes)
9. [Email](#9-email)
10. [Logging and retention](#10-logging-and-retention)
11. [Configuration](#11-configuration)
12. [Demo setup](#12-demo-setup)
13. [Build plan](#13-build-plan)
14. [Test checklist](#14-test-checklist)
15. [Future / client version](#15-future--client-version)
16. [Open items](#16-open-items)
17. [Known limitations](#17-known-limitations)

---

## 1. Overview

Vendors (contractors, support partners, auditors) sometimes need to look at one or two internal pages. Giving them a VPN account puts them *inside* the network, which is far more access than they need and hard to take back.

ScopeGate sits **outside** the network as a reverse proxy. The admin issues a time-limited grant for one vendor email address. The vendor receives a temporary link and a password. After logging in, the vendor sees only the pages the admin allowed, served through the gateway. The vendor never gets network access, a VPN client, or a direct route to the internal site.

When the time is up, or the admin revokes the grant, the session ends immediately.

## 2. Goals and non-goals

### Goals
- Vendor reaches **2-3 allowed pages** of an internal web app and nothing else.
- Admin controls **who**, **which pages**, and **for how long**.
- Admin can **revoke at any time**, taking effect on the vendor's next request and closing any live connections.
- Each link works for **one device only**.
- Everything is **logged** and visible to the admin.
- The vendor needs **no software install**, only a browser.

### Non-goals (demo)
- Preventing screenshots, copying or downloading of what the vendor is allowed to see. The goal is to keep vendors out of the network, not to control what they do with permitted pages.
- Non-web access (SSH, RDP, databases). *(later)*
- Multiple admins, roles or multiple companies (tenants). *(later)*
- Per-site action restrictions beyond the simple default in section 6.6. *(decided later)*

## 3. How it works (end to end)

### Admin issues access
1. Admin signs in to the admin dashboard with password + authenticator code (TOTP).
2. Admin opens "New grant" and enters:
   - vendor email address
   - **master password** again (step-up confirmation)
   - access duration (for example 2 hours)
   - which allowed pages the vendor gets (chosen from the configured list)
3. The system creates a grant, a long random link token, and a random vendor password.
4. The system emails the vendor the link and the password. The **link-expiry clock (3 hours by default)** starts when the email is sent.

### Vendor uses access
1. Vendor opens `https://<gateway-host>/<TOKEN>`.
2. Vendor enters their **email address** and the **password** from the email.
3. On success, the **access timer starts** (the duration the admin chose) and the vendor is tied to this browser.
4. The vendor is redirected to the gateway's proxied area and sees only the allowed pages.
5. When the timer ends, or the admin revokes, the vendor is logged out automatically and the link stops working.

### Two separate clocks

| Clock | Starts | Length | If it runs out |
|---|---|---|---|
| Link validity ("buffer") | Email is sent | 3 hours, configurable | Link dies, grant becomes `expired_unused` |
| Access duration | Vendor logs in successfully | Chosen by admin per grant | Session closed, grant becomes `expired` |

## 4. Grant life cycle

```
            admin creates
                 |
                 v
            [ pending ] ----- link not used in 3h ----> [ expired_unused ]
                 |
        vendor logs in OK
                 |
                 v
            [ active ] ------ duration ends ---------> [ expired ]
                 |
                 +----------- admin revokes ---------> [ revoked ]

   (any state before active) -- too many wrong passwords --> [ locked ]
```

Rules:
- A grant never moves backwards.
- `revoked`, `expired`, `expired_unused` and `locked` are final. Giving the vendor more time means creating a new grant.
- Revoking a `pending` grant is allowed and kills the link.

## 5. Architecture

```
                         INTERNET
                            |
                    +-------v--------+
   Vendor browser ->|  HTTPS (Caddy) |  automatic TLS certificate
                    +-------+--------+
                            |
                    +-------v--------+        +------------------+
   Admin browser -->|    Gateway     |<------>|   Database       |
                    |   (FastAPI)    |        |   (Postgres/RDS) |
                    |                |        +------------------+
                    |  - auth        |
                    |  - grants      |------> SMTP (Gmail for demo)
                    |  - proxy       |
                    |  - expiry job  |
                    +-------+--------+
                            |   private only (127.0.0.1 / private subnet)
                    +-------v--------+
                    |  Mock internal |   demo target with allowed
                    |  dashboard     |   and locked pages
                    +----------------+
```

### Components

| Component | Choice | Notes |
|---|---|---|
| Gateway app | Python, FastAPI | Auth, grants, proxy, expiry |
| Proxy client | httpx (async) | Streams responses; websocket support via `websockets` |
| Database | PostgreSQL on AWS RDS (free tier for the demo) | SQLite is fine for local development |
| TLS / front door | Caddy | Free automatic HTTPS certificate (Let's Encrypt) |
| Server | AWS EC2 (free-tier instance) | Gateway + Caddy + mock site on one machine for the demo |
| Email | SMTP via Python `smtplib` (Gmail app password for the demo) | See section 9 |
| Password hashing | argon2 | For admin password, vendor passwords |
| TOTP | `pyotp` | Authenticator app for the admin |

The **mock internal site must listen only on a private address**. The internet must only be able to reach it through the gateway.

## 6. Security design

### 6.1 Link token
- 32 random bytes from the OS secure random source, URL-safe encoded (about 43 characters), e.g. `https://host/Xk3...`.
- **Not a short number.** A 9-digit number has only a billion possibilities, which can be guessed by a script. The link therefore uses a long random token. The path format `host/<token>` from the original idea is kept; only the token is longer.
- Only a **hash of the token** is stored. The raw token exists only in the email.
- The link carries no information; the server looks the grant up by token hash.

### 6.2 Vendor login (email + password)
- Password is randomly generated (at least 12 characters), shown only in the email, stored as an argon2 hash.
- Login requires the **exact vendor email** the admin entered **and** the password.
- Wrong attempts are counted per grant. After **5 failures** the grant becomes `locked`. The admin is notified on the dashboard.
- Errors are generic ("details incorrect") so the page does not reveal which part was wrong.
- Rate limiting per IP in addition to the per-grant counter.

### 6.3 One link, one device
- Opening the link page (GET) does **not** use it up. This matters because some email security scanners open links automatically; those scanners cannot log in without the password.
- The first **successful login** binds the grant to that browser: the gateway sets a secure session cookie and stores a hash of the session plus a light fingerprint (user agent).
- Another browser or device that opens the link afterwards is refused.
- If the vendor closes the tab and returns **in the same browser** while the grant is still active, the cookie continues the session. Clearing cookies ends it, because the link cannot be used a second time. The admin can issue a fresh grant if needed.
- Edge case: if two people hold the email, the first to log in wins.

### 6.4 Admin authentication
- Admin password (argon2) **plus TOTP** authenticator code at sign-in.
- Creating a grant requires re-entering the **master password** (step-up). A stolen, already-open admin session therefore cannot issue access on its own.
- Admin session cookie: `HttpOnly`, `Secure`, `SameSite=Strict`, short idle timeout.
- CSRF protection on all admin actions.
- Admin routes live under `/admin` and are kept apart from vendor routes.
- Recommended: restrict `/admin` by IP or put it on a separate hostname once the demo moves past a pitch. *(later)*

### 6.5 Expiry and revoke are enforced on the server
- Every proxied request checks, in order: session valid -> grant status is `active` -> `now < access_expires_at`. The browser's clock and any timer on the page are not trusted.
- A background job runs every few seconds and:
  - moves finished grants to `expired` / `expired_unused`,
  - deletes their sessions,
  - **closes open websocket / streaming connections** for them.
- Revoke is the same action triggered by the admin, so it takes effect instantly.
- The vendor page shows a countdown for convenience only.

### 6.6 Proxy rules (what the vendor can reach)
- **Allowlist, not blocklist.** Each grant has a list of allowed path prefixes (for the demo, 2-3 pages of the mock dashboard). Anything else returns a clear "not allowed for your access" page and is logged.
- **Default placeholder restriction:** only `GET` and `HEAD` are allowed (read-only). Real per-site rules, such as which actions or methods a given site needs, are decided later and will plug in here.
- Vendor browser cookies and the gateway session cookie are **never forwarded** to the internal site. The gateway talks to the internal site with its own credentials or none.
- Redirects from the internal site (`Location` headers) and links in responses are rewritten so they stay inside the gateway and never leak internal addresses.
- Internal host names, IPs and server headers are stripped from responses.
- Response headers added: `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, a restrictive `Content-Security-Policy` where the target allows it.
- Request size and time limits to stop abuse.
- After login the vendor is moved off the token URL to a neutral path (for example `/s/...`) so the token does not end up in logs or `Referer` headers.

### 6.7 Secrets and storage
- Secrets (SMTP password, DB password, TOTP encryption key, session signing key) come from environment variables or a file readable only by the service user. Never from the repository.
- TOTP secrets are stored encrypted.
- No raw tokens, passwords or session ids in logs.

## 7. Data model

```
admins
  id, email, password_hash, totp_secret_enc, created_at, last_login_at

grants
  id (internal), public_id (short id shown in the dashboard)
  vendor_email
  token_hash, password_hash
  allowed_paths           (list)
  duration_minutes        (what the admin chose)
  status                  pending | active | expired | expired_unused | revoked | locked
  created_by, created_at
  link_expires_at         (created_at + 3h by default)
  failed_attempts
  activated_at, access_expires_at   (set at successful login)
  revoked_at, revoked_by
  bound_device_hash       (set at successful login)

sessions
  id, grant_id, session_hash, created_at, last_seen_at, ip, user_agent

events                    (audit log)
  id, ts, grant_id (nullable), actor (admin / vendor / system)
  type, ip, user_agent, detail (short text, no secrets)
```

Event types: `grant_created`, `email_sent`, `email_failed`, `link_viewed`, `login_ok`, `login_failed`, `grant_locked`, `device_refused`, `page_viewed`, `page_blocked`, `grant_revoked`, `grant_expired`, `link_expired_unused`, `admin_login_ok`, `admin_login_failed`.

## 8. Routes

### Admin (all behind admin session + TOTP)
| Method | Path | Purpose |
|---|---|---|
| GET/POST | `/admin/login` | Password + TOTP |
| GET | `/admin` | Dashboard: grants, status, time left, last week of logs |
| POST | `/admin/grants` | Create grant (needs master password re-entry) |
| POST | `/admin/grants/{id}/revoke` | Revoke now |
| GET | `/admin/logs` | Log view (last 7 days) with filters |
| POST | `/admin/logout` | End admin session |

### Vendor
| Method | Path | Purpose |
|---|---|---|
| GET | `/{token}` | Login page for that link (does not consume the link) |
| POST | `/{token}/login` | Email + password; on success sets session, starts timer |
| ANY | `/s/{path}` | Proxied area (allowlist enforced) |
| POST | `/s/logout` | Vendor ends their own session early |
| GET | `/s/_status` | Time left (for the countdown) |

Unknown, expired or revoked tokens all return the same neutral "link not valid" page.

## 9. Email

- Sent with Python's built-in `smtplib` over TLS (port 465 or 587), from a background thread so a slow mail server never blocks a request.
- **Demo:** a Gmail account with an app password.
- **Later:** Amazon SES SMTP (needs a verified sender domain; it starts in "sandbox" mode that only sends to verified addresses). Switching is a configuration change; no code changes.
- Settings are loaded from environment variables or a `mail.env` file readable only by its owner (same approach as the existing `access/mail.py` in the dvr-forensics-toolkit repo, which can be adapted).
- The vendor email contains: the link, the password, the link-expiry time, the access duration, and a short plain-language note. No tracking pixels, no external images.
- The admin is told on the dashboard if sending fails (`email_failed`).
- **Open item:** the link and password travel in the same email. This is accepted for the demo and flagged for later (see section 16).

## 10. Logging and retention

- The admin dashboard shows the **last 7 days** of events.
- The backend **keeps 1 year** of events. A nightly job deletes older rows.
- Both periods are settings, not hard-coded (`LOG_DASHBOARD_DAYS`, `LOG_RETENTION_DAYS`).
- Logs contain vendor email addresses and IPs, so treat them as personal data: access restricted to the admin, retention kept as short as the customer needs.
- Page views record the path and result, never page contents.

## 11. Configuration

All via environment variables (names are suggestions):

| Variable | Default | Meaning |
|---|---|---|
| `PUBLIC_URL` | - | e.g. `https://myscopegate.duckdns.org` |
| `DATABASE_URL` | - | Postgres connection string |
| `SECRET_KEY` | - | Signs sessions |
| `TOTP_ENC_KEY` | - | Encrypts TOTP secrets |
| `LINK_TTL_MINUTES` | 180 | Link validity before first login |
| `MAX_LOGIN_ATTEMPTS` | 5 | Before a grant is `locked` |
| `MAX_ACCESS_MINUTES` | 480 | Upper limit admin can choose |
| `ALLOWED_PAGES` | - | List of pages the admin can grant (path prefixes) |
| `UPSTREAM_URL` | `http://127.0.0.1:9000` | The internal site (pluggable) |
| `LOG_DASHBOARD_DAYS` | 7 | Days shown on dashboard |
| `LOG_RETENTION_DAYS` | 365 | Days kept in the backend |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `MAIL_FROM` | - | Email settings |

The `UPSTREAM_URL` setting is deliberate: the demo points it at the mock site, and a real client site can replace it later without changing the gateway.

## 12. Demo setup

### Mock internal dashboard
A small separate web app on a private address with, for example:

- Allowed pages: `/dashboard/overview`, `/dashboard/reports`, `/dashboard/tickets`
- Locked pages: `/dashboard/finance`, `/dashboard/users`, `/dashboard/settings`

It exists to show the gateway letting some pages through and refusing others.

### Hosting (free or near-free)
- AWS EC2 free-tier instance for the gateway, Caddy and the mock site.
- AWS RDS Postgres (free tier) for the database. SQLite is acceptable if RDS is a hurdle.
- A free subdomain (for example from DuckDNS) pointing at the instance. Caddy gets the HTTPS certificate automatically.
- Switching to the company's own domain later means changing `PUBLIC_URL` and the DNS record.
- Security group: open only ports 80 and 443 to the internet. The mock site and database are not open to the internet.

### Demo script (what to show)
1. Admin signs in with password + authenticator code.
2. Admin creates a grant for a test vendor email: 10 minutes, three allowed pages.
3. The vendor email arrives with the link and password.
4. Vendor opens the link, logs in. The countdown starts.
5. Vendor browses the allowed pages. Everything works.
6. Vendor tries a locked page -> blocked, and the block shows in the admin log.
7. The same link on a second device or browser -> refused.
8. Admin revokes -> vendor is logged out on the next click.
9. A second grant is left to run out -> automatic logout when the time ends.
10. A third grant is never opened -> link dies after the link window.

## 13. Build plan

| Step | Deliverable |
|---|---|
| 1 | Project skeleton, config, database models, migrations |
| 2 | Admin login with password + TOTP, dashboard shell |
| 3 | Create grant: token, password, hashing, master-password step-up |
| 4 | Email sending (Gmail SMTP, background thread, failure handling) |
| 5 | Vendor link page, login, attempt limits and lockout, device binding |
| 6 | Reverse proxy with path allowlist, header stripping, redirect rewriting |
| 7 | Expiry job, revoke, closing live connections, countdown |
| 8 | Event logging, dashboard log view, retention job |
| 9 | Mock internal dashboard |
| 10 | AWS deployment (EC2, RDS, Caddy, free domain) |
| 11 | End-to-end demo run using the script above, then fix-ups |

## 14. Test checklist

- [ ] Link token is long, random, and stored only as a hash
- [ ] Wrong email or wrong password gives the same generic error
- [ ] 5 wrong passwords lock the grant
- [ ] A link scanner opening the page does not use up the link
- [ ] Login from a second device after the first is refused
- [ ] Same browser can return while the grant is active
- [ ] Access timer starts at login, not at email send
- [ ] Unused link dies after the link window (3 h)
- [ ] Allowed pages load; locked pages are blocked and logged
- [ ] Non-GET requests are blocked under the default restriction
- [ ] No internal host names or cookies leak through the proxy
- [ ] Redirects from the internal site stay inside the gateway
- [ ] Revoke takes effect on the very next request
- [ ] Expiry closes open websocket / streaming connections
- [ ] Expired and revoked links show the same neutral page
- [ ] Admin cannot create a grant without re-entering the master password
- [ ] Admin login without TOTP fails
- [ ] Logs show 7 days on the dashboard and 1 year is kept in the database
- [ ] No tokens, passwords or session ids appear in any log
- [ ] The mock site is unreachable from the internet except through the gateway

## 15. Future / client version

Not part of the demo; to be designed once a client is signed.

- **Multiple companies (multi-tenant) or one deployment per company.** Decide shared service vs separate deployments.
- **Customer-side connector.** A small agent installed in the customer's network that opens an *outbound* connection to the gateway, so the customer opens no inbound firewall ports. The alternative is a site-to-site VPN per customer.
- **Custom domains** such as `vendors.customer.com`.
- **Amazon SES** with a verified domain for production email.
- Several separate internal sites per vendor (not just sub-pages of one dashboard), which needs per-site address rewriting.
- Multiple admins, roles and approval flows.
- Per-site action restrictions chosen by the customer.
- Restricting `/admin` by IP or a separate hostname.
- Non-web protocols (SSH, RDP, databases).
- Longer or customer-specific log retention for compliance (ISO 27001, SOC 2).

## 16. Open items

1. **Link and password in the same email.** Anyone who reads that one email gets in. Options to brainstorm: send the password over a second channel (SMS or WhatsApp), or email a one-time code at login. Accepted for the demo only.
2. **Per-site restrictions.** Which actions the vendor may take on each allowed page depends on the target site. Default for now: read-only (`GET`, `HEAD`).
3. **Exact allowed-page list** for the mock dashboard and, later, for a real client.
4. **Deployment model** for clients (shared vs separate) and the connector approach.

## 17. Known limitations

- The gateway keeps vendors **off the network** but does not stop them from copying, screenshotting or saving anything on pages they are allowed to see. This is by design.
- Some web apps break behind a proxy (absolute URLs, scripts that build links, websockets). Sub-pages of one dashboard are the easy case; unusual apps may need extra rewriting.
- The gateway is a high-value target (it is internet-facing and bridges to the internal site). It needs regular patching, rate limiting, and monitoring.
- If the admin account is compromised, grants can be issued. TOTP and the master-password step-up reduce, but do not remove, this risk.
- Single admin means no separation of duties and a single point of failure for revoking access.
