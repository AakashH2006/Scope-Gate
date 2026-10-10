# Running ScopeGate

The plan is in [README.md](README.md). This is how to run what has been built.

```
scopegate/           the gateway: auth, grants, proxy, expiry, audit log
mocksite/            the mock internal dashboard (the demo target)
migrations/          Alembic revisions
tests/               124 tests, including the checklist in section 14
scripts/run_local.py start both servers for a local demo
scripts/demo_run.py  drive the whole demo script headlessly, with pass/fail
deploy/              Caddyfile, systemd units, deployment notes
```

## Quick start (local, no mail server, no AWS)

```bash
python -m pip install -r requirements.txt

# 1. keys and configuration
python -m scopegate.cli keys           # prints SECRET_KEY and TOTP_ENC_KEY
cp .env.example .env                   # paste the two keys into it

# 2. database and the admin account
python -m scopegate.cli init-db        # fresh database: create and stamp
python -m scopegate.cli create-admin --email you@company.example
#    -> prints the password and an otpauth:// URI. Add it to an authenticator
#       app now; neither is shown again.

# 3. run the gateway and the mock internal site together
python scripts/run_local.py
```

Then open <http://127.0.0.1:8000/admin>, sign in with the password and a code
from the authenticator, and create a grant.

With `MAIL_BACKEND=file` (the default) the invite is written to `outbox/` as an
`.eml` file instead of being sent, so the whole flow works without a mail
server. The link and password are also shown on the dashboard once, right after
the grant is created.

## Does it work?

```bash
python -m pytest                 # 124 tests, ~85s
python -m pytest -m "not integration"   # skip the ones that need real sockets
python scripts/demo_run.py       # the 10-step demo script, 47 checks
```

`demo_run.py` starts a throwaway gateway and mock site on loopback ports, walks
every step of section 12's demo script over real HTTP, and prints a pass/fail
line for each. It is the fastest way to confirm the build still behaves before a
pitch.

## The commands you will actually use

```bash
python -m scopegate.cli show-config         # the effective configuration
python -m scopegate.cli check-mail          # do the SMTP credentials work? (sends nothing)
python -m scopegate.cli migrate             # apply pending migrations
python -m scopegate.cli reset-admin-totp --email you@company.example
```

## Schema changes

The schema is under Alembic. `init-db` creates it on a fresh database and
stamps the current revision, so the two paths do not diverge; on an existing
database, `migrate` applies what is pending.

After changing `scopegate/models.py`:

```bash
python -m alembic revision --autogenerate -m "what changed"
python -m alembic check          # should say no new operations
python -m scopegate.cli migrate
```

`DATABASE_URL` drives it, so a revision always runs against the same database
the gateway uses and no connection string is stored in `alembic.ini`.

## Real email (Gmail, for the demo)

In `.env`:

```
MAIL_BACKEND=smtp
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=you@gmail.com
SMTP_PASSWORD=the-16-character-app-password
MAIL_FROM=you@gmail.com
```

An app password, not the account password, and 2FA must be on for the Google
account. Moving to Amazon SES later is the same block with a different host.

Sending happens on a worker thread, so a slow server never holds up a request.
A failure is retried on that thread -- `MAIL_RETRY_ATTEMPTS` attempts in total
(3), with the gap doubling from `MAIL_RETRY_BACKOFF_SECONDS` (5s, then 10s) --
and only the final outcome is recorded, so one invite that never arrived is one
`email_failed` on the dashboard rather than one per attempt. The message is kept
in memory while it is retried and never written anywhere, because it holds the
vendor's password; a restart part-way through therefore loses it, and the
grant's **Resend** button is the way back.

## Pointing at a real internal site

`UPSTREAM_URL` and `ALLOWED_PAGES` are the only two settings that need to
change:

```
UPSTREAM_URL=http://10.0.1.25:8080
ALLOWED_PAGES=/reports/monthly,/tickets
```

`ALLOWED_PAGES` is the full set an admin may choose from; a prefix covers that
page and everything under it. A grant can never include anything outside the
list, even if the form is tampered with.

Section 17 of the plan still applies: sub-pages of one dashboard are the easy
case, and an unusual app may need extra rewriting.

## Deployment

See [deploy/README.md](deploy/README.md) for the EC2 + RDS + Caddy walkthrough.
The gateway refuses to start if `PUBLIC_URL` is not local and `SECRET_KEY`,
`TOTP_ENC_KEY`, HTTPS or secure cookies are missing.

## What the build covers

Build-plan steps 1-9 and 11 are done, and step 10 is scripted in `deploy/` but
has not been run on real AWS infrastructure (no AWS account was reachable from
this build). Every box in the section 14 test
checklist has a test behind it.

Decisions taken while building, that the plan left open:

- **Three mail backends** (`file`, `console`, `smtp`) rather than SMTP only, so
  the demo runs with no mail server. Section 9's SMTP path is unchanged.
- **The link and password are shown to the admin once**, immediately after the
  grant is created, so they can be read out if the mail is slow. They are not
  stored in the clear and the dashboard will not show them again.
- **The vendor cookie carries the grant's public id** (signed, not secret) so
  that after a revoke deletes the session row the vendor can still be told *why*
  they are out, rather than getting a bare "session invalid".
- **Admin sessions and the rate limiter live in memory.** A restart signs admins
  out. This is why the deployment notes say one process; see deploy/README.md.
- **Device binding is the user-agent string only**, as section 6.3 intends.
  Anything stronger breaks vendors on mobile networks; the one-successful-login
  rule does the real work.
- **`Date` and the server banner are stripped** from proxied responses, and the
  gateway does not send its own `Server` header either.
- **Links outside the grant are removed from proxied pages** (`BLOCKED_LINKS`,
  default `remove`). The internal site renders its whole navigation, so without
  this a vendor granted one page still reads the names of every other one --
  "Finance", "Users", "Settings" -- which the grant never meant to disclose. Set
  it to `disable` to grey them out instead, or `keep` for the old behaviour.
  This is defence in depth: the path allowlist is the control, and a vendor who
  types the URL is refused either way.

## Open items from the plan

Unchanged, and still open (section 17):

1. The link and the password travel in the same email. Accepted for the demo.
2. Per-site action restrictions: the default is read-only (`GET`, `HEAD`), set
   by `ALLOWED_METHODS`, with the allowlist check already in the right place for
   per-site rules to plug into.
3. The allowed-page list for a real client.
4. The deployment model for clients (shared vs separate) and the connector.
