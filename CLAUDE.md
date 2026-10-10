# ScopeGate — working context

A reverse proxy that gives an outside vendor **a few named pages of an internal
web app, for a limited time, with no network access**. Full design:
[README.md](README.md). How to run it: [RUNNING.md](RUNNING.md). Deployment:
[deploy/README.md](deploy/README.md). Read those rather than re-deriving — this
file is only the things they do not say.

## Naming

The product is **ScopeGate** (per the logo, `logo.png`) and so is everything
else now: the Python package `scopegate/`, the CLI (`python -m scopegate.cli`),
the cookie names (`sg_admin` / `sg_session`), the email signature, the systemd
unit and the local database file. The rename was one mechanical commit; nothing
reads `vendorgate` any more.

Repo: https://github.com/AakashH2006/Scope-Gate (public)

## State

- Build-plan steps 1–9 and 11 done. **Step 10 (AWS deployment) has never been
  run** — everything in `deploy/` is reviewed-but-untested config.
- CI runs lint, the 124 tests, the demo script and an `alembic check` on
  3.12 and 3.13, plus a job that fails if a secret file is ever tracked.
- 124 tests pass (`python -m pytest`). `python scripts/demo_run.py` walks the
  ten-step demo script over real HTTP: 47/47 checks (the resend button and the
  mail retries are covered by pytest, not by the demo script).
- Local run: `python scripts/run_local.py` → gateway on :8000, mock site on
  :9000. Admin credentials are in `admin-credentials.local.txt` (gitignored).
- Database is a local SQLite file `scopegate.db` (gitignored). Holds one admin.

## Conventions worth keeping

- **Comments explain why, not what.** Match the density already in the files.
- Every security rule is enforced **server-side on every request**. Nothing
  trusts the browser's clock, cookie contents or client-side state.
- Secrets never enter the repo. `.env`, `*.db`, `outbox/`, `*.local.txt` are
  gitignored — check `git diff --cached` before any push; the repo is public.
- New behaviour gets a test. The section 14 checklist in README.md is the spec.
- Prefer fixing the test environment over weakening an assertion.

## Decisions already taken (do not re-litigate)

- **Grants are immutable.** An admin cannot add pages or extend time on a live
  grant; more of either means a new grant. Widening was considered and rejected
  as added risk.
- **Resend reissues, it does not repeat.** Only hashes of the link and password
  are stored, so the Resend button on a `pending` grant mints a new pair and
  kills the old one. Pages, duration, link deadline and the failed-attempt
  count are all untouched, so it widens nothing — that is why it is allowed
  alongside immutability. It needs the master password, like creating a grant.
  Storing the plaintext invite so it could be re-sent verbatim was rejected:
  it would put a live vendor password at rest.
- **`BLOCKED_LINKS=remove`** — links to pages outside the grant are stripped
  from proxied HTML so a vendor cannot even read what else exists. Defence in
  depth; the path allowlist is still the control.
- **Three mail backends** (`file` default / `console` / `smtp`). Nothing is
  actually sent locally; invites land in `outbox/`.
- Admin sessions and the rate limiter are **in-memory → single process only**.
- **Mail retries are in memory too, deliberately.** Three attempts on the
  sending thread with a doubling gap, one audit row for the final outcome. A
  durable retry queue was rejected: the rendered invite holds a live vendor
  password, so queueing it would put a working credential at rest. A restart
  mid-retry loses the invite, and Resend is the way back.
- **Hiding `UPSTREAM_URL` without inverting the connection was rejected** as
  unachievable: a gateway that dials must hold a routable address, and root
  recovers it from the socket, conntrack, the resolver cache or memory however
  well the config is hidden. The connector in README §16 is the real answer.
- The link and password still travel in the same email (README §17, open).

## What is left, in priority order

1. **The connector — hiding the internal site from the gateway.** Designed and
   written up in README §16, not built. A connector inside the customer's
   network dials *outbound*, so the gateway holds no upstream address and, more
   importantly, cannot reach past the live grant even with root. This is the
   next piece of architecture, and the answer to "what if ScopeGate itself is
   compromised". Bigger than it sounds: new process, stream protocol, the
   policy check duplicated connector-side, certificates at both ends.
2. **AWS deployment — the only unfinished build step, and secondary.**
   `deploy/` is written but has never been executed. Needs the AWS CLI
   installed and `aws configure` run *by the user*; it takes access keys Claude
   should not handle. Traps: EC2 blocks outbound port 25, so use 587; SES
   starts in sandbox and silently delivers only to **verified** addresses;
   Gmail needs an app password (not the account password) and rewrites `From`
   to match `SMTP_USER`.
3. **Single process.** Admin sessions, the login rate limiter and the expiry
   job are all in memory, so a second uvicorn worker breaks all three. Fine for
   a demo; the first thing to fix if anyone asks about load.
4. Smaller: no LICENSE (a public repo without one is all rights reserved); one
   admin with no roles; `/admin` shares a hostname with the vendor routes.

## Open questions, not yet decided

- Is the connector (README §16) worth building before a client is signed, or
  does it wait for one who asks what a gateway compromise would cost them?

## The deck

Slides artifact: https://claude.ai/artifact/RYs1CunhNyskJt8ajeCNk9 — 7 slides,
source files in the session scratchpad, not in this repo. If asked to edit it,
read the artifact first. Owner preferences: dense slides with no large empty
areas, diagram-led, **no build-progress content** (no test counts, no "steps
done"), framed as what the design delivers.
