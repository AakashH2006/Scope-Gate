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
- CI runs lint, the 118 tests, the demo script and an `alembic check` on
  3.12 and 3.13, plus a job that fails if a secret file is ever tracked.
- 118 tests pass (`python -m pytest`). `python scripts/demo_run.py` walks the
  ten-step demo script over real HTTP: 47/47 checks (the resend button is
  covered by pytest, not by the demo script).
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
- The link and password still travel in the same email (README §16, open).

## What is left, in priority order

1. **AWS deployment — the only unfinished build step.** `deploy/` is written
   but has never been executed. Needs the AWS CLI installed and `aws configure`
   run *by the user*; it takes access keys Claude should not handle. Traps:
   EC2 blocks outbound port 25, so use 587; SES starts in sandbox and silently
   delivers only to **verified** addresses; Gmail needs an app password (not
   the account password) and rewrites `From` to match `SMTP_USER`.
2. **Mail has no automatic retry.** One attempt, then an `email_failed` audit
   row. The **manual** half is done: the dashboard flags failures and a
   `pending` grant has a Resend button. What is still missing is something that
   retries on its own, so a failure nobody looks at is still a vendor who never
   gets their link. Roughly 40 lines plus tests.
3. **Single process.** Admin sessions, the login rate limiter and the expiry
   job are all in memory, so a second uvicorn worker breaks all three. Fine for
   a demo; the first thing to fix if anyone asks about load.
4. Smaller: no LICENSE (a public repo without one is all rights reserved); one
   admin with no roles; `/admin` shares a hostname with the vendor routes.

## Open questions, not yet decided

- Do the automatic mail retries before the AWS deployment, or deploy first?

## The deck

Slides artifact: https://claude.ai/artifact/RYs1CunhNyskJt8ajeCNk9 — 7 slides,
source files in the session scratchpad, not in this repo. If asked to edit it,
read the artifact first. Owner preferences: dense slides with no large empty
areas, diagram-led, **no build-progress content** (no test counts, no "steps
done"), framed as what the design delivers.
