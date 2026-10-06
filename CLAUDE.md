# ScopeGate — working context

A reverse proxy that gives an outside vendor **a few named pages of an internal
web app, for a limited time, with no network access**. Full design:
[README.md](README.md). How to run it: [RUNNING.md](RUNNING.md). Deployment:
[deploy/README.md](deploy/README.md). Read those rather than re-deriving — this
file is only the things they do not say.

## Naming

The product is **ScopeGate** (per the logo, `logo.png`). The code, the Python
package and the GitHub repo are still **vendorgate / Vendor-Gate → Scope-Gate**.
The interface and the deck say ScopeGate; the code does not. A full rename
(package dir, config prefixes, CLI, email copy, systemd units) is pending and
has not been started.

Repo: https://github.com/AakashH2006/Scope-Gate (public)

## State

- Build-plan steps 1–9 and 11 done. **Step 10 (AWS deployment) has never been
  run** — everything in `deploy/` is reviewed-but-untested config.
- 98 tests pass (`python -m pytest`). `python scripts/demo_run.py` walks the
  ten-step demo script over real HTTP: 47/47 checks.
- Local run: `python scripts/run_local.py` → gateway on :8000, mock site on
  :9000. Admin credentials are in `admin-credentials.local.txt` (gitignored).
- Database is a local SQLite file `vendorgate.db` (gitignored). Holds one admin.

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
- **`BLOCKED_LINKS=remove`** — links to pages outside the grant are stripped
  from proxied HTML so a vendor cannot even read what else exists. Defence in
  depth; the path allowlist is still the control.
- **Three mail backends** (`file` default / `console` / `smtp`). Nothing is
  actually sent locally; invites land in `outbox/`.
- Admin sessions and the rate limiter are **in-memory → single process only**.
- The link and password still travel in the same email (README §16, open).

## Known gaps, roughly in priority order

1. AWS deployment never run. Watch for: EC2 blocks outbound port 25 (use 587);
   SES starts in sandbox and only delivers to verified addresses; Gmail needs
   an app password and rewrites `From` to `SMTP_USER`.
2. **Mail has no retries** — one attempt, then an `email_failed` audit row. A
   transient failure means the vendor never gets the link.
3. Single process (see above). Multiple workers would break sessions, the rate
   limiter and the expiry job.
4. One admin, no roles. `/admin` shares a hostname with vendor routes.
5. No LICENSE (public repo = all rights reserved), no CI.

## The deck

Slides artifact: https://claude.ai/artifact/RYs1CunhNyskJt8ajeCNk9 — 7 slides,
source files in the session scratchpad, not in this repo. If asked to edit it,
read the artifact first. Owner preferences: dense slides with no large empty
areas, diagram-led, **no build-progress content** (no test counts, no "steps
done"), framed as what the design delivers.
