"""Start the mock internal site and the gateway together, for a local demo.

    python scripts/run_local.py

The mock site goes on 127.0.0.1:9000 and the gateway on 127.0.0.1:8000, which
are the defaults the rest of the configuration expects.  Ctrl-C stops both.

This is a convenience for development.  A deployment uses the two systemd units
in ``deploy/`` instead, with Caddy in front.
"""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import uvicorn  # noqa: E402  (after sys.path)

from vendorgate.config import get_settings  # noqa: E402


async def main() -> None:
    os.environ.setdefault("MOCKSITE_SELF_URL", "http://127.0.0.1:9000")
    settings = get_settings()

    if not Path(".env").is_file():
        print("No .env found -- using built-in local defaults.")
        print("Run `python -m vendorgate.cli keys` and copy .env.example to .env")
        print("for a setup that survives a restart.\n")

    from mocksite.app import create_app as create_mocksite
    from vendorgate.app import create_app

    mock = uvicorn.Server(
        uvicorn.Config(
            create_mocksite(), host="127.0.0.1", port=9000, log_level="warning",
            access_log=False,
        )
    )
    gateway = uvicorn.Server(
        uvicorn.Config(
            create_app(settings),
            host=os.getenv("BIND_HOST", "127.0.0.1"),
            port=int(os.getenv("BIND_PORT", "8000")),
            log_level="info",
            access_log=False,
            server_header=False,
        )
    )

    print("mock internal site  http://127.0.0.1:9000   (private in a real setup)")
    print(f"gateway             {settings.public_url}")
    print(f"admin dashboard     {settings.public_url}/admin")
    print(f"mail backend        {settings.mail_backend}", end="")
    if settings.mail_backend == "file":
        print(f" -> {settings.mail_outbox_dir}/")
    else:
        print()
    print("\nCtrl-C to stop both.\n")

    await asyncio.gather(mock.serve(), gateway.serve())


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nstopped")
