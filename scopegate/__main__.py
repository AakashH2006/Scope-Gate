"""``python -m scopegate`` runs the gateway with uvicorn."""
from __future__ import annotations

import os

import uvicorn

from .app import create_app
from .config import get_settings


def main() -> None:
    settings = get_settings()
    host = os.getenv("BIND_HOST", "127.0.0.1")
    port = int(os.getenv("BIND_PORT", "8000"))
    uvicorn.run(
        create_app(settings),
        host=host,
        port=port,
        # Caddy terminates TLS and sets X-Forwarded-*; trust it only when the
        # configuration says a proxy is really in front.
        proxy_headers=settings.trust_forwarded_for,
        forwarded_allow_ips="*" if settings.trust_forwarded_for else None,
        access_log=False,  # the audit log is the record that matters here
        # The gateway should not advertise its own stack either (section 6.6
        # strips the internal site's banner; this is the same idea one hop out).
        server_header=False,
    )


if __name__ == "__main__":
    main()
