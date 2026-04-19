from __future__ import annotations

from urllib.parse import urlsplit


def parse_tls_target(target: str) -> tuple[str, int]:
    """Parse a TLS target in host[:port] form.

    Supports:
    - hostname
    - hostname:port
    - IPv4
    - IPv4:port
    - bracketed IPv6 ([::1], [::1]:443)

    Defaults to port 443 when unspecified.
    """
    if target is None:
        raise ValueError("target is required")

    raw = target.strip()
    if not raw:
        raise ValueError("target is required")

    # urlsplit gives robust host/port handling (incl. bracketed IPv6)
    parsed = urlsplit(f"//{raw}")
    host = parsed.hostname
    if not host:
        raise ValueError(f"invalid TLS target: {target!r}")

    port = parsed.port if parsed.port is not None else 443
    if port < 1 or port > 65535:
        raise ValueError(f"invalid port in TLS target: {target!r}")

    return host, port
