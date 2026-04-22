from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict


def evaluate_certificate_expiry(
    *,
    not_after: datetime,
    now: datetime | None = None,
    warn_days: int = 30,
) -> Dict[str, Any]:
    """Evaluate certificate expiry with fail/warn/pass semantics.

    Existing expiry logic is preserved:
    - expired certificates are failures
    - non-expired certificates may emit warning when within threshold
    """
    if now is None:
        now = datetime.now(timezone.utc)

    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)

    remaining = not_after - now
    remaining_days = remaining.total_seconds() / 86400

    expired = remaining.total_seconds() <= 0
    warning = (not expired) and (remaining_days <= warn_days)

    if expired:
        status = "fail"
    elif warning:
        status = "warn"
    else:
        status = "pass"

    return {
        "status": status,
        "expired": expired,
        "warning": warning,
        "warn_days": warn_days,
        "days_remaining": remaining_days,
        "not_after": not_after,
    }
