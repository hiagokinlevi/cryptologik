from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from cryptologik.certificate import evaluate_certificate_expiry


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def test_expired_certificate_is_still_expired_not_warning():
    now = datetime.now(timezone.utc)
    not_after = now - timedelta(days=1)

    result = evaluate_certificate_expiry(not_after=not_after, now=now, warn_days=30)

    assert result["status"] == "fail"
    assert result["expired"] is True
    assert result["warning"] is False


def test_certificate_inside_threshold_emits_warning():
    now = datetime.now(timezone.utc)
    # threshold-1 day (inside warning window)
    not_after = now + timedelta(days=29)

    result = evaluate_certificate_expiry(not_after=not_after, now=now, warn_days=30)

    assert result["status"] == "warn"
    assert result["expired"] is False
    assert result["warning"] is True


def test_certificate_outside_threshold_no_warning():
    now = datetime.now(timezone.utc)
    # threshold+1 day (outside warning window)
    not_after = now + timedelta(days=31)

    result = evaluate_certificate_expiry(not_after=not_after, now=now, warn_days=30)

    assert result["status"] == "pass"
    assert result["expired"] is False
    assert result["warning"] is False
