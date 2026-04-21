from cryptologik import logging as clog


def _safe_run(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except Exception as exc:  # pragma: no cover - defensive boundary
        clog.error("Unhandled error: %s", exc)
        raise
