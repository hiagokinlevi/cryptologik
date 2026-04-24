import importlib
import pkgutil
from datetime import datetime, timedelta, timezone


def _find_key_mgmt_module():
    candidates = []
    for mod in pkgutil.walk_packages():
        name = mod.name
        if "key" in name and ("manage" in name or "rotation" in name):
            candidates.append(name)
    # Prefer cryptologik namespace modules first
    candidates = sorted(candidates, key=lambda n: (0 if n.startswith("cryptologik") else 1, len(n)))

    for name in candidates:
        try:
            module = importlib.import_module(name)
        except Exception:
            continue
        attrs = dir(module)
        if any(a in attrs for a in ["check_key_rotation", "run_key_management_checks", "analyze_key_management"]):
            return module
    raise AssertionError("Unable to locate key management checker module")


def _invoke_checker(module, inventory, policy):
    for fn_name in ["check_key_rotation", "run_key_management_checks", "analyze_key_management"]:
        fn = getattr(module, fn_name, None)
        if callable(fn):
            try:
                return fn(inventory=inventory, policy=policy)
            except TypeError:
                try:
                    return fn(inventory, policy)
                except TypeError:
                    continue
    raise AssertionError("No callable key management check entrypoint found")


def _normalize_findings(result):
    if isinstance(result, dict):
        if "findings" in result and isinstance(result["findings"], list):
            return result["findings"]
        return []
    if isinstance(result, list):
        return result
    return []


def test_key_rotation_max_age_policy_emits_severity_tagged_finding():
    module = _find_key_mgmt_module()

    now = datetime.now(timezone.utc)
    old_date = (now - timedelta(days=120)).date().isoformat()

    inventory = {
        "keys": [
            {
                "id": "kms-prod-signing",
                "last_rotated": old_date,
            }
        ]
    }

    policy = {
        "key_management": {
            "rotation": {
                "max_age_days": 90,
                "severity": "high",
            }
        }
    }

    findings = _normalize_findings(_invoke_checker(module, inventory, policy))

    assert findings, "Expected at least one finding for overdue rotation"

    serialized = "\n".join(str(f) for f in findings)
    assert "kms-prod-signing" in serialized
    assert "high" in serialized.lower(), "Expected policy severity to be present in finding"
    assert "rotate" in serialized.lower(), "Expected remediation text to mention rotation"
