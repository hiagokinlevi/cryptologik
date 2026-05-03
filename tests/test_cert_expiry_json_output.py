import json
from dataclasses import dataclass

from cryptologik_cli.main import _finding_to_json


@dataclass
class DummyFinding:
    subject: str
    issuer: str
    not_after: str
    days_remaining: int
    severity: str
    code: str


def test_finding_to_json_maps_required_fields():
    finding = DummyFinding(
        subject="CN=example.com",
        issuer="CN=Example CA",
        not_after="2030-01-01T00:00:00+00:00",
        days_remaining=1200,
        severity="low",
        code="CERT_EXPIRY_INFO",
    )

    result = _finding_to_json(finding, "examples/certs/leaf.pem")

    assert result["certificate_path"] == "examples/certs/leaf.pem"
    assert result["subject"] == "CN=example.com"
    assert result["issuer"] == "CN=Example CA"
    assert result["not_after"] == "2030-01-01T00:00:00+00:00"
    assert result["days_remaining"] == 1200
    assert result["severity"] == "low"
    assert result["finding_code"] == "CERT_EXPIRY_INFO"


def test_json_is_deterministic_with_sort_keys():
    payload = [
        {"severity": "high", "finding_code": "B", "subject": "b"},
        {"severity": "high", "finding_code": "A", "subject": "a"},
    ]

    encoded = json.dumps(sorted(payload, key=lambda x: (x["severity"], x["finding_code"], x["subject"])), sort_keys=True, separators=(",", ":"))

    assert encoded == '[{"finding_code":"A","severity":"high","subject":"a"},{"finding_code":"B","severity":"high","subject":"b"}]'
