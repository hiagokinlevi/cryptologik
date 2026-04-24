import json
from pathlib import Path

from jsonschema import Draft202012Validator


def test_sample_findings_output_conforms_to_schema() -> None:
    schema_path = Path(__file__).resolve().parents[1] / "schemas" / "findings.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    sample_output = {
        "tool": "cryptologik",
        "version": "1.0.0",
        "findings": [
            {
                "id": "TLS-WEAK-CIPHER-001",
                "category": "tls",
                "severity": "high",
                "message": "Weak cipher suite is enabled",
                "location": {"file": "server.yaml", "line": 12},
                "recommendation": "Disable weak ciphers and prefer AEAD suites"
            }
        ]
    }

    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(sample_output), key=lambda e: e.path)
    assert errors == [], f"Schema validation errors: {[e.message for e in errors]}"
