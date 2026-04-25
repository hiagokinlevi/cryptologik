from pathlib import Path

from analyzers.cert_expiry import scan_cert_expiry, result_to_json_dict


def test_encrypted_private_key_pem_is_skipped(tmp_path: Path):
    pem = tmp_path / "encrypted-key.pem"
    pem.write_text(
        """-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIBvTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQI0SOMEFAKEFAKECAggA
MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAEqBBCxFAKEFAKEFAKEFAKEFAKEBIIBY
-----END ENCRYPTED PRIVATE KEY-----
"""
    )

    result = scan_cert_expiry(str(pem), warn_days=30)
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.status == "skipped"
    assert finding.severity == "low"
    assert "encrypted private key" in finding.message.lower()


def test_non_certificate_pem_is_skipped_and_present_in_json(tmp_path: Path):
    pem = tmp_path / "mixed.pem"
    pem.write_text(
        """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASC...
-----END PRIVATE KEY-----
"""
    )

    result = scan_cert_expiry(str(pem), warn_days=30)
    payload = result_to_json_dict(result)
    assert payload["findings"]
    first = payload["findings"][0]
    assert first["status"] == "skipped"
    assert first["severity"] == "low"
    assert "Skipped file" in first["message"]
