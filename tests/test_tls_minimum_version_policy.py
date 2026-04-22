from analyzers.tls_analyzer import check_tls_minimum_version


def test_flags_legacy_minimum_version_and_enabled_versions():
    sample = {
        "listeners": [
            {
                "name": "public-https",
                "min_version": "TLS1.0",
                "enabled_versions": ["TLS1.0", "TLS1.2"],
            },
            {
                "name": "internal",
                "minimum_version": "TLS1.1",
            },
            {
                "name": "legacy",
                "protocols": ["SSLv3", "TLS1.2"],
            },
        ]
    }

    findings = check_tls_minimum_version(sample)

    assert len(findings) == 4
    assert all(f["rule_id"] == "tls.minimum_version" for f in findings)
    assert all(f["severity"] == "high" for f in findings)
    assert all("TLS 1.2 or TLS 1.3" in f["remediation"] for f in findings)


def test_no_findings_for_modern_tls_only():
    sample = {
        "listeners": [
            {
                "name": "secure",
                "min_version": "TLS1.2",
                "enabled_versions": ["TLS1.2", "TLS1.3"],
            }
        ]
    }

    findings = check_tls_minimum_version(sample)
    assert findings == []
