from cryptologik.tls_scanner import scan_tls_config


def test_tls_cipher_allowlist_policy_passes_when_all_ciphers_approved():
    config = {
        "ciphers": [
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
        ]
    }
    policy = {
        "tls": {
            "cipher_allowlist": [
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256",
            ]
        }
    }

    findings = scan_tls_config(config, policy=policy)

    assert findings == []


def test_tls_cipher_allowlist_policy_flags_disallowed_cipher_with_severity():
    config = {
        "ciphers": [
            "TLS_AES_128_GCM_SHA256",
            "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        ]
    }
    policy = {
        "tls": {
            "cipher_allowlist": [
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384",
            ]
        }
    }

    findings = scan_tls_config(config, policy=policy)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.id == "TLS_CIPHER_NOT_ALLOWLISTED"
    assert finding.severity == "high"
    assert "TLS_RSA_WITH_3DES_EDE_CBC_SHA" in finding.description
    assert finding.field == "ciphers"
