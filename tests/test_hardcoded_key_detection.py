from crypto.validators.source_patterns import detect_hardcoded_keys


def test_detects_python_hex_key_assignment():
    content = "private_key = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'\n"
    findings = detect_hardcoded_keys(content, "app.py")
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "CRYPTO-HARDCODED-KEY"


def test_detects_js_base64_secret_assignment():
    content = "const clientSecret = 'QWxhZGRpbjpPcGVuU2VzYW1lL1Rlc3QrQmFzZTY0PVZhbHVlPT0=';\n"
    findings = detect_hardcoded_keys(content, "index.js")
    assert len(findings) == 1


def test_avoids_non_key_variable_false_positive():
    content = "const description = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';\n"
    findings = detect_hardcoded_keys(content, "index.js")
    assert findings == []


def test_avoids_short_secret_false_positive():
    content = "api_key = 'short-value-123'\n"
    findings = detect_hardcoded_keys(content, "service.py")
    assert findings == []


def test_ignores_unsupported_file_extension():
    content = "secret='0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'\n"
    findings = detect_hardcoded_keys(content, "config.txt")
    assert findings == []
