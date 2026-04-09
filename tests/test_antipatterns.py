"""Tests for the cryptographic anti-patterns detector."""
import tempfile
from pathlib import Path
from crypto.antipatterns.detector import scan_file, scan_directory, Severity


def _make_file(content: str, suffix: str = ".py") -> Path:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
    f.write(content)
    f.close()
    return Path(f.name)


def test_md5_detected():
    path = _make_file("import hashlib\nhashlib.md5(data).hexdigest()\n")
    findings = scan_file(path)
    rules = [f.rule_id for f in findings]
    assert "CP002" in rules


def test_hardcoded_key_detected():
    path = _make_file('key = "0123456789abcdef0123456789abcdef"\n')
    findings = scan_file(path)
    assert any(f.rule_id == "CP001" for f in findings)


def test_ecb_mode_detected():
    path = _make_file("cipher = AES.new(key, AES.MODE_ECB)\n")
    findings = scan_file(path)
    assert any(f.rule_id == "CP005" for f in findings)


def test_insecure_random_detected():
    path = _make_file("token = random.random()\n")
    findings = scan_file(path)
    assert any(f.rule_id == "CP006" for f in findings)


def test_sha1_detected():
    path = _make_file("hashlib.sha1(data)\n")
    findings = scan_file(path)
    assert any(f.rule_id == "CP003" for f in findings)


def test_clean_code_no_findings():
    path = _make_file(
        "import secrets\nimport hashlib\n"
        "token = secrets.token_bytes(32)\n"
        "digest = hashlib.sha256(data).hexdigest()\n"
    )
    findings = scan_file(path)
    # No CP001-CP006 should fire on clean code
    critical_high = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    assert len(critical_high) == 0


def test_comment_skipped():
    path = _make_file("# import hashlib; hashlib.md5(x)\n")
    findings = scan_file(path)
    assert len(findings) == 0


def test_scan_directory():
    with tempfile.TemporaryDirectory() as tmpdir:
        bad_file = Path(tmpdir) / "crypto_utils.py"
        bad_file.write_text("hashlib.md5(data)\n")
        findings = scan_directory(Path(tmpdir))
        assert len(findings) >= 1
