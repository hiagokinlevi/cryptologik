import json

from click.testing import CliRunner

from cryptologik_cli.main import cli


def test_review_crypto_config_writes_language_specific_findings(tmp_path):
    source = tmp_path / "Example.java"
    output = tmp_path / "findings.json"
    source.write_text(
        """
import java.security.MessageDigest;

class Example {
    byte[] digest(byte[] data) throws Exception {
        return MessageDigest.getInstance("MD5").digest(data);
    }
}
""".strip(),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        cli,
        [
            "review-crypto-config",
            "--path",
            str(source),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert len(payload) == 1
    assert payload[0]["check_name"] == "java_jca_md5"
    assert payload[0]["risk_level"] == "high"


def test_review_crypto_config_strictness_filters_medium_findings(tmp_path):
    scan_dir = tmp_path / "src"
    output = tmp_path / "findings.json"
    scan_dir.mkdir()

    (scan_dir / "legacy.go").write_text(
        """
package main

import "crypto/tls"

func build() *tls.Config {
    return &tls.Config{
        MinVersion: tls.VersionTLS10,
    }
}
""".strip(),
        encoding="utf-8",
    )
    (scan_dir / "curves.go").write_text(
        """
package main

import "crypto/tls"

func build() *tls.Config {
    return &tls.Config{
        CurvePreferences: []tls.CurveID{tls.CurveP224},
    }
}
""".strip(),
        encoding="utf-8",
    )

    result = CliRunner().invoke(
        cli,
        [
            "review-crypto-config",
            "--path",
            str(scan_dir),
            "--strictness",
            "minimal",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert len(payload) == 1
    assert payload[0]["check_name"] == "go_tls_legacy_min_version"
    assert payload[0]["risk_level"] == "high"
