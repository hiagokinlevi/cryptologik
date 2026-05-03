import json

from click.testing import CliRunner

from cryptologik_cli.main import cli


def test_cert_expiry_json_output_file_parity(tmp_path):
    cert_file = tmp_path / "cert.pem"
    cert_file.write_text(
        """-----BEGIN CERTIFICATE-----
MIIBszCCAVmgAwIBAgIUJ8m+Q3Q2jQ4w6bLQ6A0hK2mG2hUwCgYIKoZIzj0EAwIw
EjEQMA4GA1UEAwwHZXhhbXBsZTAeFw0yNDAxMDEwMDAwMDBaFw0zNDAxMDEwMDAw
MDBaMBIxEDAOBgNVBAMMB2V4YW1wbGUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AAS4n8f0QwQ9w5t8Y7Yx3NnQxv8QX9yE3dQm2rF5QvA7hYv9sA4oW9bQw5b4v8A4
j6uS9VQ3R2mQW3i+0C1D8vJxo1MwUTAdBgNVHQ4EFgQUQ3R2mQW3i+0C1D8vJx4n
8f0QwQ8wHwYDVR0jBBgwFoAUQ3R2mQW3i+0C1D8vJx4n8f0QwQ8wDwYDVR0TAQH/
BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiA9mBvY6f4Q6z2m8jYQ+8o6z9eWQ2h8
0kYz9gYw4W9nYwIgYV7J5e3Vw2g1l4sT1x8JvD5Kx3Q2gQ7q4n9Y2m1Q2h8=
-----END CERTIFICATE-----
""",
        encoding="utf-8",
    )

    out_file = tmp_path / "report.json"
    runner = CliRunner()

    stdout_result = runner.invoke(cli, ["cert-expiry", "--cert", str(cert_file), "--json"])
    assert stdout_result.exit_code == 0
    stdout_json = json.loads(stdout_result.output)

    file_result = runner.invoke(
        cli,
        ["cert-expiry", "--cert", str(cert_file), "--json", "--output", str(out_file)],
    )
    assert file_result.exit_code == 0
    assert file_result.output == ""
    assert out_file.exists()

    file_json = json.loads(out_file.read_text(encoding="utf-8"))
    assert isinstance(file_json, dict)
    assert file_json.keys() == stdout_json.keys()
