# cryptologik

Minimal defensive toolkit for cryptographic and blockchain security checks.

## Purpose

`cryptologik` helps security teams quickly review:
- TLS configuration posture
- Certificate expiry risk
- Smart contract security issues

## Installation (Python)

Using `pip`:

```bash
python -m pip install cryptologik
```

From source (repo checkout):

```bash
python -m pip install .
```

## Usage Examples

### TLS configuration check

```bash
cryptologik tls-check --input examples/tls/server.yaml
```

Use a policy profile override (YAML/JSON):

```bash
cryptologik tls-check --input examples/tls/server.yaml --config policies/tls-policy.yaml
```

Policy precedence for `tls-check` is: `CLI flags > --config file > built-in defaults`.

### Certificate expiry check

```bash
cryptologik cert-expiry --cert examples/certs/leaf.pem --warn-days 30
```

### Smart contract scan

```bash
cryptologik contract-scan --path examples/contracts/SimpleVault.sol
```

Fail CI when findings are at least `high` severity:

```bash
cryptologik contract-scan --path examples/contracts/SimpleVault.sol --fail-on high
```

## Notes

Use `--help` on any command for full options:

```bash
cryptologik --help
cryptologik tls-check --help
```
