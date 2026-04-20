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

### Certificate expiry check

```bash
cryptologik cert-expiry --cert examples/certs/leaf.pem --warn-days 30
```

### Smart contract scan

```bash
cryptologik contract-scan --path examples/contracts/SimpleVault.sol
```

## Notes

Use `--help` on any command for full options:

```bash
cryptologik --help
cryptologik tls-check --help
```
