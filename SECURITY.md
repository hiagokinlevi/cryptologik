# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities via GitHub's private vulnerability reporting feature (Security tab → "Report a vulnerability").

Include:
- A clear description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested mitigation (optional)

## Response Timeline

- **Acknowledgment:** Within 48 hours
- **Initial assessment:** Within 5 business days
- **Patch (if confirmed critical/high):** Within 30 days

## Scope

In scope:
- Code execution vulnerabilities in the CLI or analysis scripts
- Insecure handling of credentials or sensitive data
- Path traversal or injection vulnerabilities in file scanning
- False negatives in critical cryptographic weakness detection (may affect downstream security decisions)

Out of scope:
- Theoretical vulnerabilities without a practical path
- Issues in upstream third-party dependencies
- Findings in synthetic test data

## Responsible Use

This tool is built for **defensive security review**. It must not be used to attack, compromise, or exploit systems without explicit written authorization from the system owner. All SWC references and vulnerability descriptions are provided for educational and defensive purposes only.
