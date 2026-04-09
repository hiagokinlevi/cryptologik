# Contributing to cryptologik

Thank you for contributing to this defensive security tool. Contributions that improve real-world cryptographic review quality are especially welcome.

## Ways to Contribute

- **New validators:** Add detection patterns for additional cryptographic anti-patterns
- **SWC entries:** Add or update SWC reference entries in `blockchain/swc_mappings/swc_reference.yaml`
- **Policy baselines:** Add or refine cryptographic baseline policies
- **Documentation:** Improve guides, tutorials, or labs
- **Tests:** Improve test coverage for validators and report generation
- **Bug fixes:** Fix incorrect detection patterns, false positives, or false negatives

## Development Setup

```bash
git clone https://github.com/YOUR_USERNAME/cryptologik.git
cd cryptologik

python -m venv .venv
source .venv/bin/activate

pip install -e ".[dev]"

cp .env.example .env
```

## Coding Standards

- **Python:** PEP 8, type hints on all public functions, `structlog` for logging.
- **Docstrings:** All public functions and classes must have complete docstrings.
- **False positive notes:** Every detection pattern must document its false positive risk.
- **No false urgency:** Do not overstate finding severity. Include context about when a finding may be acceptable.
- **Inline comments:** All YAML config files must have inline comments.

## Detection Pattern Standards

New detection patterns in validators must include:
- `check_name`: Unique, descriptive identifier
- `risk_level`: Accurately calibrated (do not mark everything CRITICAL)
- `description`: Plain-language description of the issue
- `recommendation`: Specific, actionable guidance
- `false_positive_note`: When this may not be a real issue

## Pull Request Process

1. Create a feature branch: `git checkout -b feat/add-chacha20-check`
2. Write tests for new detection patterns
3. Run: `pytest tests/`
4. Open a PR with a clear description
5. Reference related issues with `Closes #NNN`

## Commit Message Format

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add ChaCha20-Poly1305 recommendation to ECB findings
fix: reduce false positives for MD5 in non-security contexts
docs: expand key rotation guide with HSM examples
test: add test cases for weak PRNG detection
```

## Code of Conduct

By contributing, you agree to abide by the [Code of Conduct](CODE_OF_CONDUCT.md).
