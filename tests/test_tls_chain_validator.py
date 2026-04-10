"""
Tests for crypto/tls_chain_validator.py
Covers TLS-CV-001 through TLS-CV-009 checks, chain-level validation, and happy paths.
"""
import time
import pytest
from crypto.tls_chain_validator import (
    TLSChainValidator,
    CertInfo,
    ChainFinding,
    ChainValidationReport,
    ChainSeverity,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

NOW = 1700000000.0  # fixed reference timestamp
DAY = 86400


def check_ids(report: ChainValidationReport):
    return {f.check_id for f in report.findings}


def _leaf(
    subject_cn="example.com",
    issuer_cn="Intermediate CA",
    sans=None,
    not_before=None,
    not_after=None,
    sig_algorithm="sha256WithRSAEncryption",
    key_type="RSA",
    key_bits=2048,
    is_ca=False,
    serial="001",
):
    return CertInfo(
        subject_cn=subject_cn,
        issuer_cn=issuer_cn,
        sans=sans if sans is not None else [subject_cn, f"www.{subject_cn}"],
        not_before=not_before if not_before is not None else NOW - 30 * DAY,
        not_after=not_after if not_after is not None else NOW + 90 * DAY,
        sig_algorithm=sig_algorithm,
        key_type=key_type,
        key_bits=key_bits,
        is_ca=is_ca,
        serial=serial,
    )


def _intermediate(subject_cn="Intermediate CA", issuer_cn="Root CA"):
    return CertInfo(
        subject_cn=subject_cn,
        issuer_cn=issuer_cn,
        sans=[],
        not_before=NOW - 365 * DAY,
        not_after=NOW + 730 * DAY,
        sig_algorithm="sha256WithRSAEncryption",
        key_type="RSA",
        key_bits=4096,
        is_ca=True,
        serial="int-001",
        chain_index=1,
    )


def _root(subject_cn="Root CA"):
    return CertInfo(
        subject_cn=subject_cn,
        issuer_cn=subject_cn,  # self-signed
        sans=[],
        not_before=NOW - 730 * DAY,
        not_after=NOW + 3650 * DAY,
        sig_algorithm="sha256WithRSAEncryption",
        key_type="RSA",
        key_bits=4096,
        is_ca=True,
        serial="root-001",
        chain_index=2,
    )


def _clean_chain():
    return [_leaf(), _intermediate(), _root()]


# ---------------------------------------------------------------------------
# TLSChainValidator — instantiation
# ---------------------------------------------------------------------------

class TestInstantiation:
    def test_default_init(self):
        v = TLSChainValidator()
        assert v._warning_days == 30
        assert v._ref_time is None
        assert v._allow_self_signed is False

    def test_custom_init(self):
        v = TLSChainValidator(warning_days=14, reference_time=NOW, allow_self_signed=True)
        assert v._warning_days == 14
        assert v._ref_time == NOW
        assert v._allow_self_signed is True


# ---------------------------------------------------------------------------
# TLS-CV-001: Weak signature algorithm
# ---------------------------------------------------------------------------

class TestTLSCV001:
    @pytest.mark.parametrize("algo", [
        "md5WithRSAEncryption",
        "sha1WithRSAEncryption",
        "sha1WithECDSA",
        "sha1WithDSA",
        "md2WithRSA",
        "md4WithRSA",
        "MD5withRSA",
        "SHA1withRSAEncryption",
    ])
    def test_weak_algo_fires(self, algo):
        chain = [_leaf(sig_algorithm=algo), _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        assert "TLS-CV-001" in check_ids(report)

    def test_sha256_no_finding(self):
        chain = _clean_chain()
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        assert "TLS-CV-001" not in check_ids(report)

    def test_sha384_no_finding(self):
        chain = [_leaf(sig_algorithm="sha384WithRSAEncryption"), _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        assert "TLS-CV-001" not in check_ids(report)

    def test_weak_algo_severity_high(self):
        chain = [_leaf(sig_algorithm="sha1WithRSAEncryption"), _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        findings = [f for f in report.findings if f.check_id == "TLS-CV-001"]
        assert findings[0].severity == ChainSeverity.HIGH

    def test_weak_intermediate_also_flagged(self):
        chain = [
            _leaf(),
            CertInfo(
                subject_cn="Intermediate CA",
                issuer_cn="Root CA",
                sans=[],
                not_before=NOW - 365 * DAY,
                not_after=NOW + 730 * DAY,
                sig_algorithm="sha1WithRSAEncryption",
                key_type="RSA",
                key_bits=4096,
                is_ca=True,
                serial="int-001",
                chain_index=1,
            ),
            _root(),
        ]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        assert "TLS-CV-001" in check_ids(report)


# ---------------------------------------------------------------------------
# TLS-CV-002: Expired or not yet valid
# ---------------------------------------------------------------------------

class TestTLSCV002:
    def test_expired_cert(self):
        chain = [_leaf(not_after=NOW - DAY), _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        assert "TLS-CV-002" in check_ids(report)

    def test_expired_cert_severity_critical(self):
        chain = [_leaf(not_after=NOW - DAY), _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        findings = [f for f in report.findings if f.check_id == "TLS-CV-002"]
        assert findings[0].severity == ChainSeverity.CRITICAL

    def test_not_yet_valid(self):
        chain = [_leaf(not_before=NOW + DAY), _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        assert "TLS-CV-002" in check_ids(report)

    def test_not_yet_valid_severity_high(self):
        chain = [_leaf(not_before=NOW + DAY), _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        findings = [f for f in report.findings if f.check_id == "TLS-CV-002"]
        assert findings[0].severity == ChainSeverity.HIGH

    def test_valid_cert_no_002(self):
        chain = _clean_chain()
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        assert "TLS-CV-002" not in check_ids(report)

    def test_zero_timestamps_skipped(self):
        cert = _leaf(not_before=0.0, not_after=0.0)
        report = TLSChainValidator(reference_time=NOW).validate([cert, _intermediate(), _root()])
        assert "TLS-CV-002" not in check_ids(report)


# ---------------------------------------------------------------------------
# TLS-CV-003: Expiring soon
# ---------------------------------------------------------------------------

class TestTLSCV003:
    def test_expiring_within_30_days(self):
        chain = [_leaf(not_after=NOW + 15 * DAY), _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW, warning_days=30).validate(chain)
        assert "TLS-CV-003" in check_ids(report)

    def test_expiring_soon_severity_medium(self):
        chain = [_leaf(not_after=NOW + 15 * DAY), _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW, warning_days=30).validate(chain)
        findings = [f for f in report.findings if f.check_id == "TLS-CV-003"]
        assert findings[0].severity == ChainSeverity.MEDIUM

    def test_not_expiring_soon_no_003(self):
        chain = [_leaf(not_after=NOW + 60 * DAY), _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW, warning_days=30).validate(chain)
        assert "TLS-CV-003" not in check_ids(report)

    def test_expired_fires_002_not_003(self):
        """Expired cert should only produce TLS-CV-002, not also TLS-CV-003."""
        chain = [_leaf(not_after=NOW - DAY), _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        assert "TLS-CV-002" in check_ids(report)
        assert "TLS-CV-003" not in check_ids(report)

    def test_custom_warning_days(self):
        chain = [_leaf(not_after=NOW + 5 * DAY), _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW, warning_days=3).validate(chain)
        assert "TLS-CV-003" not in check_ids(report)

        report2 = TLSChainValidator(reference_time=NOW, warning_days=10).validate(chain)
        assert "TLS-CV-003" in check_ids(report2)


# ---------------------------------------------------------------------------
# TLS-CV-004: Self-signed in non-root position
# ---------------------------------------------------------------------------

class TestTLSCV004:
    def test_self_signed_leaf_fires(self):
        leaf = _leaf(subject_cn="selfsigned.com", issuer_cn="selfsigned.com")
        chain = [leaf, _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        assert "TLS-CV-004" in check_ids(report)

    def test_self_signed_severity_high(self):
        leaf = _leaf(subject_cn="selfsigned.com", issuer_cn="selfsigned.com")
        chain = [leaf, _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        findings = [f for f in report.findings if f.check_id == "TLS-CV-004"]
        assert findings[0].severity == ChainSeverity.HIGH

    def test_root_self_signed_allowed(self):
        """Root CA (last in chain) is allowed to be self-signed."""
        chain = _clean_chain()
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        assert "TLS-CV-004" not in check_ids(report)

    def test_single_self_signed_cert_no_004(self):
        """Single self-signed cert: chain_len=1, idx=0, NOT idx < chain_len-1 = NOT 0 < 0."""
        leaf = _leaf(subject_cn="dev.local", issuer_cn="dev.local")
        report = TLSChainValidator(reference_time=NOW).validate([leaf])
        assert "TLS-CV-004" not in check_ids(report)

    def test_allow_self_signed_flag_skips_check(self):
        leaf = _leaf(subject_cn="selfsigned.com", issuer_cn="selfsigned.com")
        chain = [leaf, _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW, allow_self_signed=True).validate(chain)
        assert "TLS-CV-004" not in check_ids(report)

    def test_empty_issuer_cn_no_004(self):
        """Empty issuer_cn → is_self_signed = False (bool check on issuer_cn)."""
        leaf = _leaf(subject_cn="example.com", issuer_cn="")
        chain = [leaf, _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        assert "TLS-CV-004" not in check_ids(report)


# ---------------------------------------------------------------------------
# TLS-CV-005: Incomplete chain
# ---------------------------------------------------------------------------

class TestTLSCV005:
    def test_single_non_self_signed_fires(self):
        leaf = _leaf()  # issuer_cn="Intermediate CA" != subject_cn
        report = TLSChainValidator(reference_time=NOW).validate([leaf])
        assert "TLS-CV-005" in check_ids(report)

    def test_single_non_self_signed_severity_high(self):
        leaf = _leaf()
        report = TLSChainValidator(reference_time=NOW).validate([leaf])
        findings = [f for f in report.findings if f.check_id == "TLS-CV-005"]
        assert findings[0].severity == ChainSeverity.HIGH

    def test_complete_chain_no_005(self):
        chain = _clean_chain()
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        assert "TLS-CV-005" not in check_ids(report)

    def test_single_self_signed_no_005(self):
        """Single self-signed cert is complete (it IS the root)."""
        leaf = _leaf(subject_cn="dev.local", issuer_cn="dev.local")
        report = TLSChainValidator(reference_time=NOW).validate([leaf])
        assert "TLS-CV-005" not in check_ids(report)

    def test_empty_chain_no_005(self):
        report = TLSChainValidator(reference_time=NOW).validate([])
        assert "TLS-CV-005" not in check_ids(report)


# ---------------------------------------------------------------------------
# TLS-CV-006: Subject CN not in SANs
# ---------------------------------------------------------------------------

class TestTLSCV006:
    def test_cn_not_in_sans_fires(self):
        leaf = _leaf(
            subject_cn="api.example.com",
            sans=["www.example.com", "example.com"],
        )
        chain = [leaf, _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        assert "TLS-CV-006" in check_ids(report)

    def test_cn_in_sans_exact_no_006(self):
        leaf = _leaf(
            subject_cn="api.example.com",
            sans=["api.example.com", "www.example.com"],
        )
        chain = [leaf, _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        assert "TLS-CV-006" not in check_ids(report)

    def test_wildcard_san_covers_cn(self):
        leaf = _leaf(
            subject_cn="api.example.com",
            sans=["*.example.com"],
        )
        chain = [leaf, _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        assert "TLS-CV-006" not in check_ids(report)

    def test_wildcard_san_does_not_cover_subdomain_of_subdomain(self):
        """*.example.com does NOT cover deep.sub.example.com."""
        leaf = _leaf(
            subject_cn="deep.sub.example.com",
            sans=["*.example.com"],
        )
        chain = [leaf, _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        assert "TLS-CV-006" in check_ids(report)

    def test_no_sans_no_006(self):
        """If no SANs provided, CN check is skipped."""
        leaf = _leaf(subject_cn="example.com", sans=[])
        chain = [leaf, _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        assert "TLS-CV-006" not in check_ids(report)

    def test_cn_not_in_sans_severity_medium(self):
        leaf = _leaf(
            subject_cn="api.example.com",
            sans=["www.example.com"],
        )
        chain = [leaf, _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        findings = [f for f in report.findings if f.check_id == "TLS-CV-006"]
        assert findings[0].severity == ChainSeverity.MEDIUM

    def test_intermediate_cn_not_checked_for_san(self):
        """SAN/CN check only applies to the leaf (idx=0)."""
        chain = _clean_chain()  # intermediate has no SANs
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        # intermediate has no SANs → no TLS-CV-006
        assert "TLS-CV-006" not in check_ids(report)


# ---------------------------------------------------------------------------
# TLS-CV-007: Overly broad wildcard
# ---------------------------------------------------------------------------

class TestTLSCV007:
    def test_wildcard_tld_fires(self):
        """*.com → base=com → 1 part → too broad."""
        leaf = _leaf(
            subject_cn="*.com",
            sans=["*.com"],
        )
        chain = [leaf, _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        assert "TLS-CV-007" in check_ids(report)

    def test_wildcard_single_label_fires(self):
        """*.example → base=example → 1 part → too broad."""
        leaf = _leaf(
            subject_cn="*.example",
            sans=["*.example"],
        )
        chain = [leaf, _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        assert "TLS-CV-007" in check_ids(report)

    def test_proper_wildcard_no_007(self):
        """*.example.com → base=example.com → 2 parts → OK."""
        leaf = _leaf(
            subject_cn="example.com",
            sans=["*.example.com", "example.com"],
        )
        chain = [leaf, _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        assert "TLS-CV-007" not in check_ids(report)

    def test_wildcard_subdomain_ok(self):
        """*.sub.example.com → base=sub.example.com → 3 parts → OK."""
        leaf = _leaf(
            subject_cn="sub.example.com",
            sans=["*.sub.example.com", "sub.example.com"],
        )
        chain = [leaf, _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        assert "TLS-CV-007" not in check_ids(report)

    def test_tls_cv007_severity_medium(self):
        leaf = _leaf(
            subject_cn="*.com",
            sans=["*.com"],
        )
        chain = [leaf, _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        findings = [f for f in report.findings if f.check_id == "TLS-CV-007"]
        assert findings[0].severity == ChainSeverity.MEDIUM

    def test_non_wildcard_no_007(self):
        leaf = _leaf(
            subject_cn="example.com",
            sans=["example.com", "www.example.com"],
        )
        chain = [leaf, _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        assert "TLS-CV-007" not in check_ids(report)


# ---------------------------------------------------------------------------
# TLS-CV-008: Key too short
# ---------------------------------------------------------------------------

class TestTLSCV008:
    @pytest.mark.parametrize("bits", [512, 1024, 1023, 2047])
    def test_rsa_short_key_fires(self, bits):
        chain = [_leaf(key_type="RSA", key_bits=bits), _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        assert "TLS-CV-008" in check_ids(report)

    def test_rsa_2048_ok(self):
        chain = [_leaf(key_type="RSA", key_bits=2048), _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        assert "TLS-CV-008" not in check_ids(report)

    def test_rsa_4096_ok(self):
        chain = [_leaf(key_type="RSA", key_bits=4096), _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        assert "TLS-CV-008" not in check_ids(report)

    @pytest.mark.parametrize("bits", [128, 192, 255])
    def test_ec_short_key_fires(self, bits):
        chain = [_leaf(key_type="EC", key_bits=bits), _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        assert "TLS-CV-008" in check_ids(report)

    def test_ec_256_ok(self):
        chain = [_leaf(key_type="EC", key_bits=256), _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        assert "TLS-CV-008" not in check_ids(report)

    def test_zero_bits_skipped(self):
        chain = [_leaf(key_bits=0), _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        assert "TLS-CV-008" not in check_ids(report)

    def test_key_short_severity_high(self):
        chain = [_leaf(key_type="RSA", key_bits=1024), _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        findings = [f for f in report.findings if f.check_id == "TLS-CV-008"]
        assert findings[0].severity == ChainSeverity.HIGH

    def test_dsa_key_no_false_positive(self):
        """Unknown key type (e.g., DSA) with 2048 bits — no firing."""
        chain = [_leaf(key_type="DSA", key_bits=2048), _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        assert "TLS-CV-008" not in check_ids(report)


# ---------------------------------------------------------------------------
# TLS-CV-009: Long-lived leaf certificate
# ---------------------------------------------------------------------------

class TestTLSCV009:
    def test_leaf_validity_above_398_days_fires(self):
        chain = [
            _leaf(
                not_before=NOW - DAY,
                not_after=NOW + 398 * DAY,
            ),
            _intermediate(),
            _root(),
        ]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        assert "TLS-CV-009" in check_ids(report)

    def test_leaf_validity_398_days_ok(self):
        chain = [
            _leaf(
                not_before=NOW - DAY,
                not_after=NOW + 397 * DAY,
            ),
            _intermediate(),
            _root(),
        ]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        assert "TLS-CV-009" not in check_ids(report)

    def test_leaf_validity_uses_medium_severity(self):
        chain = [
            _leaf(
                not_before=NOW - DAY,
                not_after=NOW + 398 * DAY,
            ),
            _intermediate(),
            _root(),
        ]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        findings = [f for f in report.findings if f.check_id == "TLS-CV-009"]
        assert findings[0].severity == ChainSeverity.MEDIUM

    def test_intermediate_long_lifetime_is_not_leaf_finding(self):
        intermediate = _intermediate()
        intermediate.not_before = NOW - 730 * DAY
        intermediate.not_after = NOW + 3650 * DAY

        chain = [_leaf(), intermediate, _root()]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        assert "TLS-CV-009" not in check_ids(report)


# ---------------------------------------------------------------------------
# Risk score
# ---------------------------------------------------------------------------

class TestRiskScore:
    def test_clean_chain_zero_score(self):
        chain = _clean_chain()
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        assert report.risk_score == 0

    def test_risk_score_nonzero_when_findings(self):
        chain = [_leaf(not_after=NOW - DAY), _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        assert report.risk_score > 0

    def test_risk_score_capped_at_100(self):
        # Multiple issues: expired(50) + weak_algo(40) + short_key(35) = 125 → cap at 100
        chain = [
            _leaf(
                not_after=NOW - DAY,
                sig_algorithm="sha1WithRSAEncryption",
                key_bits=1024,
            ),
            _intermediate(),
            _root(),
        ]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        assert report.risk_score <= 100


# ---------------------------------------------------------------------------
# ChainValidationReport helpers
# ---------------------------------------------------------------------------

class TestChainValidationReport:
    def test_total_findings(self):
        chain = [_leaf(not_after=NOW - DAY), _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        assert report.total_findings == len(report.findings)

    def test_critical_findings_filter(self):
        chain = [_leaf(not_after=NOW - DAY), _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        crit = report.critical_findings
        assert all(f.severity == ChainSeverity.CRITICAL for f in crit)

    def test_high_findings_filter(self):
        chain = [_leaf(key_bits=1024), _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        high = report.high_findings
        assert all(f.severity == ChainSeverity.HIGH for f in high)

    def test_findings_by_check(self):
        chain = [_leaf(key_bits=1024), _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        cv008 = report.findings_by_check("TLS-CV-008")
        assert all(f.check_id == "TLS-CV-008" for f in cv008)

    def test_chain_length(self):
        chain = _clean_chain()
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        assert report.chain_length == 3

    def test_empty_chain(self):
        report = TLSChainValidator(reference_time=NOW).validate([])
        assert report.total_findings == 0
        assert report.chain_length == 0
        assert report.risk_score == 0

    def test_summary_string(self):
        report = TLSChainValidator(reference_time=NOW).validate(_clean_chain())
        s = report.summary()
        assert "Chain Validation" in s
        assert "risk_score" in s

    def test_to_dict_structure(self):
        report = TLSChainValidator(reference_time=NOW).validate(_clean_chain())
        d = report.to_dict()
        assert "total_findings" in d
        assert "risk_score" in d
        assert "chain_length" in d
        assert "critical" in d
        assert "high" in d
        assert "generated_at" in d
        assert "findings" in d
        assert isinstance(d["findings"], list)

    def test_finding_to_dict(self):
        chain = [_leaf(key_bits=1024), _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        d = report.findings[0].to_dict()
        assert "check_id" in d
        assert "severity" in d
        assert "cert_cn" in d
        assert "chain_idx" in d
        assert "title" in d
        assert "detail" in d
        assert "remediation" in d

    def test_finding_summary(self):
        chain = [_leaf(key_bits=1024), _intermediate(), _root()]
        report = TLSChainValidator(reference_time=NOW).validate(chain)
        s = report.findings[0].summary()
        assert "[TLS-CV-" in s
