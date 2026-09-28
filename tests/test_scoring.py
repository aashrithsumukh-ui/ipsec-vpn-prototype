from ipsecguard.models import Finding
from ipsecguard.scoring.rules import score_findings


def test_scoring_applies_expected_deductions():
    findings = [
        Finding("Observed ike enc", "high", "crypto_strength", "observed", "", raw_value="3DES"),
        Finding(
            "Observed integ", "high", "crypto_strength", "observed", "", raw_value="HMAC-MD5-96"
        ),
        Finding(
            "IKEv1 aggressive mode observed",
            "high",
            "metadata_exposure",
            "observed",
            "",
            raw_value="aggressive-mode",
        ),
    ]
    score, subscores, _ = score_findings(findings)
    assert score < 100
    assert subscores["crypto_strength"] <= 55
    assert subscores["metadata_exposure"] <= 70


def test_scoring_handles_pfs_null_prf_and_anomaly_paths():
    findings = [
        Finding(
            "PFS disabled",
            "medium",
            "forward_secrecy",
            "observed",
            "",
            raw_value="off",
        ),
        Finding("Null cipher", "high", "crypto_strength", "observed", "", raw_value="NULL"),
        Finding("Weak PRF", "medium", "key_management", "observed", "", raw_value="HMAC-MD5"),
        Finding(
            "Traffic anomaly inferred",
            "high",
            "metadata_exposure",
            "inferred",
            "",
            raw_value=0.9,
        ),
    ]
    _, subscores, _ = score_findings(findings)
    assert subscores["forward_secrecy"] <= 75
    assert subscores["crypto_strength"] <= 45
    assert subscores["key_management"] <= 90
    assert subscores["metadata_exposure"] <= 82
