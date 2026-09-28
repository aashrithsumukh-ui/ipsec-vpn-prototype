from __future__ import annotations

from collections import defaultdict

from ipsecguard.models import Finding

LIKELIHOOD_ORDER = {"low": 0, "medium": 1, "high": 2}
IMPACT_ORDER = {"low": 0, "medium": 1, "high": 2}
SUBSCORE_BASE = {
    "crypto_strength": 100,
    "key_management": 100,
    "forward_secrecy": 100,
    "metadata_exposure": 100,
    "replay_protection": 100,
}


def _deductions_for_finding(finding: Finding) -> dict[str, int]:
    text = str(finding.raw_value).upper()
    title = finding.title.lower()
    deductions = {key: 0 for key in SUBSCORE_BASE}
    if "3DES" in text or text == "DES":
        deductions["crypto_strength"] += 25
    if "MD5" in text:
        deductions["crypto_strength"] += 20
        deductions["key_management"] += 10
    if "SHA1" in text or "SHA-1" in text:
        deductions["crypto_strength"] += 15
    if text.startswith("DH-2") or "MODP-1024" in text:
        deductions["key_management"] += 20
        deductions["forward_secrecy"] += 10
    if "pfs disabled" in title or text == "off":
        deductions["forward_secrecy"] += 25
    if finding.raw_value == "aggressive-mode" or finding.source_field == "ikev1.exchange_type":
        deductions["metadata_exposure"] += 30
    if "NULL" in text:
        deductions["crypto_strength"] += 35
    if "PRF-1" in text or "HMAC-MD5" in text:
        deductions["key_management"] += 10
    if finding.title == "Traffic anomaly inferred":
        deductions["metadata_exposure"] += int(float(finding.raw_value) * 20)
    if finding.title == "Replay protection weakness inferred":
        deductions["replay_protection"] += 25
    if finding.title == "ESP sequence anomaly inferred":
        deductions["replay_protection"] += 15
    if finding.source_field == "ike.sa_lifetime":
        try:
            lifetime = float(finding.raw_value)
            if lifetime > 86400:
                deductions["key_management"] += 15
        except (ValueError, TypeError):
            pass
    return deductions


def build_threat_matrix(findings: list[Finding]) -> dict[str, list[dict]]:
    matrix: dict[str, list[dict]] = defaultdict(list)
    for finding in findings:
        key = f"{finding.likelihood}_{finding.impact}"
        matrix[key].append(
            {
                "title": finding.title,
                "severity": finding.severity,
                "derivation": finding.derivation,
                "confidence": finding.confidence,
            }
        )
    return dict(matrix)


def score_findings(findings: list[Finding]) -> tuple[int, dict[str, int], dict[str, list[dict]]]:
    deductions = {key: 0 for key in SUBSCORE_BASE}
    for finding in findings:
        for key, value in _deductions_for_finding(finding).items():
            deductions[key] += value
    subscores = {key: max(0, SUBSCORE_BASE[key] - deductions[key]) for key in SUBSCORE_BASE}
    score = round(sum(subscores.values()) / len(subscores))
    return score, subscores, build_threat_matrix(findings)
