from __future__ import annotations

from typing import Any
from ipsecguard.models import Finding


class ComplianceEvaluator:
    """Evaluates IPsec session findings against national & international security standards."""

    @staticmethod
    def evaluate(findings: list[Finding], session_summary: dict[str, Any]) -> dict[str, Any]:
        finding_texts = " ".join([f"{f.title} {f.description} {f.raw_value}" for f in findings]).upper()

        has_ikev1 = any("1.0" in str(f.raw_value) or "IKEV1" in f.title.upper() for f in findings)
        has_3des = "3DES" in finding_texts or " DES" in finding_texts
        has_md5 = "MD5" in finding_texts
        has_sha1 = "SHA1" in finding_texts or "SHA-1" in finding_texts
        has_weak_dh = any("DH-2" in str(f.raw_value) or "MODP-1024" in str(f.raw_value) for f in findings)
        pfs_disabled = any(f.category == "forward_secrecy" and (f.raw_value == "off" or "disabled" in f.title.lower()) for f in findings)
        has_ah_only = any("AH-ONLY" in str(f.raw_value).upper() or "NO CONFIDENTIALITY" in f.title.upper() for f in findings)
        has_replay_weakness = any("REPLAY PROTECTION WEAKNESS" in f.title.upper() for f in findings)

        # 1. NIST SP 800-77 Rev. 1 Guidelines
        nist_checks = [
            {
                "id": "NIST-IPSEC-01",
                "name": "IKEv2 Protocol Enforcement",
                "status": "FAIL" if has_ikev1 else "PASS",
                "details": "IKEv2 MUST be used; IKEv1 is deprecated due to protocol vulnerabilities." if has_ikev1 else "IKEv2 protocol correctly negotiated.",
                "standard": "NIST SP 800-77 Rev. 1 Section 3.1"
            },
            {
                "id": "NIST-IPSEC-02",
                "name": "Approved Encryption Algorithm (AES-CBC / AES-GCM)",
                "status": "FAIL" if has_3des else "PASS",
                "details": "Legacy 3DES/DES detected. Minimum AES-128 or AES-256 is required." if has_3des else "Modern AES encryption suite active.",
                "standard": "NIST SP 800-77 Rev. 1 Section 3.3"
            },
            {
                "id": "NIST-IPSEC-03",
                "name": "Secure Hash & Integrity (SHA-2 / SHA-3)",
                "status": "FAIL" if has_md5 else ("WARNING" if has_sha1 else "PASS"),
                "details": "MD5/SHA1 are cryptographically broken/weak; SHA2-256 or better required." if (has_md5 or has_sha1) else "Secure SHA-2 integrity transform verified.",
                "standard": "NIST SP 800-77 Rev. 1 Section 3.4"
            },
            {
                "id": "NIST-IPSEC-04",
                "name": "Diffie-Hellman Group Strength (>= Group 14 / 2048-bit)",
                "status": "FAIL" if has_weak_dh else "PASS",
                "details": "DH Group 2 (1024-bit MODP) is insufficient. Group 14 (2048-bit) or ECDH Group 19/20 required." if has_weak_dh else "Strong DH exchange group verified.",
                "standard": "NIST SP 800-77 Rev. 1 Section 3.2"
            },
            {
                "id": "NIST-IPSEC-05",
                "name": "Perfect Forward Secrecy (PFS)",
                "status": "WARNING" if pfs_disabled else "PASS",
                "details": "PFS is disabled; compromise of long-term key compromises past sessions." if pfs_disabled else "PFS is enabled for Child SA rekeys.",
                "standard": "NIST SP 800-77 Rev. 1 Section 3.5"
            },
            {
                "id": "NIST-IPSEC-06",
                "name": "Anti-Replay Window & Sequence Protection",
                "status": "FAIL" if has_replay_weakness else "PASS",
                "details": "ESP sequence anomalies indicate disabled or flawed anti-replay window." if has_replay_weakness else "ESP sequence numbers are monotonically protected.",
                "standard": "NIST SP 800-77 Rev. 1 Section 3.6 / RFC 4303"
            }
        ]

        # 2. CNSA Suite 1.0 & Suite B (National Security Systems)
        cnsa_checks = [
            {
                "id": "CNSA-01",
                "name": "CNSA Symmetric Encryption (AES-256)",
                "status": "FAIL" if (has_3des or "AES-128" in finding_texts) else "PASS",
                "details": "CNSA requires AES-256 (GCM or CBC mode)." if (has_3des or "AES-128" in finding_texts) else "AES-256 compliant configuration.",
                "standard": "CNSS Policy 15"
            },
            {
                "id": "CNSA-02",
                "name": "CNSA Key Exchange (ECDH P-384 / DH-20)",
                "status": "PASS" if ("DH-20" in finding_texts or "ECP-384" in finding_texts) else "WARNING",
                "details": "CNSA Suite requires ECDH with Curve P-384 (Group 20)." if not ("DH-20" in finding_texts or "ECP-384" in finding_texts) else "Curve P-384 (DH-20) verified.",
                "standard": "CNSS Policy 15"
            },
            {
                "id": "CNSA-03",
                "name": "CNSA Integrity & PRF (SHA-384)",
                "status": "PASS" if "384" in finding_texts else "WARNING",
                "details": "CNSA Suite requires SHA-384." if "384" not in finding_texts else "SHA-384 PRF/Integrity verified.",
                "standard": "CNSS Policy 15"
            }
        ]

        # Calculate compliance scores
        nist_passed = sum(1 for c in nist_checks if c["status"] == "PASS")
        nist_score = round((nist_passed / len(nist_checks)) * 100)

        cnsa_passed = sum(1 for c in cnsa_checks if c["status"] == "PASS")
        cnsa_score = round((cnsa_passed / len(cnsa_checks)) * 100)

        return {
            "nist": {
                "name": "NIST SP 800-77 Rev. 1",
                "score": nist_score,
                "passed": nist_passed,
                "total": len(nist_checks),
                "checks": nist_checks
            },
            "cnsa": {
                "name": "NSA Commercial National Security Algorithm (CNSA)",
                "score": cnsa_score,
                "passed": cnsa_passed,
                "total": len(cnsa_checks),
                "checks": cnsa_checks
            }
        }
