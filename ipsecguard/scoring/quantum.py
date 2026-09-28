from __future__ import annotations

from typing import Any
from ipsecguard.models import Finding


class QuantumResilienceAssessor:
    """Assesses Post-Quantum Cryptography (PQC) readiness & CNSA 2.0 quantum vulnerability.
    
    Evaluates exposure to "Harvest Now, Decrypt Later" (HNDL) attacks using Shor's and Grover's algorithms.
    """

    @staticmethod
    def assess(findings: list[Finding]) -> dict[str, Any]:
        finding_texts = " ".join([f"{f.title} {f.description} {f.raw_value}" for f in findings]).upper()

        has_pqc_hybrid = "KYBER" in finding_texts or "ML-KEM" in finding_texts or "RFC 9370" in finding_texts
        has_aes256 = "AES-256" in finding_texts or "AES-GCM-16" in finding_texts or "AESGCM" in finding_texts
        has_aes128 = "AES-128" in finding_texts
        has_3des = "3DES" in finding_texts or " DES" in finding_texts
        has_ecdh = "ECP-256" in finding_texts or "ECP-384" in finding_texts or "DH-19" in finding_texts or "DH-20" in finding_texts
        has_modp = "MODP" in finding_texts or "DH-2" in finding_texts or "DH-14" in finding_texts

        checks = []

        # 1. Key Encapsulation / Exchange (Shor's Algorithm Resistance)
        if has_pqc_hybrid:
            checks.append({
                "component": "Key Exchange (KEM)",
                "algorithm": "Post-Quantum Hybrid (ML-KEM / Kyber)",
                "quantum_status": "PQC_SECURE",
                "risk_level": "LOW",
                "details": "Protected against Shor's algorithm via lattice-based hybrid key exchange (RFC 9370).",
                "cnsa2_compliant": True
            })
        else:
            alg_desc = "Elliptic Curve (ECDH P-256/P-384)" if has_ecdh else ("MODP DH Group" if has_modp else "Classical DH")
            checks.append({
                "component": "Key Exchange (KEM)",
                "algorithm": f"Classical {alg_desc}",
                "quantum_status": "CRITICAL_VULNERABLE",
                "risk_level": "HIGH",
                "details": "Vulnerable to Shor's Algorithm. Adversaries collecting current encrypted traffic can decrypt retrospectively once a cryptanalytically relevant quantum computer (CRQC) is available.",
                "cnsa2_compliant": False
            })

        # 2. Symmetric Encryption (Grover's Algorithm Resistance)
        if has_aes256:
            checks.append({
                "component": "Symmetric Cipher",
                "algorithm": "AES-256 (GCM/CBC)",
                "quantum_status": "QUANTUM_RESISTANT",
                "risk_level": "LOW",
                "details": "Provides 128-bit effective security against Grover's algorithm search; fully CNSA 2.0 compliant.",
                "cnsa2_compliant": True
            })
        elif has_aes128:
            checks.append({
                "component": "Symmetric Cipher",
                "algorithm": "AES-128",
                "quantum_status": "DEGRADED",
                "risk_level": "MEDIUM",
                "details": "Grover's algorithm reduces effective security from 128 bits to 64 bits. AES-256 is required for quantum resistance.",
                "cnsa2_compliant": False
            })
        elif has_3des:
            checks.append({
                "component": "Symmetric Cipher",
                "algorithm": "3DES",
                "quantum_status": "BROKEN",
                "risk_level": "CRITICAL",
                "details": "Effective 56-bit security classically; instantaneously breakable quantumly.",
                "cnsa2_compliant": False
            })

        # 3. Hash & Integrity (Quantum Pre-image Resistance)
        if "384" in finding_texts or "512" in finding_texts:
            checks.append({
                "component": "Hash / PRF",
                "algorithm": "SHA-384 / SHA-512",
                "quantum_status": "QUANTUM_RESISTANT",
                "risk_level": "LOW",
                "details": "Provides minimum 192 bits of collision resistance under quantum attacks.",
                "cnsa2_compliant": True
            })
        else:
            checks.append({
                "component": "Hash / PRF",
                "algorithm": "SHA-256 / SHA-1 / MD5",
                "quantum_status": "PARTIALLY_RESISTANT",
                "risk_level": "MEDIUM",
                "details": "CNSA 2.0 recommends SHA-384 or SHA-512 for quantum resilience.",
                "cnsa2_compliant": False
            })

        # Calculate PQC Readiness Index
        pqc_score = 100 if has_pqc_hybrid else (70 if has_aes256 and ("384" in finding_texts or "512" in finding_texts) else (45 if has_aes256 else 20))

        return {
            "pqc_score": pqc_score,
            "hndl_risk": "HIGH" if not has_pqc_hybrid else "LOW",
            "cnsa2_timeline": "Migrate Key Exchange to ML-KEM (Kyber) by 2030 (NSA CNSA 2.0 Directive)",
            "checks": checks
        }
