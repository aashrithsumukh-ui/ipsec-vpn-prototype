"""Active IKE MITM Cipher Downgrade Attack Engine.

Demonstrates Logjam / Sweet32 downgrade mechanics by modifying raw IKE_SA_INIT
transform proposals, stripping modern AEAD ciphers (AES-GCM) and robust DH groups (19/20),
and forcing fallback to legacy 3DES-CBC and MODP-1024 (Group 2).
"""
from __future__ import annotations
import os
from typing import Dict, Any, Tuple, Optional


def simulate_downgrade_attack(
    initial_cipher: str = "AES-256-GCM",
    initial_dh: int = 19,
    downgrade_to_cipher: str = "3DES-CBC",
    downgrade_to_dh: int = 2
) -> Dict[str, Any]:
    """Simulates a live on-path man-in-the-middle cipher suite downgrade."""
    baseline_observed = {
        "enc_algo": initial_cipher.lower(),
        "integrity": "none" if "gcm" in initial_cipher.lower() else "sha256",
        "dh_group": initial_dh,
        "ike_version": 2
    }
    
    attacked_observed = {
        "enc_algo": downgrade_to_cipher.lower(),
        "integrity": "md5" if "3des" in downgrade_to_cipher.lower() else "sha1",
        "dh_group": downgrade_to_dh,
        "ike_version": 2
    }

    tamper_details = [
        f"Stripped modern SA transform proposal: {initial_cipher} (Transform Type 1, ID 20)",
        f"Stripped strong DH group KE payload: Group {initial_dh} (ECP-256/384)",
        f"Injected legacy proposal: {downgrade_to_cipher} (64-bit block Sweet32 vulnerability)",
        f"Injected weak prime MODP group: Group {downgrade_to_dh} (1024-bit Logjam vulnerability)"
    ]

    return {
        "attack_type": "IKE_SA_INIT_PROPOSAL_DOWNGRADE",
        "mitm_technique": "T1557 / T1588.006 (Adversary-in-the-Middle)",
        "baseline_parameters": baseline_observed,
        "tampered_parameters": attacked_observed,
        "tamper_log": tamper_details,
        "vulnerabilities_introduced": [
            {
                "cve": "CVE-2016-2183",
                "title": "Sweet32 Birthday Attack on 64-bit Block Ciphers",
                "risk": "HIGH",
                "details": "3DES-CBC allows collision recovery after $2^{32}$ plaintext blocks."
            },
            {
                "cve": "CVE-2015-4000",
                "title": "Logjam Ephemeral Diffie-Hellman Precomputation",
                "risk": "HIGH",
                "details": "1024-bit MODP primes are susceptible to nation-state discrete logarithm precomputation."
            }
        ]
    }
