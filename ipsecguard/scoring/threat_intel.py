from __future__ import annotations

from typing import Any
from ipsecguard.models import Finding


class MitreThreatIntel:
    """Enriches IPsec protocol findings with MITRE ATT&CK techniques, CVEs, and attack mechanics."""

    # Threat database mapping keywords and finding categories to CVEs, MITRE ATT&CK, and impact details
    INTEL_DB: list[dict[str, Any]] = [
        {
            "match_terms": ["3DES", " DES"],
            "cve": "CVE-2016-2183",
            "cve_title": "Sweet32 Birthday Attack",
            "cvss": 7.5,
            "mitre_id": "T1588.006",
            "mitre_technique": "Obtain Capabilities: Digital Certificates & Cryptographic Flaws",
            "tactic": "Credential Access / Defense Evasion",
            "attack_vector": "Adversary captures ~32GB of 64-bit block cipher traffic (3DES) to exploit collision probability, recovering plaintext session cookies and sensitive data.",
            "threat_actor_relevance": "State-sponsored APTs conducting long-term bulk passive interception."
        },
        {
            "match_terms": ["DH-2", "MODP-1024"],
            "cve": "CVE-2015-4000",
            "cve_title": "Logjam Discrete Logarithm Factorization Attack",
            "cvss": 6.8,
            "mitre_id": "T1557",
            "mitre_technique": "Adversary-in-the-Middle (AiTM)",
            "tactic": "Credential Access / Collection",
            "attack_vector": "Pre-computation of Number Field Sieve (NFS) tables against common 1024-bit primes enables real-time discrete logarithm computation to recover session keys.",
            "threat_actor_relevance": "Nation-state SIGINT agencies with specialized high-performance computing resources."
        },
        {
            "match_terms": ["MD5", "HMAC-MD5"],
            "cve": "CVE-2004-2761",
            "cve_title": "MD5 Hash Collision & Forgery",
            "cvss": 7.5,
            "mitre_id": "T1565.002",
            "mitre_technique": "Data Manipulation: Transmitted Data Manipulation",
            "tactic": "Impact",
            "attack_vector": "Differential cryptanalysis generates MD5 collisions in seconds, allowing packet forgery and tampering with authenticated handshakes.",
            "threat_actor_relevance": "Network-positioned adversaries attempting integrity bypass and payload manipulation."
        },
        {
            "match_terms": ["SHA1", "SHA-1", "HMAC-SHA1"],
            "cve": "CVE-2017-15999",
            "cve_title": "SHAttered Cryptographic Hash Collision",
            "cvss": 5.9,
            "mitre_id": "T1565.002",
            "mitre_technique": "Data Manipulation: Transmitted Data Manipulation",
            "tactic": "Impact",
            "attack_vector": "Identical-prefix collision attacks on SHA-1 allow rogue credential and certificate forging.",
            "threat_actor_relevance": "Resource-backed threat actors targeting authentication integrity."
        },
        {
            "match_terms": ["AGGRESSIVE-MODE", "IKEV1 AGGRESSIVE"],
            "cve": "CVE-2002-1623",
            "cve_title": "IKEv1 Aggressive Mode Cleartext PSK Hash Exposure",
            "cvss": 7.5,
            "mitre_id": "T1040",
            "mitre_technique": "Network Sniffing & Offline PSK Cracking",
            "tactic": "Credential Access",
            "attack_vector": "IKEv1 Aggressive Mode transmits the identity (ID) and pre-shared key (PSK) authentication hash unencrypted in packet 2/3, permitting offline dictionary and rainbow table cracking.",
            "threat_actor_relevance": "Opportunistic and targeted threat actors intercepting perimeter VPN handshakes."
        },
        {
            "match_terms": ["REPLAY PROTECTION WEAKNESS", "NON-MONOTONIC"],
            "cve": "CWE-294",
            "cve_title": "Authentication Bypass by Capture-replay",
            "cvss": 6.5,
            "mitre_id": "T1557.002",
            "mitre_technique": "Adversary-in-the-Middle: ARP/IP Spoofing & Replay",
            "tactic": "Defense Evasion / Lateral Movement",
            "attack_vector": "Captured ESP ciphertext packets can be re-injected into the network stream to cause duplicate state updates or denial-of-service without key discovery.",
            "threat_actor_relevance": "Internal network adversaries and LAN-level threat actors."
        },
        {
            "match_terms": ["AH-ONLY", "NO CONFIDENTIALITY"],
            "cve": "CWE-319",
            "cve_title": "Cleartext Transmission of Sensitive Information",
            "cvss": 7.5,
            "mitre_id": "T1040",
            "mitre_technique": "Network Sniffing & Passive Wiretapping",
            "tactic": "Credential Access / Collection",
            "attack_vector": "Authentication Header without ESP provides ZERO data confidentiality. All user data, credentials, and protocols are visible in plaintext over the wire.",
            "threat_actor_relevance": "Any observer on the transit path (ISPs, AS-level interceptors, eavesdroppers)."
        }
    ]

    @classmethod
    def enrich_findings(cls, findings: list[Finding]) -> list[dict[str, Any]]:
        """Enriches findings with corresponding threat intelligence entries."""
        threat_cards = []
        seen_cves = set()

        for finding in findings:
            finding_str = f"{finding.title} {finding.description} {finding.raw_value}".upper()
            for entry in cls.INTEL_DB:
                if entry["cve"] in seen_cves:
                    continue
                if any(term in finding_str for term in entry["match_terms"]):
                    seen_cves.add(entry["cve"])
                    threat_cards.append({
                        **entry,
                        "source_finding": finding.title,
                        "severity": finding.severity
                    })

        return threat_cards
