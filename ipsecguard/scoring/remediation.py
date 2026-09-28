from __future__ import annotations

from ipsecguard.models import Finding


class RemediationAdvisor:
    """Generates vendor-specific remediation steps and configuration templates for IPsec hardening."""

    @staticmethod
    def generate_recommendations(findings: list[Finding]) -> list[dict[str, str]]:
        recs = []
        finding_texts = " ".join([f"{f.title} {f.description} {f.raw_value}" for f in findings]).upper()

        if "3DES" in finding_texts or " DES" in finding_texts:
            recs.append({
                "title": "Upgrade Legacy 3DES/DES Cipher to AES-256-GCM",
                "severity": "high",
                "issue": "3DES is susceptible to collision attacks (Sweet32) and lacks hardware acceleration.",
                "solution": "Configure AES-256-GCM (Transform ID 18/20) for both IKE SA and Child ESP SAs.",
                "strongswan_snippet": "esp_proposals = aes256gcm16-sha384-ecp384\nproposals = aes256gcm16-sha384-ecp384",
                "cisco_snippet": "crypto ikev2 proposal IKEV2-SECURE\n encryption aes-gcm-256\n prf sha384\n group 20\n!\ncrypto ipsec transform-set ESP-SECURE esp-gcm 256\n mode tunnel"
            })

        if "MD5" in finding_texts or "SHA1" in finding_texts or "SHA-1" in finding_texts:
            recs.append({
                "title": "Replace Deprecated Hash Algorithms (MD5/SHA-1) with SHA-256/SHA-384",
                "severity": "high",
                "issue": "MD5 and SHA-1 suffer from theoretical and practical collision vulnerabilities.",
                "solution": "Migrate integrity transforms to HMAC-SHA2-256-128 or HMAC-SHA2-384-192.",
                "strongswan_snippet": "proposals = aes256-sha384-modp2048\nesp_proposals = aes256-sha384",
                "cisco_snippet": "crypto ipsec transform-set ESP-TRANS esp-aes 256 esp-sha384-hmac"
            })

        if any("DH-2" in str(f.raw_value) or "MODP-1024" in str(f.raw_value) for f in findings):
            recs.append({
                "title": "Upgrade Diffie-Hellman Group to Group 14 (2048-bit) or ECDH Group 19/20",
                "severity": "high",
                "issue": "MODP-1024 (DH Group 2) can be cracked by well-resourced adversaries (Logjam attack class).",
                "solution": "Configure minimum DH Group 14 (MODP 2048-bit) or ECDH Curve 25519 / NIST P-384 (Group 19/20).",
                "strongswan_snippet": "proposals = aes256-sha256-modp2048,aes256gcm16-sha384-ecp384",
                "cisco_snippet": "crypto ikev2 policy 10\n proposal IKEV2-SECURE\n group 19 20 14"
            })

        if any(f.category == "forward_secrecy" and (f.raw_value == "off" or "disabled" in f.title.lower()) for f in findings):
            recs.append({
                "title": "Enable Perfect Forward Secrecy (PFS) for Child SA",
                "severity": "medium",
                "issue": "Without PFS, compromising the long-term private key exposes past and future encrypted traffic.",
                "solution": "Enable PFS so each child SA renegotiation performs a fresh Diffie-Hellman exchange.",
                "strongswan_snippet": "# In swanctl.conf children section:\nchildren {\n  net-secure {\n    esp_proposals = aes256gcm16-modp2048\n    # DH group in esp_proposals enforces PFS\n  }\n}",
                "cisco_snippet": "crypto map VPN-MAP 10 ipsec-isakmp\n set pfs group14"
            })

        if any("1.0" in str(f.raw_value) or "IKEV1" in f.title.upper() for f in findings):
            recs.append({
                "title": "Migrate IKEv1 to IKEv2 Protocol",
                "severity": "high",
                "issue": "IKEv1 lacks native NAT traversal support, has complex 2-phase handshakes, and leaks identity in aggressive mode.",
                "solution": "Configure IKEv2 as the sole supported key exchange version.",
                "strongswan_snippet": "connections {\n  vpn-tunnel {\n    version = 2\n  }\n}",
                "cisco_snippet": "crypto ikev2 enable OUTSIDE"
            })

        if any("AH-ONLY" in str(f.raw_value).upper() or "NO CONFIDENTIALITY" in f.title.upper() for f in findings):
            recs.append({
                "title": "Enforce Encapsulating Security Payload (ESP) for Data Encryption",
                "severity": "high",
                "issue": "Authentication Header (AH) only provides integrity, leaving all payload data unencrypted in cleartext.",
                "solution": "Deploy ESP in tunnel or transport mode to ensure confidentiality.",
                "strongswan_snippet": "children {\n  net-tunnel {\n    mode = tunnel\n    esp_proposals = aes256gcm16\n  }\n}",
                "cisco_snippet": "crypto ipsec transform-set ESP-SET esp-aes 256 esp-sha256-hmac"
            })

        return recs
