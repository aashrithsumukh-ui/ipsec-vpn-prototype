from __future__ import annotations

import struct
from pathlib import Path

from scapy.all import PcapReader
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6

from ipsecguard.models import Finding


def _get_ip_layer(packet):  # noqa: ANN001
    """Return the IP or IPv6 layer from a packet."""
    if IP in packet:
        return packet[IP], packet[IP].proto
    if IPv6 in packet:
        return packet[IPv6], packet[IPv6].nh
    return None, None


def extract_ah_findings(pcap_path: str | Path) -> list[Finding]:
    """Extract findings from AH (Authentication Header, IP protocol 51) packets.

    AH provides integrity and authentication but NOT confidentiality.
    Its presence without ESP indicates traffic is authenticated but not encrypted.
    """
    findings: list[Finding] = []
    ah_count = 0
    has_esp = False
    seen_spis: set[int] = set()

    with PcapReader(str(pcap_path)) as reader:
        for packet in reader:
            ip_layer, proto = _get_ip_layer(packet)
            if ip_layer is None:
                continue

            if proto == 50:  # ESP
                has_esp = True

            if proto == 51:  # AH
                ah_count += 1
                payload = bytes(ip_layer.payload)
                if len(payload) >= 12:
                    # AH header: Next Header (1), Payload Len (1),
                    # Reserved (2), SPI (4), Seq (4)
                    spi = struct.unpack("!I", payload[4:8])[0]
                    seen_spis.add(spi)

    if ah_count > 0:
        findings.append(
            Finding(
                title="AH protocol detected",
                severity="medium",
                category="protocol",
                derivation="observed",
                description=(
                    f"Authentication Header (AH) protocol detected with {ah_count} "
                    f"packets across {len(seen_spis)} SPI(s). AH provides integrity "
                    "and authentication but does NOT provide confidentiality."
                ),
                source_field="ip.proto",
                raw_value="AH (protocol 51)",
                citation="RFC 4302",
                likelihood="medium",
                impact="medium",
            )
        )

        if not has_esp:
            findings.append(
                Finding(
                    title="AH without ESP — no confidentiality",
                    severity="high",
                    category="crypto_strength",
                    derivation="observed",
                    description=(
                        "Traffic uses AH for authentication but ESP is absent. "
                        "This means packets are authenticated but NOT encrypted — "
                        "payload contents are visible to any network observer."
                    ),
                    source_field="ipsec.protocol_combination",
                    raw_value="AH-only (no ESP)",
                    citation="RFC 4302 / NIST SP 800-77 Rev. 1",
                    likelihood="high",
                    impact="high",
                )
            )

    return findings
