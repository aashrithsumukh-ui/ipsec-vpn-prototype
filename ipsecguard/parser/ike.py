from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

from scapy.all import PcapReader, Raw
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6

from ipsecguard.constants import (
    IKEV1_ENCR,
    IKEV1_HASH,
    IKEV2_DH,
    IKEV2_ENCR,
    IKEV2_INTEG,
    IKEV2_PRF,
    RFC_CITATIONS,
)
from ipsecguard.models import Finding

IKEV2_SA_INIT = 34
IKEV1_MAIN_MODE = 2
IKEV1_AGGRESSIVE_MODE = 4
SA_PAYLOAD = 33
PROPOSAL_SUBSTRUCTURE_LAST = 0
TRANSFORM_LAST = 0


def _payload_bytes(packet: Any) -> bytes:
    if UDP in packet:
        payload = bytes(packet[UDP].payload)
        if packet[UDP].dport == 4500 or packet[UDP].sport == 4500:
            if payload.startswith(b"\x00\x00\x00\x00"):
                return payload[4:]
        return payload
    if Raw in packet:
        return bytes(packet[Raw].load)
    return b""


def _decode_version(version_byte: int) -> str:
    return f"{version_byte >> 4}.{version_byte & 0x0F}"


def _severity_for_transform(name: str | None) -> str:
    if not name:
        return "info"
    if any(weak in name for weak in ("DES", "MD5", "SHA1", "MODP-1024")):
        return "high"
    return "low"


def _parse_ikev2_transforms(payload: bytes) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    if len(payload) < 4:
        return results
    next_payload = payload[0]
    payload_length = struct.unpack("!H", payload[2:4])[0]
    body = payload[4:payload_length]
    cursor = 0
    while cursor + 8 <= len(body):
        proposal_length = struct.unpack("!H", body[cursor + 2 : cursor + 4])[0]
        if proposal_length < 8:
            break
        proposal = body[cursor : cursor + proposal_length]
        spi_size = proposal[6]
        num_transforms = proposal[7]
        transform_cursor = 8 + spi_size
        transforms: dict[str, str] = {}
        for _ in range(num_transforms):
            if transform_cursor + 8 > len(proposal):
                break
            transform_length = struct.unpack(
                "!H", proposal[transform_cursor + 2 : transform_cursor + 4]
            )[0]
            if transform_length < 8:
                break
            transform = proposal[transform_cursor : transform_cursor + transform_length]
            transform_type = transform[4]
            transform_id = struct.unpack("!H", transform[6:8])[0]
            transforms.update(_map_ikev2_transform(transform_type, transform_id))
            transform_cursor += transform_length
        if transforms:
            results.append(transforms)
        if proposal[0] == PROPOSAL_SUBSTRUCTURE_LAST:
            break
        cursor += proposal_length
    if next_payload != SA_PAYLOAD:
        return results
    return results


def _map_ikev2_transform(transform_type: int, transform_id: int) -> dict[str, str]:
    if transform_type == 1:
        return {"ike_enc": IKEV2_ENCR.get(transform_id, f"ENCR-{transform_id}")}
    if transform_type == 2:
        return {"ike_prf": IKEV2_PRF.get(transform_id, f"PRF-{transform_id}")}
    if transform_type == 3:
        return {"ike_integ": IKEV2_INTEG.get(transform_id, f"INTEG-{transform_id}")}
    if transform_type == 4:
        return {"dh_group": IKEV2_DH.get(transform_id, f"DH-{transform_id}")}
    return {}


def _parse_ikev1_transforms(payload: bytes) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    if len(payload) < 8:
        return results
    payload_length = struct.unpack("!H", payload[2:4])[0]
    body = payload[4:payload_length]
    if len(body) < 4:
        return results
    cursor = 4
    while cursor + 8 <= len(body):
        proposal_length = struct.unpack("!H", body[cursor + 2 : cursor + 4])[0]
        if proposal_length < 8:
            break
        proposal = body[cursor : cursor + proposal_length]
        num_transforms = proposal[7]
        transform_cursor = 8 + proposal[6]
        attrs: dict[str, str] = {}
        for _ in range(num_transforms):
            if transform_cursor + 8 > len(proposal):
                break
            transform_length = struct.unpack(
                "!H", proposal[transform_cursor + 2 : transform_cursor + 4]
            )[0]
            if transform_length < 8:
                break
            attrs.update(
                _parse_ikev1_attributes(
                    proposal[transform_cursor : transform_cursor + transform_length]
                )
            )
            transform_cursor += transform_length
        if attrs:
            results.append(attrs)
        if proposal[0] == PROPOSAL_SUBSTRUCTURE_LAST:
            break
        cursor += proposal_length
    return results


def _parse_ikev1_attributes(transform: bytes) -> dict[str, str]:
    attrs: dict[str, str] = {}
    cursor = 8
    while cursor + 4 <= len(transform):
        attr_type = struct.unpack("!H", transform[cursor : cursor + 2])[0] & 0x7FFF
        value = struct.unpack("!H", transform[cursor + 2 : cursor + 4])[0]
        if attr_type == 1:
            attrs["ike_enc"] = IKEV1_ENCR.get(value, f"ENCR-{value}")
        elif attr_type == 2:
            attrs["ike_integ"] = IKEV1_HASH.get(value, f"HASH-{value}")
        elif attr_type == 4:
            attrs["dh_group"] = IKEV2_DH.get(value, f"DH-{value}")
        cursor += 4
    return attrs


def _observed_finding(title: str, source_field: str, raw_value: Any, citation: str) -> Finding:
    text = str(raw_value)
    return Finding(
        title=title,
        severity=_severity_for_transform(text),
        category="protocol",
        derivation="observed",
        description=f"Observed {source_field} directly from plaintext IKE fields.",
        source_field=source_field,
        raw_value=raw_value,
        citation=citation,
        likelihood="medium",
        impact="medium",
    )


def extract_findings(pcap_path: str | Path) -> tuple[list[Finding], dict[str, Any]]:
    findings: list[Finding] = []
    summary: dict[str, Any] = {"has_esp": False, "ike_versions": []}
    seen_fields: set[tuple[str, str]] = set()
    ikev2_initiators: dict[bytes, tuple[str, str]] = {}
    with PcapReader(str(pcap_path)) as reader:
        for packet in reader:
            if (IP in packet and packet[IP].proto == 50) or (
                IPv6 in packet and packet[IPv6].nh == 50
            ):
                summary["has_esp"] = True
            src_addr = packet[IP].src if IP in packet else (
                packet[IPv6].src if IPv6 in packet else None
            )
            dst_addr = packet[IP].dst if IP in packet else (
                packet[IPv6].dst if IPv6 in packet else None
            )
            if (
                UDP not in packet
                or packet[UDP].sport not in {500, 4500}
                and packet[UDP].dport not in {500, 4500}
            ):
                continue
            payload = _payload_bytes(packet)
            if len(payload) < 28:
                continue
            next_payload = payload[16]
            version_byte = payload[17]
            exchange_type = payload[18]
            version = _decode_version(version_byte)
            summary["ike_versions"].append(version)
            citation = RFC_CITATIONS["ikev2"] if version.startswith("2") else RFC_CITATIONS["ikev1"]
            if ("ike_version", version) not in seen_fields:
                findings.append(
                    _observed_finding("IKE version observed", "ike_version", version, citation)
                )
                seen_fields.add(("ike_version", version))
            if (
                version.startswith("2")
                and exchange_type == IKEV2_SA_INIT
                and next_payload == SA_PAYLOAD
            ):
                initiator_spi = payload[:8]
                if initiator_spi not in ikev2_initiators:
                    ikev2_initiators[initiator_spi] = (src_addr, dst_addr)
                for proposal in _parse_ikev2_transforms(payload[28:]):
                    for source_field, raw_value in proposal.items():
                        key = (source_field, raw_value)
                        if key in seen_fields:
                            continue
                        findings.append(
                            _observed_finding(
                                f"Observed {source_field.replace('_', ' ')}",
                                source_field,
                                raw_value,
                                RFC_CITATIONS["ikev2"],
                            )
                        )
                        seen_fields.add(key)
                if (
                    packet[UDP].sport == 500
                    and packet[UDP].dport == 500
                    and ikev2_initiators.get(initiator_spi) != (src_addr, dst_addr)
                    and ("ikev2.sa_payload", "responder_sa_init_seen") not in seen_fields
                ):
                    findings.append(
                        Finding(
                            title="Responder proposal observed",
                            severity="info",
                            category="protocol",
                            derivation="observed",
                            description="Responder plaintext SA_INIT proposal was captured.",
                            source_field="ikev2.sa_payload",
                            raw_value="responder_sa_init_seen",
                            citation=RFC_CITATIONS["ikev2"],
                            likelihood="low",
                            impact="low",
                        )
                    )
                    seen_fields.add(("ikev2.sa_payload", "responder_sa_init_seen"))
            elif version.startswith("1"):
                if exchange_type == IKEV1_AGGRESSIVE_MODE:
                    findings.append(
                        Finding(
                            title="IKEv1 aggressive mode observed",
                            severity="high",
                            category="metadata_exposure",
                            derivation="observed",
                            description=(
                                "IKEv1 aggressive mode leaks identity information in cleartext."
                            ),
                            source_field="ikev1.exchange_type",
                            raw_value="aggressive-mode",
                            citation=RFC_CITATIONS["ikev1"],
                            likelihood="high",
                            impact="high",
                        )
                    )
                if next_payload == 1:
                    for proposal in _parse_ikev1_transforms(payload[28:]):
                        for source_field, raw_value in proposal.items():
                            key = (source_field, raw_value)
                            if key in seen_fields:
                                continue
                            findings.append(
                                _observed_finding(
                                    f"Observed {source_field.replace('_', ' ')}",
                                    source_field,
                                    raw_value,
                                    RFC_CITATIONS["ikev1"],
                                )
                            )
                            seen_fields.add(key)
    summary["ike_versions"] = sorted(set(summary["ike_versions"]))
    if summary["has_esp"] and not summary["ike_versions"]:
        findings.append(
            Finding(
                title="IKE handshake not captured",
                severity="medium",
                category="coverage",
                derivation="observed",
                description=(
                    "ESP packets were present, but the capture does not include "
                    "a plaintext IKE handshake."
                ),
                source_field="capture.coverage",
                raw_value="esp_without_ike",
                citation="Capture observation",
                likelihood="medium",
                impact="medium",
            )
        )
    return findings, summary
