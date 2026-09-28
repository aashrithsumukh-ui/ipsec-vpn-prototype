"""Automatic IPsec Tunnel vs Transport Mode Detection Engine.

Determines whether an analyzed IPsec session uses Tunnel Mode or Transport Mode
using evidence from PCAP packet structures, IKE notification payloads (e.g. USE_TRANSPORT_MODE),
header layering (IP-in-IP), and flow metadata.
"""
from __future__ import annotations
import os
import struct
from typing import Any, Dict, List, Optional, Union

OBSERVED = "observed"
INFERRED = "inferred"

NOTIFY_USE_TRANSPORT_MODE = 16391  # 0x4007


def detect_ipsec_mode(
    pcap_source: Union[str, Dict[str, Any], List[Any]],
    fallback_hint: Optional[str] = None
) -> Dict[str, Any]:
    evidence = []
    supporting_fields = {}
    limitations = []

    if isinstance(pcap_source, dict):
        return _detect_from_session_dict(pcap_source, fallback_hint)

    if isinstance(pcap_source, str) and not os.path.exists(pcap_source):
        if fallback_hint in ("tunnel", "transport"):
            return {
                "detected_mode": fallback_hint,
                "confidence": 0.50,
                "derivation": "hint",
                "evidence": [f"PCAP file not accessible; relied on mode hint: '{fallback_hint}'."],
                "supporting_fields": {"hint_used": True},
                "limitations": ["PCAP file not available for direct packet inspection."]
            }
        return {
            "detected_mode": "unknown",
            "confidence": 0.0,
            "derivation": "unknown",
            "evidence": ["PCAP file not found and no mode hint provided."],
            "supporting_fields": {},
            "limitations": ["File inaccessible; unable to inspect headers."]
        }

    try:
        if isinstance(pcap_source, str):
            from scapy.all import rdpcap
            pkts = rdpcap(pcap_source)
        else:
            pkts = pcap_source
    except Exception as e:
        if fallback_hint in ("tunnel", "transport"):
            return {
                "detected_mode": fallback_hint,
                "confidence": 0.50,
                "derivation": "hint",
                "evidence": [f"PCAP parsing error ({e}); using fallback hint '{fallback_hint}'."],
                "supporting_fields": {"error": str(e)},
                "limitations": ["Failed reading raw packets from capture."]
            }
        return {
            "detected_mode": "unknown",
            "confidence": 0.0,
            "derivation": "unknown",
            "evidence": [f"Could not parse capture packets: {e}"],
            "supporting_fields": {},
            "limitations": ["Corrupted or unreadable PCAP structure."]
        }

    if not pkts or len(pkts) == 0:
        return {
            "detected_mode": fallback_hint if fallback_hint else "unknown",
            "confidence": 0.5 if fallback_hint else 0.0,
            "derivation": "hint" if fallback_hint else "unknown",
            "evidence": ["Empty PCAP capture (0 packets)."],
            "supporting_fields": {"packet_count": 0},
            "limitations": ["Capture contains zero packets."]
        }

    from scapy.all import IP, IPv6, UDP
    from scapy.layers.ipsec import ESP

    nested_ip_count = 0
    esp_packet_count = 0
    ike_packet_count = 0
    use_transport_notify_found = False
    ikev1_transport_found = False
    ikev1_tunnel_found = False
    outer_ips = set()

    for p in pkts:
        if p.haslayer(IP):
            outer_ip = p[IP]
            outer_ips.add(f"{outer_ip.src}->{outer_ip.dst}")
            if outer_ip.payload and outer_ip.payload.haslayer(IP):
                nested_ip_count += 1
            if outer_ip.proto == 50 or p.haslayer(ESP):
                esp_packet_count += 1

        elif p.haslayer(IPv6):
            outer_ip = p[IPv6]
            outer_ips.add(f"{outer_ip.src}->{outer_ip.dst}")
            if outer_ip.payload and (outer_ip.payload.haslayer(IP) or outer_ip.payload.haslayer(IPv6)):
                nested_ip_count += 1
            if outer_ip.nh == 50 or p.haslayer(ESP):
                esp_packet_count += 1

        if p.haslayer(UDP) and (p[UDP].dport in (500, 4500) or p[UDP].sport in (500, 4500)):
            ike_packet_count += 1
            payload = bytes(p[UDP].payload)
            if payload.startswith(b"\x00\x00\x00\x00"):
                payload = payload[4:]

            if b"\x40\x07" in payload:
                use_transport_notify_found = True
            if b"\x80\x04\x00\x02" in payload:
                ikev1_transport_found = True
            elif b"\x80\x04\x00\x01" in payload:
                ikev1_tunnel_found = True

    supporting_fields = {
        "total_packets": len(pkts),
        "esp_packets": esp_packet_count,
        "ike_packets": ike_packet_count,
        "nested_ip_packets": nested_ip_count,
        "unique_endpoints": list(outer_ips)[:4],
        "use_transport_notify": use_transport_notify_found,
        "ikev1_mode_attr": "transport" if ikev1_transport_found else ("tunnel" if ikev1_tunnel_found else None)
    }

    if nested_ip_count > 0:
        evidence.append(f"Observed nested IP encapsulation in {nested_ip_count} packet(s) (direct IP-in-IP tunnel).")
        return {
            "detected_mode": "tunnel",
            "confidence": 0.98,
            "derivation": OBSERVED,
            "evidence": evidence,
            "supporting_fields": supporting_fields,
            "limitations": []
        }

    if use_transport_notify_found:
        evidence.append("Observed IKEv2 USE_TRANSPORT_MODE Notification (Type 16391 / 0x4007) in handshake exchange.")
        return {
            "detected_mode": "transport",
            "confidence": 0.95,
            "derivation": OBSERVED,
            "evidence": evidence,
            "supporting_fields": supporting_fields,
            "limitations": []
        }

    if ikev1_transport_found:
        evidence.append("Observed IKEv1 Quick Mode SA Encapsulation Mode attribute = 2 (Transport Mode).")
        return {
            "detected_mode": "transport",
            "confidence": 0.95,
            "derivation": OBSERVED,
            "evidence": evidence,
            "supporting_fields": supporting_fields,
            "limitations": []
        }

    if ikev1_tunnel_found:
        evidence.append("Observed IKEv1 Quick Mode SA Encapsulation Mode attribute = 1 (Tunnel Mode).")
        return {
            "detected_mode": "tunnel",
            "confidence": 0.95,
            "derivation": OBSERVED,
            "evidence": evidence,
            "supporting_fields": supporting_fields,
            "limitations": []
        }

    if esp_packet_count > 0 or ike_packet_count > 0:
        if fallback_hint in ("tunnel", "transport"):
            detected = fallback_hint
            confidence = 0.85 if fallback_hint == "tunnel" else 0.75
            derivation = INFERRED
            evidence.append(f"Standard IPsec encapsulation detected with {esp_packet_count} ESP packet(s). No Transport notify present — evaluated as '{detected}'.")
        else:
            detected = "tunnel"
            confidence = 0.80
            derivation = INFERRED
            evidence.append(f"Standard ESP encapsulation active ({esp_packet_count} packets). RFC 7296 default mode is Tunnel Mode.")

        limitations.append("Inner IP header is encrypted within ESP payload; mode confirmed via protocol defaults and encapsulation characteristics.")

        return {
            "detected_mode": detected,
            "confidence": confidence,
            "derivation": derivation,
            "evidence": evidence,
            "supporting_fields": supporting_fields,
            "limitations": limitations
        }

    if fallback_hint in ("tunnel", "transport"):
        return {
            "detected_mode": fallback_hint,
            "confidence": 0.60,
            "derivation": "hint",
            "evidence": [f"Insufficient ESP/IKE packets in capture; used fallback hint '{fallback_hint}'."],
            "supporting_fields": supporting_fields,
            "limitations": ["Capture contained no identifiable ESP or IKE payload structures."]
        }

    return {
        "detected_mode": "unknown",
        "confidence": 0.0,
        "derivation": "unknown",
        "evidence": ["No ESP or IKE protocol packets identified to establish IPsec mode."],
        "supporting_fields": supporting_fields,
        "limitations": ["Packet capture does not contain IPsec traffic."]
    }


def _detect_from_session_dict(session: Dict[str, Any], fallback_hint: Optional[str]) -> Dict[str, Any]:
    inferred = session.get("inferred", {})
    observed = session.get("observed", {})
    feats = session.get("flow_features", {})

    mode_val = inferred.get("mode") or observed.get("mode") or fallback_hint
    if mode_val in ("tunnel", "transport"):
        conf = float(inferred.get("mode_conf", 0.75))
        return {
            "detected_mode": mode_val,
            "confidence": conf,
            "derivation": INFERRED if "mode" in inferred else "hint",
            "evidence": [f"Mode established from session flow characteristics ({mode_val}, confidence: {conf*100:.0f}%)."],
            "supporting_fields": {"mode": mode_val, "pkt_size_mean": feats.get("pkt_size_mean")},
            "limitations": ["Inner IP header is encrypted inside ESP; mode is derived from flow heuristics."]
        }

    return {
        "detected_mode": "unknown",
        "confidence": 0.0,
        "derivation": "unknown",
        "evidence": ["No mode information available in session dictionary."],
        "supporting_fields": {},
        "limitations": ["Missing flow features or mode metadata."]
    }
