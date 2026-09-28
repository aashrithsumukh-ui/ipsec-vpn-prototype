from __future__ import annotations

import csv
import random
import shutil
import struct
from pathlib import Path

from scapy.all import IP, UDP, Raw, wrpcap
from scapy.layers.inet6 import IPv6 as IPv6Pkt

BASE_DIR = Path(__file__).resolve().parent.parent
SYNTH_DIR = BASE_DIR / "data" / "synthetic"
SAMPLES_DIR = BASE_DIR / "samples"

TRAFFIC_PROFILES = {
    "icmp": {"count": 18, "base": 132, "spread": 12, "iat": 0.08},
    "bulk": {"count": 26, "base": 420, "spread": 40, "iat": 0.02},
    "voip": {"count": 40, "base": 188, "spread": 10, "iat": 0.015},
    "web": {"count": 24, "base": 260, "spread": 35, "iat": 0.05},
    "mixed": {"count": 32, "base": 240, "spread": 90, "iat": 0.035},
    "email": {"count": 20, "base": 350, "spread": 30, "iat": 0.06},
    "video": {"count": 45, "base": 500, "spread": 60, "iat": 0.012},
    "whatsapp": {"count": 22, "base": 200, "spread": 25, "iat": 0.04},
}

CONFIGS = [
    {
        "ike_enc": "3DES",
        "ike_integ": "HMAC-MD5-96",
        "ike_prf": "HMAC-MD5",
        "dh_group": 2,
        "pfs": "off",
        "mode": "transport",
        "esp_cipher": "3des-family",
    },
    {
        "ike_enc": "AES-CBC",
        "ike_integ": "HMAC-SHA1-96",
        "ike_prf": "HMAC-SHA1",
        "dh_group": 14,
        "pfs": "off",
        "mode": "tunnel",
        "esp_cipher": "aes-cbc-family",
    },
    {
        "ike_enc": "AES-GCM-16",
        "ike_integ": "SHA2-256-128",
        "ike_prf": "HMAC-SHA2-256",
        "dh_group": 19,
        "pfs": "on",
        "mode": "tunnel",
        "esp_cipher": "aes-gcm-family",
    },
    {
        "ike_enc": "AES-CBC",
        "ike_integ": "SHA2-256-128",
        "ike_prf": "HMAC-SHA2-256",
        "dh_group": 20,
        "pfs": "on",
        "mode": "transport",
        "esp_cipher": "aes-cbc-family",
    },
    {
        "ike_enc": "AES-GCM-16",
        "ike_integ": "SHA2-384-192",
        "ike_prf": "HMAC-SHA2-384",
        "dh_group": 20,
        "pfs": "off",
        "mode": "tunnel",
        "esp_cipher": "aes-gcm-family",
    },
    {
        "ike_enc": "3DES",
        "ike_integ": "HMAC-SHA1-96",
        "ike_prf": "HMAC-SHA1",
        "dh_group": 14,
        "pfs": "off",
        "mode": "tunnel",
        "esp_cipher": "3des-family",
    },
]

IKEV2_TRANSFORMS = {
    "ike_enc": {"3DES": (1, 3), "AES-CBC": (1, 12), "AES-GCM-16": (1, 18)},
    "ike_prf": {
        "HMAC-MD5": (2, 1),
        "HMAC-SHA1": (2, 2),
        "HMAC-SHA2-256": (2, 5),
        "HMAC-SHA2-384": (2, 6),
    },
    "ike_integ": {
        "HMAC-MD5-96": (3, 1),
        "HMAC-SHA1-96": (3, 2),
        "SHA2-256-128": (3, 12),
        "SHA2-384-192": (3, 13),
    },
}


def build_ikev2_payload(config: dict, initiator: bytes, responder: bytes) -> bytes:
    transforms = [
        IKEV2_TRANSFORMS["ike_enc"][config["ike_enc"]],
        IKEV2_TRANSFORMS["ike_prf"][config["ike_prf"]],
        IKEV2_TRANSFORMS["ike_integ"][config["ike_integ"]],
        (4, config["dh_group"]),
    ]
    transform_blobs = []
    for index, (transform_type, transform_id) in enumerate(transforms):
        next_payload = 3 if index < len(transforms) - 1 else 0
        transform_blobs.append(
            struct.pack("!BBHBBH", next_payload, 0, 8, transform_type, 0, transform_id)
        )
    proposal_body = b"".join(transform_blobs)
    proposal = (
        struct.pack("!BBHBBBB", 0, 0, 8 + len(proposal_body), 1, 1, 0, len(transforms))
        + proposal_body
    )
    sa_payload = struct.pack("!BBH", 0, 0, 4 + len(proposal)) + proposal
    header = (
        initiator
        + responder
        + bytes([33, 0x20, 34, 0x08])
        + struct.pack("!II", 0, 28 + len(sa_payload))
    )
    return header + sa_payload


def build_ikev1_aggressive_payload() -> bytes:
    transform_attrs = (
        struct.pack("!HH", 0x8001, 3)
        + struct.pack("!HH", 0x8002, 1)
        + struct.pack("!HH", 0x8004, 2)
    )
    transform = (
        struct.pack("!BBHBBBB", 0, 0, 8 + len(transform_attrs), 1, 0, 0, 0) + transform_attrs
    )
    proposal = struct.pack("!BBHBBBB", 0, 0, 8 + len(transform), 1, 1, 0, 1) + transform
    sa_payload = struct.pack("!BBH", 0, 0, 4 + 4 + len(proposal)) + struct.pack("!I", 1) + proposal
    header = (
        b"\x10" * 8
        + b"\x20" * 8
        + bytes([1, 0x10, 4, 0x08])
        + struct.pack("!II", 0, 28 + len(sa_payload))
    )
    return header + sa_payload


def esp_payload_size(traffic_label: str, mode: str, cipher_family: str, rng: random.Random) -> int:
    profile = TRAFFIC_PROFILES[traffic_label]
    base = profile["base"] + rng.randint(-profile["spread"], profile["spread"])
    if mode == "tunnel":
        base += 34
    if cipher_family == "3des-family":
        base = ((base + 7) // 8) * 8
    elif cipher_family == "aes-cbc-family":
        base = ((base + 15) // 16) * 16
    else:
        base = ((base + 3) // 4) * 4 + 2
    return max(base, 96)


def build_session_packets(
    config: dict, traffic_label: str, latency_ms: int, jitter_ms: int, loss_pct: int, seed: int
):
    rng = random.Random(seed)
    packets = []
    initiator = b"\xaa" * 8
    responder = b"\xbb" * 8
    ike_request = (
        IP(src="10.0.0.1", dst="10.0.0.2")
        / UDP(sport=500, dport=500)
        / Raw(build_ikev2_payload(config, initiator, b"\x00" * 8))
    )
    ike_response = (
        IP(src="10.0.0.2", dst="10.0.0.1")
        / UDP(sport=500, dport=500)
        / Raw(build_ikev2_payload(config, initiator, responder))
    )
    ike_request.time = 0.0
    ike_response.time = 0.05
    packets.extend([ike_request, ike_response])
    profile = TRAFFIC_PROFILES[traffic_label]
    current_time = 0.1
    for sequence in range(1, profile["count"] + 1):
        if rng.random() < (loss_pct / 100.0):
            current_time += profile["iat"]
            continue
        size = esp_payload_size(traffic_label, config["mode"], config["esp_cipher"], rng)
        spi = 0x1000 if sequence % 2 else 0x2000
        overhead = b"\x00" * max(size - 8, 0)
        src, dst = ("10.0.0.1", "10.0.0.2") if sequence % 2 else ("10.0.0.2", "10.0.0.1")
        packet = IP(src=src, dst=dst, proto=50) / Raw(struct.pack("!II", spi, sequence) + overhead)
        jitter = rng.uniform(-jitter_ms / 1000.0, jitter_ms / 1000.0)
        current_time += profile["iat"] + latency_ms / 1000.0 * 0.01 + jitter
        packet.time = round(max(current_time, 0.1), 6)
        packets.append(packet)
    return packets


def write_dataset() -> None:
    SYNTH_DIR.mkdir(parents=True, exist_ok=True)
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    manifest_path = SYNTH_DIR / "manifest.csv"
    sample_counter = 0
    rows = []
    for config_index, config in enumerate(CONFIGS):
        for traffic_index, traffic_label in enumerate(TRAFFIC_PROFILES):
            latency_ms = 10 + traffic_index * 5 + config_index * 2
            jitter_ms = 1 + (traffic_index % 3) * 2
            loss_pct = (config_index + traffic_index) % 4
            seed = config_index * 100 + traffic_index
            packets = build_session_packets(
                config, traffic_label, latency_ms, jitter_ms, loss_pct, seed
            )
            filename = (
                f"cfg{config_index}_{traffic_label}_{config['mode']}_{config['esp_cipher']}_"
                f"{config['ike_enc'].lower().replace('-', '')}_"
                f"dh{config['dh_group']}_pfs{config['pfs']}.pcap"
            )
            wrpcap(str(SYNTH_DIR / filename), packets)
            rows.append(
                {
                    "file": filename,
                    "ike_version": "2.0",
                    "ike_enc": config["ike_enc"],
                    "ike_integ": config["ike_integ"],
                    "dh_group": config["dh_group"],
                    "pfs": config["pfs"],
                    "mode": config["mode"],
                    "esp_cipher": config["esp_cipher"],
                    "traffic_label": traffic_label,
                    "latency_ms": latency_ms,
                    "jitter_ms": jitter_ms,
                    "loss_pct": loss_pct,
                }
            )
            if sample_counter < 10:
                shutil.copy2(SYNTH_DIR / filename, SAMPLES_DIR / filename)
                sample_counter += 1
    for aggressive_index in range(2):
        filename = f"ikev1_aggressive_{aggressive_index + 1}.pcap"
        packet = (
            IP(src="10.1.0.1", dst="10.1.0.2")
            / UDP(sport=500, dport=500)
            / Raw(build_ikev1_aggressive_payload())
        )
        packet.time = 0.0
        wrpcap(str(SYNTH_DIR / filename), [packet])
        rows.append(
            {
                "file": filename,
                "ike_version": "1.0",
                "ike_enc": "3DES",
                "ike_integ": "MD5",
                "dh_group": 2,
                "pfs": "off",
                "mode": "transport",
                "esp_cipher": "3des-family",
                "traffic_label": "icmp",
                "latency_ms": 0,
                "jitter_ms": 0,
                "loss_pct": 0,
            }
        )
    # Generate IPv6 sessions for dual-stack testing
    for ipv6_index in range(2):
        ipv6_config = CONFIGS[ipv6_index % len(CONFIGS)]
        filename = f"ipv6_session_{ipv6_index + 1}.pcap"
        ipv6_packets = []
        initiator = b"\xcc" * 8
        responder = b"\xdd" * 8
        ike_req = (
            IPv6Pkt(src="fd00::1", dst="fd00::2")
            / UDP(sport=500, dport=500)
            / Raw(build_ikev2_payload(ipv6_config, initiator, b"\x00" * 8))
        )
        ike_req.time = 0.0
        ipv6_packets.append(ike_req)
        rng = random.Random(200 + ipv6_index)
        current_time = 0.1
        for seq in range(1, 16):
            size = esp_payload_size("web", ipv6_config["mode"], ipv6_config["esp_cipher"], rng)
            overhead = b"\x00" * max(size - 8, 0)
            src, dst = ("fd00::1", "fd00::2") if seq % 2 else ("fd00::2", "fd00::1")
            pkt = IPv6Pkt(src=src, dst=dst, nh=50) / Raw(
                struct.pack("!II", 0x3000, seq) + overhead
            )
            current_time += 0.05
            pkt.time = round(current_time, 6)
            ipv6_packets.append(pkt)
        wrpcap(str(SYNTH_DIR / filename), ipv6_packets)
        rows.append(
            {
                "file": filename,
                "ike_version": "2.0",
                "ike_enc": ipv6_config["ike_enc"],
                "ike_integ": ipv6_config["ike_integ"],
                "dh_group": ipv6_config["dh_group"],
                "pfs": ipv6_config["pfs"],
                "mode": ipv6_config["mode"],
                "esp_cipher": ipv6_config["esp_cipher"],
                "traffic_label": "web",
                "latency_ms": 15,
                "jitter_ms": 2,
                "loss_pct": 0,
            }
        )
    with manifest_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    write_dataset()
