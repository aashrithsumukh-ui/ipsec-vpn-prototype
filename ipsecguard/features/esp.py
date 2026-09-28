from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from statistics import mean, pstdev

import pandas as pd
from scapy.all import PcapReader
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6


def _percentile(values: list[float], quantile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    index = (len(ordered) - 1) * quantile
    lower = int(index)
    upper = min(lower + 1, len(ordered) - 1)
    weight = index - lower
    return float(ordered[lower] * (1 - weight) + ordered[upper] * weight)


def extract_flow_features(pcap_path: str | Path) -> pd.DataFrame:
    sessions: dict[tuple[str, str], list[dict[str, float | int | str]]] = defaultdict(list)
    with PcapReader(str(pcap_path)) as reader:
        for packet in reader:
            if IP in packet and packet[IP].proto == 50:
                payload = bytes(packet[IP].payload)
                src, dst = packet[IP].src, packet[IP].dst
            elif IPv6 in packet and packet[IPv6].nh == 50:
                payload = bytes(packet[IPv6].payload)
                src, dst = packet[IPv6].src, packet[IPv6].dst
            else:
                continue
            if len(payload) < 8:
                continue
            spi = int.from_bytes(payload[:4], "big")
            seq_num = int.from_bytes(payload[4:8], "big")
            peers = tuple(sorted((src, dst)))
            sessions[peers].append(
                {
                    "timestamp": float(packet.time),
                    "size": float(len(payload) + 20),
                    "src": src,
                    "dst": dst,
                    "spi": spi,
                    "seq": seq_num,
                }
            )
    rows: list[dict[str, float | str | int]] = []
    for peers, packets in sessions.items():
        all_packets = sorted(packets, key=lambda entry: entry["timestamp"])
        sizes = [entry["size"] for entry in all_packets]
        timestamps = [entry["timestamp"] for entry in all_packets]
        iats = [
            max(timestamps[idx] - timestamps[idx - 1], 0.0) for idx in range(1, len(timestamps))
        ]
        direction_totals: dict[str, float] = defaultdict(float)
        for entry in all_packets:
            direction_totals[str(entry["src"])] += float(entry["size"])
        byte_totals = sorted(direction_totals.values(), reverse=True)
        larger_direction = byte_totals[0] if byte_totals else 0.0
        smaller_direction = byte_totals[1] if len(byte_totals) > 1 else 0.0
        size_mean = mean(sizes) if sizes else 0.0
        size_std = pstdev(sizes) if len(sizes) > 1 else 0.0
        iat_mean = mean(iats) if iats else 0.0
        iat_std = pstdev(iats) if len(iats) > 1 else 0.0
        bursts = 1
        burst_lengths = []
        current_burst = 1
        for iat in iats:
            if iat <= max(iat_mean * 1.5, 0.03):
                current_burst += 1
            else:
                burst_lengths.append(current_burst)
                current_burst = 1
                bursts += 1
        burst_lengths.append(current_burst)
        size_mod_4 = mean([1.0 if size % 4 == 0 else 0.0 for size in sizes]) if sizes else 0.0
        size_mod_8 = mean([1.0 if size % 8 == 0 else 0.0 for size in sizes]) if sizes else 0.0
        size_mod_16 = mean([1.0 if size % 16 == 0 else 0.0 for size in sizes]) if sizes else 0.0
        overhead_consistency = 1.0 - min(size_std / max(size_mean, 1.0), 1.0)
        # Replay protection features from ESP sequence numbers
        seq_numbers = [int(entry["seq"]) for entry in all_packets]
        monotonic_pairs = sum(
            1 for i in range(1, len(seq_numbers)) if seq_numbers[i] > seq_numbers[i - 1]
        )
        seq_monotonic = monotonic_pairs / max(len(seq_numbers) - 1, 1)
        seq_gap_count = sum(
            1 for i in range(1, len(seq_numbers))
            if seq_numbers[i] - seq_numbers[i - 1] > 1
        )
        rows.append(
            {
                "spi": int(all_packets[0]["spi"]) if all_packets else 0,
                "src": peers[0],
                "dst": peers[1],
                "packet_count": len(sizes),
                "duration": max(timestamps[-1] - timestamps[0], 0.0)
                if len(timestamps) > 1
                else 0.0,
                "size_mean": size_mean,
                "size_std": size_std,
                "size_p10": _percentile(sizes, 0.10),
                "size_p50": _percentile(sizes, 0.50),
                "size_p90": _percentile(sizes, 0.90),
                "iat_mean": iat_mean,
                "iat_std": iat_std,
                "iat_cv": iat_std / iat_mean if iat_mean else 0.0,
                "burst_count": bursts,
                "burst_mean_length": mean(burst_lengths) if burst_lengths else 0.0,
                "byte_direction_ratio": larger_direction / max(smaller_direction, 1.0),
                "overhead_consistency": overhead_consistency,
                "size_mod_4_ratio": size_mod_4,
                "size_mod_8_ratio": size_mod_8,
                "size_mod_16_ratio": size_mod_16,
                "seq_monotonic": seq_monotonic,
                "seq_gap_count": seq_gap_count,
            }
        )
    return pd.DataFrame(rows)
