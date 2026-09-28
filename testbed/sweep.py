from __future__ import annotations

import csv
import itertools
from pathlib import Path

MODES = ["tunnel", "transport"]
IKE_ENC = ["aes128", "aes256", "aes-gcm"]
DH_GROUPS = [14, 19, 20]
PFS_VALUES = ["on", "off"]


def build_manifest_rows() -> list[dict[str, str | int]]:
    rows = []
    for mode, cipher, dh_group, pfs in itertools.product(MODES, IKE_ENC, DH_GROUPS, PFS_VALUES):
        filename = f"{mode}_{cipher}_dh{dh_group}_pfs{pfs}.pcap"
        rows.append(
            {
                "file": filename,
                "mode": mode,
                "ike_enc": cipher,
                "dh_group": dh_group,
                "pfs": pfs,
                "notes": "Documented hackathon scaffold; run with privileged Docker host.",
            }
        )
    return rows


def write_manifest(path: Path) -> None:
    rows = build_manifest_rows()
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    output = Path(__file__).resolve().parent / "manifest.csv"
    write_manifest(output)
    print(f"Wrote scaffold manifest to {output}")
