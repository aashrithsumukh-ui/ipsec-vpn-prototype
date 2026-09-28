from __future__ import annotations

import pandas as pd

from ipsecguard.features.esp import extract_flow_features
from ipsecguard.ml.anomaly import FEATURE_COLUMNS, train_anomaly_model
from ipsecguard.ml.traffic_classifier import build_split_indices, train_classifier
from ipsecguard.utils import DATA_DIR


def build_training_frame() -> pd.DataFrame:
    manifest = pd.read_csv(DATA_DIR / "synthetic" / "manifest.csv")
    required_columns = {
        "file",
        "ike_version",
        "ike_enc",
        "ike_integ",
        "dh_group",
        "pfs",
        "mode",
        "esp_cipher",
        "traffic_label",
    }
    rows = []
    for item in manifest.to_dict(orient="records"):
        if not required_columns.issubset(item):
            continue
        if str(item["ike_version"]) != "2.0":
            continue
        pcap_path = DATA_DIR / "synthetic" / item["file"]
        features = extract_flow_features(pcap_path)
        if features.empty:
            continue
        row = features.iloc[0].to_dict()
        row.update(item)
        row["config_group"] = (
            f"{item['ike_enc']}|{item['ike_integ']}|{item['dh_group']}|"
            f"{item['pfs']}|{item['mode']}|{item['esp_cipher']}"
        )
        rows.append(row)
    frame = pd.DataFrame(rows)
    return frame


def main() -> None:
    dataset = build_training_frame()
    train_idx, test_idx = build_split_indices(dataset)
    train_classifier(dataset, train_idx=train_idx, test_idx=test_idx)
    train_anomaly_model(dataset.iloc[train_idx][FEATURE_COLUMNS])


if __name__ == "__main__":
    main()
