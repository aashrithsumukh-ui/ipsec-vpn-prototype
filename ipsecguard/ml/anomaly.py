from __future__ import annotations

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

from ipsecguard.utils import MODELS_DIR

MODEL_PATH = MODELS_DIR / "anomaly.joblib"

FEATURE_COLUMNS = [
    "packet_count",
    "duration",
    "size_mean",
    "size_std",
    "size_p10",
    "size_p50",
    "size_p90",
    "iat_mean",
    "iat_std",
    "iat_cv",
    "burst_count",
    "burst_mean_length",
    "byte_direction_ratio",
    "overhead_consistency",
    "size_mod_4_ratio",
    "size_mod_8_ratio",
    "size_mod_16_ratio",
    "seq_monotonic",
    "seq_gap_count",
]


def train_anomaly_model(features: pd.DataFrame) -> IsolationForest:
    model = IsolationForest(random_state=42, contamination=0.2)
    model.fit(features[FEATURE_COLUMNS])
    joblib.dump(model, MODEL_PATH)
    return model


def load_or_create_model(features: pd.DataFrame | None = None) -> IsolationForest:
    if MODEL_PATH.exists():
        return joblib.load(MODEL_PATH)
    baseline = (
        features
        if features is not None and not features.empty
        else pd.DataFrame([{column: 0.0 for column in FEATURE_COLUMNS}])
    )
    return train_anomaly_model(baseline)


def score_anomaly(model: IsolationForest, features: pd.DataFrame) -> float:
    if features.empty:
        return 0.0
    raw = -model.score_samples(features[FEATURE_COLUMNS])[0]
    return max(0.0, min(raw / 0.8, 1.0))
