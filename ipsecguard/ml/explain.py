from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd

from ipsecguard.ml.anomaly import FEATURE_COLUMNS

try:
    import shap
except Exception:  # pragma: no cover - graceful fallback
    shap = None


def top_contributions(model: Any, features: pd.DataFrame) -> list[dict[str, float | str]]:
    if features.empty:
        return []
    row = features[FEATURE_COLUMNS]
    if shap is not None:
        try:
            explainer = shap.TreeExplainer(model)
            values = explainer.shap_values(row)
            predicted_index = int(model.predict(row)[0])
            if isinstance(values, list):
                array = np.array(values[predicted_index][0])
            else:
                array = np.array(values)
                if array.ndim == 3:
                    array = array[0, :, predicted_index]
                else:
                    array = array[0]
            pairs = sorted(
                zip(FEATURE_COLUMNS, array, strict=False),
                key=lambda item: abs(float(item[1])),
                reverse=True,
            )[:5]
            return [{"feature": name, "impact": round(float(value), 4)} for name, value in pairs]
        except Exception:
            pass
    baseline = row.iloc[0].to_dict()
    pairs = sorted(baseline.items(), key=lambda item: abs(float(item[1])), reverse=True)[:5]
    return [{"feature": name, "impact": round(float(value), 4)} for name, value in pairs]
