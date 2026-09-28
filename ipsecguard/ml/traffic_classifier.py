from __future__ import annotations

import json

import joblib
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score
from sklearn.model_selection import GroupShuffleSplit
from xgboost import XGBClassifier

from ipsecguard.ml.anomaly import FEATURE_COLUMNS
from ipsecguard.utils import MODELS_DIR

MODEL_PATH = MODELS_DIR / "traffic_classifier.joblib"
METRICS_PATH = MODELS_DIR / "metrics.json"
CONFUSION_PATH = MODELS_DIR / "confusion_matrix.png"
LABELS_PATH = MODELS_DIR / "traffic_labels.json"


def build_split_indices(dataset: pd.DataFrame) -> tuple[list[int], list[int]]:
    feature_frame = dataset[FEATURE_COLUMNS]
    labels = dataset["traffic_label"]
    groups = dataset["config_group"]
    splitter = GroupShuffleSplit(n_splits=1, test_size=0.3, random_state=42)
    train_idx, test_idx = next(splitter.split(feature_frame, labels, groups=groups))
    return train_idx.tolist(), test_idx.tolist()


def train_classifier(
    dataset: pd.DataFrame,
    train_idx: list[int] | None = None,
    test_idx: list[int] | None = None,
) -> dict:
    feature_frame = dataset[FEATURE_COLUMNS]
    labels = dataset["traffic_label"]
    if train_idx is None or test_idx is None:
        train_idx, test_idx = build_split_indices(dataset)
    X_train = feature_frame.iloc[train_idx]
    X_test = feature_frame.iloc[test_idx]
    y_train = labels.iloc[train_idx]
    y_test = labels.iloc[test_idx]
    classes = sorted(labels.unique().tolist())
    mapping = {label: index for index, label in enumerate(classes)}
    inverse_mapping = {index: label for label, index in mapping.items()}
    model = XGBClassifier(
        objective="multi:softprob",
        eval_metric="mlogloss",
        random_state=42,
        n_estimators=40,
        max_depth=4,
        learning_rate=0.2,
        subsample=0.9,
        colsample_bytree=0.9,
    )
    model.fit(X_train, y_train.map(mapping))
    predictions = model.predict(X_test)
    predicted_labels = [inverse_mapping[int(value)] for value in predictions]
    matrix = confusion_matrix(y_test, predicted_labels, labels=classes)
    accuracy = accuracy_score(y_test, predicted_labels)
    macro_f1 = f1_score(y_test, predicted_labels, average="macro")
    metrics = {
        "accuracy": round(float(accuracy), 4),
        "macro_f1": round(float(macro_f1), 4),
        "evaluation": "held-out config split via GroupShuffleSplit",
        "train_size": int(len(train_idx)),
        "test_size": int(len(test_idx)),
        "config_groups": sorted(dataset["config_group"].unique().tolist()),
        "labels": classes,
        "confusion_matrix": matrix.tolist(),
    }
    joblib.dump(model, MODEL_PATH)
    LABELS_PATH.write_text(json.dumps(inverse_mapping, indent=2), encoding="utf-8")
    METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.imshow(matrix, cmap="Blues")
    ax.set_xticks(range(len(classes)), classes, rotation=45, ha="right")
    ax.set_yticks(range(len(classes)), classes)
    ax.set_title("Traffic confusion matrix")
    for row in range(len(classes)):
        for column in range(len(classes)):
            ax.text(column, row, int(matrix[row, column]), ha="center", va="center")
    fig.tight_layout()
    fig.savefig(CONFUSION_PATH)
    plt.close(fig)
    return metrics


def load_model() -> XGBClassifier:
    return joblib.load(MODEL_PATH)


def predict_traffic(model: XGBClassifier, features: pd.DataFrame) -> tuple[str, float]:
    label_map = json.loads(LABELS_PATH.read_text(encoding="utf-8"))
    probabilities = model.predict_proba(features[FEATURE_COLUMNS])[0]
    best_idx = int(probabilities.argmax())
    return label_map[str(best_idx)], float(probabilities[best_idx])
