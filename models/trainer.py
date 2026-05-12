"""
Model training orchestrator.

Loads CICIDS-2017 data, fits the preprocessing pipeline, trains both models,
evaluates on a held-out test set, and logs everything to MLflow.

MLflow autolog captures XGBoost params and per-round metrics automatically.
The preprocessor and IsolationForest are logged manually (autolog misses them).

Usage:
    python scripts/run_training.py
    # or directly:
    python -m models.trainer --data-dir data/cicids --experiment sentinelai-classifier
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import tempfile
from pathlib import Path

import joblib
import mlflow
import mlflow.xgboost
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from ingestion.normalizer import INT_TO_LABEL, LABEL_TO_INT, iter_chunks, normalize_labels
from models.anomaly_detector import AnomalyDetector
from models.evaluator import confusion_matrix_figure, evaluate, figure_to_bytes
from models.preprocessor import fit_and_save, get_feature_names, load, transform
from models.threat_classifier import ThreatClassifier

logger = logging.getLogger(__name__)

MODEL_DIR = Path("models")
DATA_DIR = Path("data/cicids")


def load_dataset(data_dir: Path, max_rows: int | None = None) -> pd.DataFrame:
    """Load all CICIDS CSVs from data_dir into a single DataFrame."""
    csv_files = list(data_dir.glob("*.csv"))
    if not csv_files:
        raise FileNotFoundError(
            f"No CSV files found in {data_dir}. "
            "Run: python data/download_cicids.py"
        )
    logger.info("Loading %d CSV files from %s", len(csv_files), data_dir)

    chunks = []
    total = 0
    for csv_path in csv_files:
        for chunk in iter_chunks(csv_path, chunk_size=50_000):
            chunks.append(chunk)
            total += len(chunk)
            if max_rows and total >= max_rows:
                break
        if max_rows and total >= max_rows:
            break

    df = pd.concat(chunks, ignore_index=True)
    if max_rows:
        df = df.head(max_rows)
    logger.info("Loaded %d total rows", len(df))
    return df


def prepare_features(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    """Extract feature matrix X and integer label vector y."""
    df = normalize_labels(df)

    # Drop rows with unknown labels (-1)
    df = df[df["label_int"] >= 0].reset_index(drop=True)

    feature_cols = [c for c in df.columns if c not in ("label", "label_int", "Label")]
    X = df[feature_cols].values.astype(np.float32)
    y = df["label_int"].values

    logger.info("Feature matrix: %s, labels: %d classes", X.shape, len(np.unique(y)))
    return X, y


def train(
    data_dir: Path = DATA_DIR,
    model_dir: Path = MODEL_DIR,
    experiment_name: str = "sentinelai-classifier",
    mlflow_uri: str = "http://localhost:5000",
    test_size: float = 0.2,
    val_size: float = 0.1,
    max_rows: int | None = None,
) -> dict:
    """Full training pipeline. Returns evaluation metrics dict."""
    mlflow.set_tracking_uri(mlflow_uri)
    mlflow.set_experiment(experiment_name)

    # Load and split data
    df = load_dataset(data_dir, max_rows=max_rows)
    X, y = prepare_features(df)

    # Column names (before preprocessing reduces them)
    feature_cols = [c for c in df.columns if c not in ("label", "label_int", "Label")]
    class_names = [INT_TO_LABEL[i] for i in sorted(np.unique(y)) if i in INT_TO_LABEL]

    # Train/val/test split — stratified to preserve class distribution
    X_trainval, X_test, y_trainval, y_test = train_test_split(
        X, y, test_size=test_size, random_state=42, stratify=y
    )
    val_ratio = val_size / (1 - test_size)
    X_train, X_val, y_train, y_val = train_test_split(
        X_trainval, y_trainval, test_size=val_ratio, random_state=42, stratify=y_trainval
    )
    logger.info("Train: %d, Val: %d, Test: %d", len(X_train), len(X_val), len(X_test))

    with mlflow.start_run():
        mlflow.log_params({
            "n_train": len(X_train),
            "n_val": len(X_val),
            "n_test": len(X_test),
            "n_classes": len(np.unique(y)),
            "test_size": test_size,
        })

        # ── Step 1: Fit preprocessor ────────────────────────────────────
        logger.info("Fitting preprocessing pipeline...")
        preprocessor_path = model_dir / "preprocessor.joblib"
        pipeline = fit_and_save(X_train, y_train, path=preprocessor_path)
        selected_features = get_feature_names(pipeline, feature_cols)
        logger.info("Selected %d features", len(selected_features))

        X_train_t = transform(pipeline, X_train)
        X_val_t = transform(pipeline, X_val)
        X_test_t = transform(pipeline, X_test)

        mlflow.log_artifact(str(preprocessor_path))
        mlflow.log_dict(
            {"selected_features": selected_features},
            "selected_features.json",
        )

        # ── Step 2: Train IsolationForest (BENIGN-only) ─────────────────
        logger.info("Training IsolationForest on BENIGN rows only...")
        benign_mask = y_train == 0  # 0 = BENIGN
        X_benign = X_train_t[benign_mask]
        detector = AnomalyDetector()
        detector.fit(X_benign)

        if_path = model_dir / "isolation_forest.joblib"
        detector.save(if_path)
        mlflow.log_artifact(str(if_path))

        # Evaluate anomaly detector on test set
        anomaly_preds = detector.predict(X_test_t)
        # Anomaly = -1 → everything non-BENIGN should ideally be -1
        true_anomaly = (y_test != 0).astype(int)
        pred_anomaly = (anomaly_preds == -1).astype(int)
        if_precision = float(np.sum((pred_anomaly == 1) & (true_anomaly == 1)) / (np.sum(pred_anomaly == 1) + 1e-9))
        if_recall = float(np.sum((pred_anomaly == 1) & (true_anomaly == 1)) / (np.sum(true_anomaly == 1) + 1e-9))
        mlflow.log_metrics({"if_precision": if_precision, "if_recall": if_recall})
        logger.info("IsolationForest — precision: %.3f, recall: %.3f", if_precision, if_recall)

        # ── Step 3: Train XGBoost classifier ───────────────────────────
        logger.info("Training XGBoost classifier...")
        mlflow.xgboost.autolog()

        classifier = ThreatClassifier()
        classifier.fit(X_train_t, y_train, X_val_t, y_val)

        classifier_path = model_dir / "xgb_classifier.ubj"
        classifier.save(classifier_path)

        # ── Step 4: Evaluate on test set ───────────────────────────────
        logger.info("Evaluating on test set...")
        y_pred_labels, y_proba = classifier.predict_proba(X_test_t)
        y_pred_int = np.array([
            list(INT_TO_LABEL.values()).index(lbl)
            if lbl in list(INT_TO_LABEL.values()) else -1
            for lbl in y_pred_labels
        ])

        metrics = evaluate(y_test, y_pred_int, y_proba, class_names=class_names)
        mlflow.log_metric("macro_f1", metrics["macro_f1"])
        mlflow.log_metric("accuracy", metrics["accuracy"])
        if "roc_auc" in metrics and metrics["roc_auc"] is not None:
            mlflow.log_metric("roc_auc", metrics["roc_auc"])

        mlflow.log_dict(metrics["classification_report"], "classification_report.json")

        # Confusion matrix figure
        fig = confusion_matrix_figure(y_test, y_pred_int, class_names=class_names)
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
            f.write(figure_to_bytes(fig))
            mlflow.log_artifact(f.name, artifact_path="plots")

        logger.info(
            "Training complete. macro_F1=%.4f, accuracy=%.4f",
            metrics["macro_f1"],
            metrics["accuracy"],
        )
        return metrics


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train SentinelAI models")
    parser.add_argument("--data-dir", default=str(DATA_DIR))
    parser.add_argument("--model-dir", default=str(MODEL_DIR))
    parser.add_argument("--experiment", default="sentinelai-classifier")
    parser.add_argument("--mlflow-uri", default=os.getenv("MLFLOW_TRACKING_URI", "http://localhost:5000"))
    parser.add_argument("--max-rows", type=int, default=None, help="Limit rows for quick testing")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    metrics = train(
        data_dir=Path(args.data_dir),
        model_dir=Path(args.model_dir),
        experiment_name=args.experiment,
        mlflow_uri=args.mlflow_uri,
        max_rows=args.max_rows,
    )
    print(f"\nmacro_F1 = {metrics['macro_f1']:.4f}")
    print(f"accuracy = {metrics['accuracy']:.4f}")
