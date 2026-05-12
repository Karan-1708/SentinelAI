"""
Prediction service — orchestrates the two-stage inference pipeline.

Loaded once at API startup via FastAPI lifespan. Never instantiate per-request
(model loading from disk takes seconds and would cause catastrophic latency).

Inference order:
  1. preprocess(features) → scaled/selected numpy array
  2. anomaly_score()     → IsolationForest raw score
  3. classify()          → XGBoost label + probabilities
  4. map_mitre()         → MITRE ATT&CK techniques
  5. explain()           → SHAP feature contributions
  6. derive_severity()   → CRITICAL/HIGH/MEDIUM/LOW/INFO
"""

from __future__ import annotations

import logging
from typing import Optional

import numpy as np

from api.config import settings
from ingestion.normalizer import INT_TO_LABEL
from models.anomaly_detector import AnomalyDetector
from models.mitre_mapper import MitreMapper
from models.preprocessor import load as load_preprocessor
from models.threat_classifier import ThreatClassifier

logger = logging.getLogger(__name__)

# Feature column order for CICIDS-2017 (must match training data column order)
FEATURE_COLUMNS = [
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
    "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
    "Min Packet Length", "Max Packet Length", "Packet Length Mean",
    "Packet Length Std", "Packet Length Variance", "FIN Flag Count",
    "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count",
    "URG Flag Count", "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio",
    "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size",
    "Fwd Header Length.1", "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate", "Subflow Fwd Packets", "Subflow Fwd Bytes",
    "Subflow Bwd Packets", "Subflow Bwd Bytes", "Init_Win_bytes_forward",
    "Init_Win_bytes_backward", "act_data_pkt_fwd", "min_seg_size_forward",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]


def _derive_severity(anomaly_score: float, label: str, confidence: float) -> str:
    """
    Derive a severity tier from the anomaly score, threat label, and confidence.
    Anomaly score from IsolationForest: more negative = more anomalous.
    """
    if label == "BENIGN":
        return "INFO"
    if anomaly_score < settings.anomaly_score_critical and confidence > 0.8:
        return "CRITICAL"
    if anomaly_score < settings.anomaly_score_high:
        return "HIGH"
    if anomaly_score < settings.anomaly_score_medium:
        return "MEDIUM"
    return "LOW"


class PredictionService:
    def __init__(
        self,
        preprocessor_path: str = settings.preprocessor_path,
        model_path: str = settings.model_path,
        isolation_forest_path: str = settings.isolation_forest_path,
        stix_path: str = "data/enterprise-attack.json",
    ) -> None:
        logger.info("Loading preprocessor from %s", preprocessor_path)
        self.pipeline = load_preprocessor(preprocessor_path)

        logger.info("Loading IsolationForest from %s", isolation_forest_path)
        self.detector = AnomalyDetector.load(isolation_forest_path)

        logger.info("Loading XGBoost classifier from %s", model_path)
        self.classifier = ThreatClassifier.load(model_path)

        self.mitre_mapper = MitreMapper(stix_path)

        # Lazy-load SHAP explainer (heavy import)
        self._shap_explainer = None
        logger.info("PredictionService ready")

    def _get_shap_explainer(self):
        if self._shap_explainer is None:
            from explainability.shap_explainer import SHAPExplainer
            from models.preprocessor import get_feature_names
            feature_names = get_feature_names(self.pipeline, FEATURE_COLUMNS)
            self._shap_explainer = SHAPExplainer(
                xgb_model=self.classifier.model,
                feature_names=feature_names,
            )
        return self._shap_explainer

    def features_to_array(self, features: dict[str, float]) -> np.ndarray:
        """Convert a feature dict to a numpy array in CICIDS-2017 column order."""
        row = np.array(
            [features.get(col, 0.0) for col in FEATURE_COLUMNS],
            dtype=np.float32,
        )
        return row.reshape(1, -1)

    def predict(
        self,
        features: dict[str, float],
        source_ip: Optional[str] = None,
        dest_ip: Optional[str] = None,
    ) -> dict:
        """
        Full prediction pipeline. Returns a dict with all inference results.
        """
        X_raw = self.features_to_array(features)

        # Replace Infinity before preprocessing
        X_raw = np.where(np.isinf(X_raw), np.nan, X_raw)

        # Step 1: Preprocess
        X_processed = self.pipeline.transform(X_raw)

        # Step 2: Anomaly detection
        anomaly_score = float(self.detector.score(X_processed)[0])
        anomaly_flag = bool(self.detector.is_anomaly(X_processed)[0])

        # Step 3: Classification (always run — even for non-anomalies, for logging)
        label, confidence, proba = self.classifier.predict_single(X_processed)
        if label.isdigit():
            label = INT_TO_LABEL.get(int(label), label)

        # Step 4: MITRE mapping
        mitre_techniques = self.mitre_mapper.map(label)

        # Step 5: SHAP explanation
        try:
            explainer = self._get_shap_explainer()
            shap_data = explainer.explain_prediction(X_processed)
            shap_values = shap_data["feature_contributions"]
            top_shap = shap_data["top_features"][:10]
        except Exception as e:
            logger.warning("SHAP explanation failed: %s", e)
            shap_values = []
            top_shap = []

        # Step 6: Severity
        severity = _derive_severity(anomaly_score, label, confidence)

        return {
            "threat_label": label,
            "severity": severity,
            "confidence": confidence,
            "anomaly_score": anomaly_score,
            "is_anomaly": anomaly_flag,
            "mitre_techniques": mitre_techniques,
            "shap_values": shap_values,
            "top_shap_features": top_shap,
            "raw_features": features,
        }
