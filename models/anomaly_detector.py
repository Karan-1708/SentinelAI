"""
Isolation Forest anomaly detector — Stage 1 of the two-stage inference pipeline.

Key design decisions:
  - Trained ONLY on BENIGN rows: learns what normal network traffic looks like.
    Training on all classes would corrupt the "normal" distribution baseline.
  - decision_function() returns a raw score: more negative = more anomalous.
  - predict() returns -1 (anomaly) or 1 (normal).
  - If predict() returns 1 (normal), the ThreatClassifier is skipped (early exit).
    This catches zero-day patterns that XGBoost hasn't seen in training.
"""

from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

DEFAULT_PATH = Path("models/isolation_forest.joblib")


class AnomalyDetector:
    def __init__(
        self,
        contamination: float = 0.05,
        n_estimators: int = 100,
        random_state: int = 42,
    ) -> None:
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            n_jobs=-1,
            random_state=random_state,
        )
        self._fitted = False

    def fit(self, X_benign: np.ndarray) -> "AnomalyDetector":
        """
        Fit on BENIGN-only rows.
        Caller must filter to label == 'BENIGN' before passing X.
        """
        self.model.fit(X_benign)
        self._fitted = True
        return self

    def score(self, X: np.ndarray) -> np.ndarray:
        """
        Raw anomaly scores: more negative = more anomalous.
        Range is roughly [-0.5, 0.5] but not bounded.
        """
        if not self._fitted:
            raise RuntimeError("AnomalyDetector must be fitted before scoring.")
        return self.model.decision_function(X)

    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Returns -1 for anomalies, 1 for normal traffic.
        Use score() for a continuous severity signal.
        """
        if not self._fitted:
            raise RuntimeError("AnomalyDetector must be fitted before predicting.")
        return self.model.predict(X)

    def is_anomaly(self, X: np.ndarray) -> np.ndarray:
        """Returns a boolean array: True = anomaly detected."""
        return self.predict(X) == -1

    def save(self, path: str | Path = DEFAULT_PATH) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)

    @classmethod
    def load(cls, path: str | Path = DEFAULT_PATH) -> "AnomalyDetector":
        return joblib.load(path)
