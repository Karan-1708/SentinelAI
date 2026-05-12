"""
XGBoost multi-class threat classifier — Stage 2 of the two-stage inference pipeline.

Only runs when IsolationForest has flagged traffic as anomalous.

Class imbalance strategy (CICIDS-2017 is ~80% BENIGN):
  - compute_class_weight('balanced') → passed as sample_weight to .fit()
  - SMOTE only for extreme minorities (< 500 samples) inside imblearn.Pipeline
  - StratifiedKFold for cross-validation
  - Primary metric: macro F1 (not accuracy — misleading at 80/20 imbalance)

XGBoost kwargs:
  - tree_method='hist': faster than 'exact' on 2.8M rows
  - early_stopping_rounds=20: stops if val mlogloss doesn't improve for 20 rounds
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import xgboost as xgb
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_class_weight

DEFAULT_PATH = Path("models/xgb_classifier.ubj")


class ThreatClassifier:
    def __init__(
        self,
        n_estimators: int = 500,
        max_depth: int = 7,
        learning_rate: float = 0.05,
        subsample: float = 0.8,
        colsample_bytree: float = 0.8,
        random_state: int = 42,
    ) -> None:
        self.model = xgb.XGBClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            learning_rate=learning_rate,
            subsample=subsample,
            colsample_bytree=colsample_bytree,
            use_label_encoder=False,
            eval_metric="mlogloss",
            tree_method="hist",
            device="cpu",
            n_jobs=-1,
            random_state=random_state,
            early_stopping_rounds=20,
        )
        self.label_encoder = LabelEncoder()
        self._fitted = False

    def _compute_sample_weights(self, y: np.ndarray) -> np.ndarray:
        """Compute per-sample weights to compensate for class imbalance."""
        classes = np.unique(y)
        weights = compute_class_weight("balanced", classes=classes, y=y)
        weight_map = dict(zip(classes, weights))
        return np.array([weight_map[label] for label in y])

    def fit(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: np.ndarray,
        y_val: np.ndarray,
        sample_weight: Optional[np.ndarray] = None,
    ) -> "ThreatClassifier":
        """
        Fit the classifier with validation set for early stopping.

        Args:
            X_train, y_train: Training features and string labels.
            X_val, y_val: Validation set for early stopping.
            sample_weight: Per-sample weights. If None, computed automatically.
        """
        y_enc = self.label_encoder.fit_transform(y_train)
        y_val_enc = self.label_encoder.transform(y_val)

        if sample_weight is None:
            sample_weight = self._compute_sample_weights(y_train)

        self.model.fit(
            X_train,
            y_enc,
            sample_weight=sample_weight,
            eval_set=[(X_val, y_val_enc)],
            verbose=100,
        )
        self._fitted = True
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Returns predicted string labels."""
        if not self._fitted:
            raise RuntimeError("ThreatClassifier must be fitted before predicting.")
        y_enc = self.model.predict(X)
        return self.label_encoder.inverse_transform(y_enc)

    def predict_proba(self, X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """
        Returns (predicted_labels, probability_matrix).
        probability_matrix shape: (n_samples, n_classes)
        """
        if not self._fitted:
            raise RuntimeError("ThreatClassifier must be fitted before predicting.")
        proba = self.model.predict_proba(X)
        predicted_indices = np.argmax(proba, axis=1)
        labels = self.label_encoder.inverse_transform(predicted_indices)
        return labels, proba

    def predict_single(self, X_row: np.ndarray) -> tuple[str, float, np.ndarray]:
        """
        Predict a single sample. Returns (label, confidence, all_probas).
        Confidence = probability of the predicted class.
        """
        X_2d = X_row.reshape(1, -1) if X_row.ndim == 1 else X_row
        labels, proba = self.predict_proba(X_2d)
        confidence = float(np.max(proba[0]))
        return str(labels[0]), confidence, proba[0]

    @property
    def classes_(self) -> list[str]:
        return list(self.label_encoder.classes_)

    def save(self, path: str | Path = DEFAULT_PATH) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        # Save XGBoost model in native UBJ format (faster than pickle)
        self.model.save_model(str(path))
        # Save the label encoder alongside
        joblib.dump(self.label_encoder, str(path).replace(".ubj", "_encoder.joblib"))

    @classmethod
    def load(cls, path: str | Path = DEFAULT_PATH) -> "ThreatClassifier":
        instance = cls.__new__(cls)
        instance.model = xgb.XGBClassifier()
        instance.model.load_model(str(path))
        encoder_path = str(path).replace(".ubj", "_encoder.joblib")
        instance.label_encoder = joblib.load(encoder_path)
        instance._fitted = True
        return instance
