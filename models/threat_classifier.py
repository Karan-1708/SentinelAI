"""
XGBoost multi-class threat classifier — Stage 2 of the two-stage inference pipeline.

Only runs when IsolationForest has flagged traffic as anomalous.

Class imbalance strategy (CICIDS-2017 is ~80% BENIGN):
  - compute_class_weight('balanced') → passed as sample_weight to .fit()
  - SMOTE only for extreme minorities (< 500 samples) inside imblearn.Pipeline
  - StratifiedKFold for cross-validation
  - Primary metric: macro F1 (not accuracy — misleading at 80/20 imbalance)

Robustness against unseen labels:
  - The label encoder is fit on training labels only. If the validation set
    contains a class the trainer never saw, ``fit`` filters it out and logs
    the count (rather than crashing on transform).
  - At inference, if the raw prediction cannot be reversed to a training-time
    class, ``predict_single`` returns ("UNKNOWN", 0.0, proba).

Serialization layout:
  ``<model_path>``               — XGBoost .ubj (native format)
  ``<model_path stem>_encoder.joblib``  — pickled LabelEncoder
  ``<model_path stem>_manifest.json``   — SHA-256 hashes for both files.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import sklearn
import xgboost as xgb
from sklearn.preprocessing import LabelEncoder
from sklearn.utils.class_weight import compute_class_weight

logger = logging.getLogger(__name__)

DEFAULT_PATH = Path("models/xgb_classifier.ubj")


def _encoder_path(model_path: Path) -> Path:
    """Deterministic sibling path for the label encoder."""
    return model_path.with_name(f"{model_path.stem}_encoder.joblib")


def _manifest_path(model_path: Path) -> Path:
    return model_path.with_name(f"{model_path.stem}_manifest.json")


def _sha256(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


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
        y_enc = self.label_encoder.fit_transform(y_train)

        # Filter validation rows whose class was never seen in training —
        # otherwise LabelEncoder.transform raises and kills the whole run.
        known = set(self.label_encoder.classes_.tolist())
        mask = np.array([label in known for label in y_val])
        skipped = int((~mask).sum())
        if skipped:
            logger.warning(
                "Dropping %d/%d validation rows with labels unseen during training",
                skipped,
                len(y_val),
            )
        X_val_f = X_val[mask]
        y_val_enc = self.label_encoder.transform(y_val[mask])

        if sample_weight is None:
            sample_weight = self._compute_sample_weights(y_train)

        eval_set = [(X_val_f, y_val_enc)] if len(y_val_enc) else None
        self.model.fit(
            X_train,
            y_enc,
            sample_weight=sample_weight,
            eval_set=eval_set,
            verbose=100,
        )
        self._fitted = True
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        if not self._fitted:
            raise RuntimeError("ThreatClassifier must be fitted before predicting.")
        y_enc = self.model.predict(X)
        return self.label_encoder.inverse_transform(y_enc)

    def predict_proba(self, X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        if not self._fitted:
            raise RuntimeError("ThreatClassifier must be fitted before predicting.")
        proba = self.model.predict_proba(X)
        predicted_indices = np.argmax(proba, axis=1)
        labels = self.label_encoder.inverse_transform(predicted_indices)
        return labels, proba

    def predict_single(self, X_row: np.ndarray) -> tuple[str, float, np.ndarray]:
        X_2d = X_row.reshape(1, -1) if X_row.ndim == 1 else X_row
        try:
            labels, proba = self.predict_proba(X_2d)
        except ValueError:
            logger.exception("Prediction failed; returning UNKNOWN")
            return "UNKNOWN", 0.0, np.zeros(len(self.label_encoder.classes_))
        confidence = float(np.max(proba[0]))
        return str(labels[0]), confidence, proba[0]

    @property
    def classes_(self) -> list[str]:
        return list(self.label_encoder.classes_)

    def save(self, path: str | Path = DEFAULT_PATH) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.model.save_model(str(path))

        encoder_path = _encoder_path(path)
        joblib.dump(self.label_encoder, encoder_path)

        manifest = {
            "model_path": path.name,
            "encoder_path": encoder_path.name,
            "model_sha256": _sha256(path),
            "encoder_sha256": _sha256(encoder_path),
            "sklearn_version": sklearn.__version__,
            "xgboost_version": xgb.__version__,
            "n_classes": len(self.label_encoder.classes_),
            "classes": [str(c) for c in self.label_encoder.classes_],
            "trained_at": datetime.now(timezone.utc).isoformat(),
        }
        _manifest_path(path).write_text(json.dumps(manifest, indent=2))

    @classmethod
    def load(cls, path: str | Path = DEFAULT_PATH) -> "ThreatClassifier":
        model_path = Path(path)
        encoder_path = _encoder_path(model_path)
        if not encoder_path.exists():
            raise FileNotFoundError(f"Encoder not found alongside model: {encoder_path}")

        instance = cls.__new__(cls)
        instance.model = xgb.XGBClassifier()
        instance.model.load_model(str(model_path))
        instance.label_encoder = joblib.load(encoder_path)
        instance._fitted = True

        manifest_p = _manifest_path(model_path)
        if manifest_p.exists():
            try:
                manifest = json.loads(manifest_p.read_text())
                trained_sklearn = manifest.get("sklearn_version")
                if trained_sklearn and trained_sklearn.split(".")[0] != sklearn.__version__.split(".")[0]:
                    logger.warning(
                        "Model trained with scikit-learn %s but runtime is %s — "
                        "predictions may be unstable.",
                        trained_sklearn,
                        sklearn.__version__,
                    )
            except (json.JSONDecodeError, OSError):
                logger.exception("Manifest at %s could not be read", manifest_p)
        return instance
