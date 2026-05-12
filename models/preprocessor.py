"""
Feature preprocessing pipeline for CICIDS-2017 features.

Pipeline steps:
  1. SimpleImputer(median)     — handles NaN from Infinity replacement
  2. StandardScaler            — required for IsolationForest distance calculations
  3. VarianceThreshold(0.01)   — removes near-constant features
  4. SelectKBest(f_classif, 50) — 78 → 50 features; ~35% faster inference

The fitted pipeline is persisted with joblib and loaded at inference time
by both the AnomalyDetector and ThreatClassifier.
"""

from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.feature_selection import VarianceThreshold

DEFAULT_PATH = Path("models/preprocessor.joblib")
N_FEATURES_OUT = 50


def build_pipeline(n_features: int = N_FEATURES_OUT) -> Pipeline:
    """Build a fresh (unfitted) preprocessing pipeline."""
    return Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler()),
        ("variance_threshold", VarianceThreshold(threshold=0.01)),
        ("feature_selection", SelectKBest(f_classif, k=n_features)),
    ])


def fit_and_save(
    X_train: np.ndarray,
    y_train: np.ndarray,
    path: str | Path = DEFAULT_PATH,
    n_features: int = N_FEATURES_OUT,
) -> Pipeline:
    """Fit the pipeline on training data and persist it."""
    pipeline = build_pipeline(n_features)
    pipeline.fit(X_train, y_train)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, path)
    return pipeline


def load(path: str | Path = DEFAULT_PATH) -> Pipeline:
    """Load a previously fitted pipeline from disk."""
    return joblib.load(path)


def transform(pipeline: Pipeline, X: np.ndarray) -> np.ndarray:
    """Apply the fitted pipeline to new data."""
    return pipeline.transform(X)


def get_feature_names(pipeline: Pipeline, original_names: list[str]) -> list[str]:
    """Return the names of selected features after the full pipeline."""
    # VarianceThreshold mask
    vt_support = pipeline.named_steps["variance_threshold"].get_support()
    after_vt = [n for n, keep in zip(original_names, vt_support) if keep]

    # SelectKBest mask
    kb_support = pipeline.named_steps["feature_selection"].get_support()
    selected = [n for n, keep in zip(after_vt, kb_support) if keep]
    return selected
