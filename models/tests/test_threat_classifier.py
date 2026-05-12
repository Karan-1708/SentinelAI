"""Tests for models/threat_classifier.py — uses synthetic 1000-row sample."""

import sys
from pathlib import Path

import numpy as np
import pytest
from sklearn.metrics import f1_score

sys.path.insert(0, str(Path(__file__).parents[2]))


@pytest.fixture(scope="module")
def sample_dataset():
    """
    Generate a synthetic dataset that is intentionally easy to classify
    (well-separated clusters) for smoke testing the model code path.
    """
    rng = np.random.default_rng(42)
    n_per_class = 200
    n_classes = 5
    n_features = 50

    X_parts, y_parts = [], []
    for cls in range(n_classes):
        X_cls = rng.normal(loc=float(cls * 5), scale=1.0, size=(n_per_class, n_features))
        X_parts.append(X_cls)
        y_parts.append(np.full(n_per_class, cls))

    X = np.vstack(X_parts).astype(np.float32)
    y = np.concatenate(y_parts)
    rng.shuffle(X)

    # Simple 80/20 split
    n_train = int(len(X) * 0.8)
    return (
        X[:n_train], y[:n_train],
        X[n_train:], y[n_train:],
    )


def test_fit_and_predict_shape(sample_dataset):
    """predict() must return array of same length as input."""
    from models.threat_classifier import ThreatClassifier
    X_train, y_train, X_val, y_val = sample_dataset
    clf = ThreatClassifier(n_estimators=50)
    clf.fit(X_train, y_train, X_val, y_val)
    preds = clf.predict(X_val)
    assert preds.shape == (len(y_val),)


def test_predict_proba_shape(sample_dataset):
    """predict_proba() must return (labels, proba) with correct shapes."""
    from models.threat_classifier import ThreatClassifier
    X_train, y_train, X_val, y_val = sample_dataset
    clf = ThreatClassifier(n_estimators=50)
    clf.fit(X_train, y_train, X_val, y_val)
    labels, proba = clf.predict_proba(X_val)
    assert labels.shape == (len(y_val),)
    assert proba.shape == (len(y_val), 5)  # 5 classes
    # Probabilities must sum to ~1 per row
    np.testing.assert_allclose(proba.sum(axis=1), 1.0, atol=1e-5)


def test_macro_f1_above_threshold(sample_dataset):
    """Macro F1 on well-separated synthetic data must exceed 0.7 (smoke test)."""
    from models.threat_classifier import ThreatClassifier
    X_train, y_train, X_val, y_val = sample_dataset
    clf = ThreatClassifier(n_estimators=50)
    clf.fit(X_train, y_train, X_val, y_val)
    preds = clf.predict(X_val)
    # Convert string labels back to int for f1_score
    label_to_int = {str(i): i for i in range(5)}
    y_pred_int = np.array([label_to_int.get(str(p), -1) for p in preds])
    macro_f1 = f1_score(y_val, y_pred_int, average="macro", zero_division=0)
    assert macro_f1 > 0.7, f"Macro F1 = {macro_f1:.4f} — check for preprocessing issues"


def test_predict_single(sample_dataset):
    """predict_single() must return (label_str, confidence_float, proba_array)."""
    from models.threat_classifier import ThreatClassifier
    X_train, y_train, X_val, y_val = sample_dataset
    clf = ThreatClassifier(n_estimators=50)
    clf.fit(X_train, y_train, X_val, y_val)
    label, confidence, proba = clf.predict_single(X_val[0])
    assert isinstance(label, str)
    assert 0.0 <= confidence <= 1.0
    assert len(proba) == 5


def test_save_load(sample_dataset, tmp_path):
    """Loaded classifier must produce identical predictions as original."""
    from models.threat_classifier import ThreatClassifier
    X_train, y_train, X_val, y_val = sample_dataset
    clf = ThreatClassifier(n_estimators=50)
    clf.fit(X_train, y_train, X_val, y_val)
    path = tmp_path / "test_xgb.ubj"
    clf.save(path)

    loaded = ThreatClassifier.load(path)
    orig_preds = clf.predict(X_val)
    loaded_preds = loaded.predict(X_val)
    np.testing.assert_array_equal(orig_preds, loaded_preds)


def test_unfitted_raises():
    """predict/predict_proba before fit must raise RuntimeError."""
    from models.threat_classifier import ThreatClassifier
    clf = ThreatClassifier()
    X = np.random.rand(10, 50).astype(np.float32)
    with pytest.raises(RuntimeError):
        clf.predict(X)
    with pytest.raises(RuntimeError):
        clf.predict_proba(X)
