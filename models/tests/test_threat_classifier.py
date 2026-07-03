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

    The permutation applies to X *and* y with the same index so the input
    and target stay aligned — shuffling X alone silently destroys the
    correspondence and the "well-separated" premise of the test.
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

    perm = rng.permutation(len(X))
    X, y = X[perm], y[perm]

    n_train = int(len(X) * 0.8)
    return (
        X[:n_train], y[:n_train],
        X[n_train:], y[n_train:],
    )


def test_fit_and_predict_shape(sample_dataset):
    from models.threat_classifier import ThreatClassifier
    X_train, y_train, X_val, y_val = sample_dataset
    clf = ThreatClassifier(n_estimators=50)
    clf.fit(X_train, y_train, X_val, y_val)
    preds = clf.predict(X_val)
    assert preds.shape == (len(y_val),)


def test_predict_proba_shape(sample_dataset):
    from models.threat_classifier import ThreatClassifier
    X_train, y_train, X_val, y_val = sample_dataset
    clf = ThreatClassifier(n_estimators=50)
    clf.fit(X_train, y_train, X_val, y_val)
    labels, proba = clf.predict_proba(X_val)
    assert labels.shape == (len(y_val),)
    assert proba.shape == (len(y_val), 5)
    np.testing.assert_allclose(proba.sum(axis=1), 1.0, atol=1e-5)


def test_macro_f1_above_threshold(sample_dataset):
    """Well-separated synthetic data should achieve macro F1 > 0.7."""
    from models.threat_classifier import ThreatClassifier
    X_train, y_train, X_val, y_val = sample_dataset
    clf = ThreatClassifier(n_estimators=50)
    clf.fit(X_train, y_train, X_val, y_val)
    # `predict` returns the encoder's inverse_transform of int labels, so
    # results are int-typed and directly comparable to y_val — no ad-hoc
    # str-mapping needed.
    preds = clf.predict(X_val)
    macro_f1 = f1_score(y_val, preds, average="macro", zero_division=0)
    assert macro_f1 > 0.7, f"Macro F1 = {macro_f1:.4f} — check for preprocessing issues"


def test_predict_single(sample_dataset):
    from models.threat_classifier import ThreatClassifier
    X_train, y_train, X_val, y_val = sample_dataset
    clf = ThreatClassifier(n_estimators=50)
    clf.fit(X_train, y_train, X_val, y_val)
    label, confidence, proba = clf.predict_single(X_val[0])
    assert isinstance(label, str)
    assert 0.0 <= confidence <= 1.0
    assert len(proba) == 5


def test_save_load(sample_dataset, tmp_path):
    from models.threat_classifier import ThreatClassifier
    X_train, y_train, X_val, y_val = sample_dataset
    clf = ThreatClassifier(n_estimators=50)
    clf.fit(X_train, y_train, X_val, y_val)
    path = tmp_path / "test_xgb.ubj"
    clf.save(path)

    # Encoder + manifest must land on disk alongside the model
    assert (tmp_path / "test_xgb_encoder.joblib").exists()
    assert (tmp_path / "test_xgb_manifest.json").exists()

    loaded = ThreatClassifier.load(path)
    orig_preds = clf.predict(X_val)
    loaded_preds = loaded.predict(X_val)
    np.testing.assert_array_equal(orig_preds, loaded_preds)


def test_unfitted_raises():
    from models.threat_classifier import ThreatClassifier
    clf = ThreatClassifier()
    X = np.random.rand(10, 50).astype(np.float32)
    with pytest.raises(RuntimeError):
        clf.predict(X)
    with pytest.raises(RuntimeError):
        clf.predict_proba(X)


def test_unseen_val_label_is_dropped(sample_dataset):
    """Validation labels not present in training data must be skipped, not crash."""
    from models.threat_classifier import ThreatClassifier
    X_train, y_train, X_val, y_val = sample_dataset
    # Inject a class the trainer will never see
    y_val_dirty = y_val.copy()
    y_val_dirty[0] = 99
    clf = ThreatClassifier(n_estimators=50)
    # Must not raise
    clf.fit(X_train, y_train, X_val, y_val_dirty)
    assert clf.classes_ == [0, 1, 2, 3, 4]
