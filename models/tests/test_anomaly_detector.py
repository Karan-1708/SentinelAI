"""Tests for models/anomaly_detector.py — no Docker or real dataset required."""

import numpy as np
import pytest

from models.anomaly_detector import AnomalyDetector


@pytest.fixture
def benign_data():
    """500 rows of 'normal' traffic (tight Gaussian cluster)."""
    rng = np.random.default_rng(0)
    return rng.normal(loc=0.0, scale=1.0, size=(500, 50))


@pytest.fixture
def attack_data():
    """100 rows of 'attack' traffic (shifted distribution — clearly anomalous)."""
    rng = np.random.default_rng(1)
    return rng.normal(loc=10.0, scale=2.0, size=(100, 50))


def test_fit_predict_shape(benign_data, attack_data):
    """predict() must return array of same length as input."""
    detector = AnomalyDetector()
    detector.fit(benign_data)
    preds = detector.predict(attack_data)
    assert preds.shape == (100,)


def test_predict_values(benign_data, attack_data):
    """predict() must return only -1 or 1."""
    detector = AnomalyDetector()
    detector.fit(benign_data)
    preds = detector.predict(attack_data)
    assert set(preds).issubset({-1, 1})


def test_attack_more_anomalous_than_benign(benign_data, attack_data):
    """
    Mean anomaly score for clearly-shifted attack data must be lower
    (more negative) than for benign data.
    """
    detector = AnomalyDetector()
    detector.fit(benign_data)

    benign_scores = detector.score(benign_data)
    attack_scores = detector.score(attack_data)

    assert attack_scores.mean() < benign_scores.mean(), (
        "Attack rows should have lower (more anomalous) decision scores than BENIGN rows"
    )


def test_is_anomaly(benign_data, attack_data):
    """is_anomaly() must flag more attack rows than benign rows."""
    detector = AnomalyDetector()
    detector.fit(benign_data)

    benign_flags = detector.is_anomaly(benign_data).sum()
    attack_flags = detector.is_anomaly(attack_data).sum()

    # With clear separation (loc=0 vs loc=10), attacks should be flagged more
    assert attack_flags > benign_flags


def test_save_load(benign_data, attack_data, tmp_path):
    """Loaded detector must produce identical scores as the original."""
    detector = AnomalyDetector()
    detector.fit(benign_data)
    path = tmp_path / "if_test.joblib"
    detector.save(path)

    loaded = AnomalyDetector.load(path)
    orig_scores = detector.score(attack_data)
    load_scores = loaded.score(attack_data)
    np.testing.assert_array_almost_equal(orig_scores, load_scores)


def test_unfitted_raises(attack_data):
    """Calling predict/score before fit must raise RuntimeError."""
    detector = AnomalyDetector()
    with pytest.raises(RuntimeError):
        detector.predict(attack_data)
    with pytest.raises(RuntimeError):
        detector.score(attack_data)
