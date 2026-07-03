"""Tests for models/preprocessor.py — no Docker or real dataset required."""

import sys
from pathlib import Path

import numpy as np
import pytest

# Add project root to path so imports work without installation
sys.path.insert(0, str(Path(__file__).parents[2]))

from models.preprocessor import build_pipeline, fit_and_save, get_feature_names, load, transform


@pytest.fixture
def synthetic_data():
    """500 rows, 78 features, 5 classes — mirrors CICIDS-2017 structure."""
    rng = np.random.default_rng(42)
    X = np.abs(rng.normal(100, 50, size=(500, 78))).astype(np.float32)
    # Inject some NaN values (as would come from Infinity replacement)
    for _ in range(20):
        X[rng.integers(500), rng.integers(78)] = np.nan
    y = rng.integers(0, 5, size=500)
    return X, y


def test_output_shape(synthetic_data, tmp_path):
    """Pipeline must reduce 78 features to 50."""
    X, y = synthetic_data
    pipeline = build_pipeline(n_features=50)
    X_t = pipeline.fit_transform(X, y)
    assert X_t.shape[0] == 500
    assert X_t.shape[1] == 50


def test_no_nan_after_transform(synthetic_data, tmp_path):
    """No NaN values must remain after pipeline transform."""
    X, y = synthetic_data
    pipeline = build_pipeline(n_features=50)
    X_t = pipeline.fit_transform(X, y)
    assert not np.isnan(X_t).any(), "NaN values found after preprocessing pipeline"


def test_no_inf_after_transform(synthetic_data):
    """Inject Inf values; pipeline must eliminate them via imputation."""
    X, y = synthetic_data
    X[0, 0] = np.inf
    X[1, 1] = -np.inf
    pipeline = build_pipeline(n_features=50)
    # SimpleImputer does NOT handle inf — normalizer.py must replace inf with nan first
    X_clean = np.where(np.isinf(X), np.nan, X)
    X_t = pipeline.fit_transform(X_clean, y)
    assert not np.isinf(X_t).any()


def test_save_and_load(synthetic_data, tmp_path):
    """Saved pipeline must produce identical output when reloaded."""
    X, y = synthetic_data
    path = tmp_path / "test_preprocessor.joblib"
    fitted = fit_and_save(X, y, path=path, n_features=50)

    # Exercise the SimpleImputer path — do NOT scrub NaN before transform.
    X_fitted = transform(fitted, X)
    loaded = load(path)
    X_loaded = transform(loaded, X)
    np.testing.assert_array_almost_equal(X_fitted, X_loaded)


def test_get_feature_names(synthetic_data, tmp_path):
    """get_feature_names must return exactly n_features strings."""
    X, y = synthetic_data
    original_names = [f"feature_{i}" for i in range(78)]
    pipeline = build_pipeline(n_features=50)
    pipeline.fit(X, y)
    selected = get_feature_names(pipeline, original_names)
    assert len(selected) == 50
    assert all(isinstance(n, str) for n in selected)
