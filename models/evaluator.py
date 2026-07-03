"""
Model evaluation utilities.

Generates classification metrics, confusion matrices, and ROC curves.
All metrics are logged to MLflow by trainer.py.
Primary metric: macro F1 (not accuracy — misleading at 80/20 class imbalance).
"""

from __future__ import annotations

import io
import logging
import math
from typing import Optional

import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    classification_report,
    confusion_matrix,
    f1_score,
    roc_auc_score,
)

logger = logging.getLogger(__name__)


def _binary_roc_auc(y_true: np.ndarray, y_proba: np.ndarray) -> float:
    # For binary problems ``y_proba`` can be either a 1D vector of positive-class
    # scores or a 2D (n, 2) matrix. We normalise to the vector form.
    if y_proba.ndim == 2:
        if y_proba.shape[1] != 2:
            raise ValueError(f"Expected 2-column proba for binary AUC, got {y_proba.shape}")
        return float(roc_auc_score(y_true, y_proba[:, 1]))
    return float(roc_auc_score(y_true, y_proba))


def _multiclass_roc_auc_ovr(y_true: np.ndarray, y_proba: np.ndarray, n_classes: int) -> float:
    if y_proba.ndim != 2:
        raise ValueError(f"Multi-class AUC needs 2D proba; got shape {y_proba.shape}")
    if y_proba.shape[1] != n_classes:
        raise ValueError(
            f"proba has {y_proba.shape[1]} columns but y_true has {n_classes} unique classes"
        )
    return float(roc_auc_score(y_true, y_proba, multi_class="ovr", average="macro"))


def roc_auc(y_true: np.ndarray, y_proba: np.ndarray) -> float:
    """Return macro-ovr ROC-AUC (binary or multi-class).

    Returns ``nan`` and logs the reason on any failure. Never swallows to
    ``None`` — that hid metric collection failures in the training pipeline.
    """
    n_classes = int(len(np.unique(y_true)))
    if n_classes < 2:
        logger.warning("ROC-AUC undefined: only one class present in y_true")
        return math.nan
    try:
        if n_classes == 2:
            return _binary_roc_auc(y_true, y_proba)
        return _multiclass_roc_auc_ovr(y_true, y_proba, n_classes)
    except ValueError as exc:
        logger.warning("ROC-AUC could not be computed: %s", exc)
        return math.nan


def evaluate(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_proba: Optional[np.ndarray] = None,
    class_names: Optional[list[str]] = None,
) -> dict:
    """
    Compute a full evaluation suite.

    Returns a dict with:
        macro_f1, accuracy, classification_report (dict),
        confusion_matrix (ndarray), roc_auc (float, may be nan)
    """
    macro_f1 = f1_score(y_true, y_pred, average="macro", zero_division=0)
    accuracy = float(np.mean(y_true == y_pred))
    report = classification_report(
        y_true, y_pred,
        target_names=class_names,
        output_dict=True,
        zero_division=0,
    )
    cm = confusion_matrix(y_true, y_pred)

    result: dict = {
        "macro_f1": float(macro_f1),
        "accuracy": accuracy,
        "classification_report": report,
        "confusion_matrix": cm,
    }

    if y_proba is not None:
        result["roc_auc"] = roc_auc(y_true, y_proba)

    return result


def confusion_matrix_figure(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    class_names: Optional[list[str]] = None,
) -> plt.Figure:
    """Return a matplotlib Figure of the normalized confusion matrix."""
    cm = confusion_matrix(y_true, y_pred, normalize="true")
    fig, ax = plt.subplots(figsize=(10, 8))
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=class_names)
    disp.plot(ax=ax, cmap="Blues", colorbar=True, xticks_rotation=45)
    ax.set_title("Normalized Confusion Matrix — SentinelAI Threat Classifier")
    plt.tight_layout()
    return fig


def figure_to_bytes(fig: plt.Figure, fmt: str = "png", dpi: int = 150) -> bytes:
    """Serialize a matplotlib Figure to bytes for MLflow artifact logging."""
    buf = io.BytesIO()
    fig.savefig(buf, format=fmt, dpi=dpi, bbox_inches="tight")
    buf.seek(0)
    plt.close(fig)
    return buf.read()
