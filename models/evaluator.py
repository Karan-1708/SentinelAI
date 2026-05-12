"""
Model evaluation utilities.

Generates classification metrics, confusion matrices, and ROC curves.
All metrics are logged to MLflow by trainer.py.
Primary metric: macro F1 (not accuracy — misleading at 80/20 class imbalance).
"""

from __future__ import annotations

import io
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
        confusion_matrix (ndarray), roc_auc (optional)
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
        "macro_f1": macro_f1,
        "accuracy": accuracy,
        "classification_report": report,
        "confusion_matrix": cm,
    }

    # ROC-AUC (only when probability scores available)
    if y_proba is not None and len(np.unique(y_true)) > 1:
        try:
            roc_auc = roc_auc_score(
                y_true, y_proba,
                multi_class="ovr",
                average="macro",
            )
            result["roc_auc"] = roc_auc
        except Exception:
            result["roc_auc"] = None

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
