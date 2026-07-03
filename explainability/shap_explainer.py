"""
SHAP TreeExplainer for the XGBoost multi-class classifier.

Two ``feature_perturbation`` modes are supported:

  ``interventional`` — requires a background dataset; more accurate under
      feature correlation (CICIDS-2017 has correlated packet-length features).
  ``tree_path_dependent`` — fast, requires no background, but can misattribute
      importance for correlated inputs. Used as the fallback when no
      background is supplied so the platform still works out of the box.

Multi-class handling adapts to both SHAP output layouts:

  * old (< 0.40): ``shap_values`` is a ``list[ndarray]`` (per class)
  * new (>= 0.40): ``shap_values`` is a single ``ndarray`` shape
      ``(n_rows, n_features, n_classes)``.

The predicted class index is always derived from the model — never estimated
from SHAP sums — so the explanation cannot desynchronise from the model's
own argmax.
"""

from __future__ import annotations

import logging
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)


class SHAPExplainer:
    def __init__(
        self,
        xgb_model,
        feature_names: list[str],
        background: Optional[np.ndarray] = None,
    ) -> None:
        import shap

        self._model = xgb_model
        self.feature_names = feature_names

        if background is not None and len(background):
            self.explainer = shap.TreeExplainer(
                xgb_model,
                data=background,
                feature_perturbation="interventional",
            )
            logger.info(
                "SHAP TreeExplainer initialised (interventional, background=%d rows)",
                len(background),
            )
        else:
            self.explainer = shap.TreeExplainer(
                xgb_model,
                feature_perturbation="tree_path_dependent",
            )
            logger.info(
                "SHAP TreeExplainer initialised (tree_path_dependent; no background)"
            )

    # ── Helpers ────────────────────────────────────────────────────────

    def _predicted_class_idx(self, X_row: np.ndarray) -> int:
        """Ask the model itself for the winning class, not SHAP sums."""
        try:
            proba = self._model.predict_proba(X_row)
            return int(np.argmax(proba[0]))
        except Exception:
            logger.exception("predict_proba failed; falling back to class 0")
            return 0

    def _class_shap_and_base(
        self, X_row: np.ndarray, predicted_class_idx: int
    ) -> tuple[np.ndarray, float]:
        shap_values = self.explainer.shap_values(X_row)
        ev = self.explainer.expected_value

        if isinstance(shap_values, list):
            n_classes = len(shap_values)
            idx = predicted_class_idx if 0 <= predicted_class_idx < n_classes else 0
            base_values = ev if hasattr(ev, "__len__") else [ev] * n_classes
            return np.asarray(shap_values[idx][0]), float(base_values[idx])

        arr = np.asarray(shap_values)
        if arr.ndim == 3:
            n_classes = arr.shape[-1]
            idx = predicted_class_idx if 0 <= predicted_class_idx < n_classes else 0
            base = float(ev[idx]) if hasattr(ev, "__len__") else float(ev)
            return arr[0, :, idx], base
        # Binary / single-output
        base = float(ev[0]) if hasattr(ev, "__len__") else float(ev)
        return arr[0], base

    # ── Public API ─────────────────────────────────────────────────────

    def explain_prediction(self, X_row: np.ndarray) -> dict:
        """SHAP explanation for a single prediction.

        Args:
            X_row: shape (1, n_features) — already preprocessed.

        Returns a dict with ``base_value``, ``predicted_class_idx``,
        ``feature_contributions``, ``top_features``.
        """
        predicted_class_idx = self._predicted_class_idx(X_row)
        class_shap, base_value = self._class_shap_and_base(X_row, predicted_class_idx)

        n_features = X_row.shape[1]
        contributions = []
        for i, name in enumerate(self.feature_names):
            if i >= n_features or i >= len(class_shap):
                break
            contributions.append(
                {
                    "feature": name,
                    "shap_value": float(class_shap[i]),
                    "feature_value": float(X_row[0][i]),
                }
            )

        top_features = sorted(
            [{"feature": c["feature"], "shap_value": c["shap_value"]} for c in contributions],
            key=lambda x: abs(x["shap_value"]),
            reverse=True,
        )[:10]

        return {
            "base_value": base_value,
            "predicted_class_idx": predicted_class_idx,
            "feature_contributions": contributions,
            "top_features": top_features,
        }

    def waterfall_figure(self, X_row: np.ndarray, max_display: int = 15):
        """Return a matplotlib Figure of the SHAP waterfall for the predicted class."""
        import matplotlib.pyplot as plt
        import shap

        predicted_class_idx = self._predicted_class_idx(X_row)
        class_shap, base = self._class_shap_and_base(X_row, predicted_class_idx)

        explanation = shap.Explanation(
            values=class_shap,
            base_values=base,
            data=X_row[0],
            feature_names=self.feature_names,
        )

        fig, _ax = plt.subplots(figsize=(10, 6))
        shap.plots.waterfall(explanation, max_display=max_display, show=False)
        plt.tight_layout()
        return plt.gcf()
