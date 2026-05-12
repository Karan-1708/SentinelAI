"""
SHAP TreeExplainer for XGBoost multi-class classifier.

Key decisions:
  - feature_perturbation="interventional": more accurate for correlated features
    (CICIDS-2017 has correlated packet length features).
    Default "tree_path_dependent" can misattribute importance for correlated inputs.
  - Multi-class output: shap_values shape = (n_classes, n_rows, n_features)
    Index [predicted_class_idx] to get contributions for the predicted class.
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
    ) -> None:
        import shap
        self.explainer = shap.TreeExplainer(
            xgb_model,
            feature_perturbation="interventional",
        )
        self.feature_names = feature_names

    def explain_prediction(self, X_row: np.ndarray) -> dict:
        """
        Generate SHAP explanation for a single prediction.

        Args:
            X_row: shape (1, n_features) — already preprocessed

        Returns:
            dict with:
              base_value: float — model's baseline output for predicted class
              feature_contributions: list of {feature, shap_value, feature_value}
              top_features: top 10 by |shap_value|
        """
        shap_values = self.explainer.shap_values(X_row)

        # For multi-class XGBoost: shape (n_classes, n_rows, n_features)
        if isinstance(shap_values, list):
            # Older SHAP returns list of arrays
            n_classes = len(shap_values)
            # Determine predicted class by summing SHAP + base value
            base_values = self.explainer.expected_value
            if not hasattr(base_values, "__len__"):
                base_values = [base_values] * n_classes

            class_totals = [
                float(base_values[i]) + float(shap_values[i][0].sum())
                for i in range(n_classes)
            ]
            predicted_class_idx = int(np.argmax(class_totals))
            class_shap = shap_values[predicted_class_idx][0]
            base_value = float(base_values[predicted_class_idx])
        else:
            # Newer SHAP: ndarray shape (n_rows, n_features, n_classes)
            if shap_values.ndim == 3:
                predicted_class_idx = int(np.argmax(shap_values[0].sum(axis=0)))
                class_shap = shap_values[0, :, predicted_class_idx]
            else:
                class_shap = shap_values[0]
                predicted_class_idx = 0

            ev = self.explainer.expected_value
            base_value = float(ev[predicted_class_idx]) if hasattr(ev, "__len__") else float(ev)

        contributions = [
            {
                "feature": name,
                "shap_value": float(val),
                "feature_value": float(X_row[0][i]) if i < X_row.shape[1] else 0.0,
            }
            for i, (name, val) in enumerate(zip(self.feature_names, class_shap))
        ]

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

    def waterfall_figure(
        self,
        X_row: np.ndarray,
        max_display: int = 15,
    ):
        """
        Generate a matplotlib Figure of the SHAP waterfall plot.
        Returned figure is embedded in PDF reports by report_generator.py.
        """
        import matplotlib.pyplot as plt
        import shap

        shap_values = self.explainer.shap_values(X_row)

        if isinstance(shap_values, list):
            # Use first class for waterfall (simplified)
            sv = shap_values[0][0]
            ev = self.explainer.expected_value
            base = float(ev[0]) if hasattr(ev, "__len__") else float(ev)
        else:
            sv = shap_values[0] if shap_values.ndim == 2 else shap_values[0, :, 0]
            ev = self.explainer.expected_value
            base = float(ev[0]) if hasattr(ev, "__len__") else float(ev)

        explanation = shap.Explanation(
            values=sv,
            base_values=base,
            data=X_row[0],
            feature_names=self.feature_names,
        )

        fig, ax = plt.subplots(figsize=(10, 6))
        shap.plots.waterfall(explanation, max_display=max_display, show=False)
        plt.tight_layout()
        return plt.gcf()
