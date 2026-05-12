from __future__ import annotations

import uuid
from typing import Optional

from pydantic import BaseModel


class PredictionResponse(BaseModel):
    incident_id: uuid.UUID
    threat_label: str
    severity: str
    confidence: float
    anomaly_score: float
    is_anomaly: bool
    mitre_techniques: list[dict]
    top_shap_features: list[dict]


class ShapFeature(BaseModel):
    feature: str
    shap_value: float
    feature_value: float
