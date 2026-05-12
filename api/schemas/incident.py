from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class IncidentSummary(BaseModel):
    id: uuid.UUID
    created_at: Optional[datetime]
    severity: str
    threat_label: str
    confidence: float
    anomaly_score: float
    source_ip: Optional[str]
    dest_ip: Optional[str]
    status: str
    mitre_techniques: list[dict]

    model_config = {"from_attributes": True}


class IncidentDetail(IncidentSummary):
    shap_values: Optional[list]
    raw_features: dict

    model_config = {"from_attributes": True}


class IncidentListResponse(BaseModel):
    items: list[IncidentSummary]
    total: int
    page: int
    page_size: int
