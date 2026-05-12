from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import JSON, DateTime, Float, String, func
from sqlalchemy.orm import Mapped, mapped_column

from api.database import Base


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    severity: Mapped[str] = mapped_column(String(16))        # CRITICAL/HIGH/MEDIUM/LOW
    threat_label: Mapped[str] = mapped_column(String(64))    # XGBoost prediction label
    confidence: Mapped[float] = mapped_column(Float)          # max predict_proba
    anomaly_score: Mapped[float] = mapped_column(Float)       # IsolationForest decision_function
    mitre_techniques: Mapped[list] = mapped_column(JSON, default=list)
    source_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    dest_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    raw_features: Mapped[dict] = mapped_column(JSON, default=dict)
    shap_values: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    report_path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="OPEN")

    def to_summary_dict(self) -> dict:
        """Lightweight dict for WebSocket broadcast — no raw features or full SHAP."""
        return {
            "id": str(self.id),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "severity": self.severity,
            "threat_label": self.threat_label,
            "confidence": self.confidence,
            "anomaly_score": self.anomaly_score,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "status": self.status,
            "mitre_techniques": self.mitre_techniques,
        }
