from __future__ import annotations

import io
import uuid

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from api.database import get_db
from api.services import incident_service

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/{incident_id}")
async def get_report(
    incident_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    """
    Generate and stream a PDF incident report.
    SHAP explanation and MITRE TTP details are pulled from the stored incident.
    """
    incident = await incident_service.get_by_id(db, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    try:
        from explainability.report_generator import IncidentReportGenerator
        generator = IncidentReportGenerator()
        pdf_bytes = generator.generate(
            incident={
                "id": str(incident.id),
                "created_at": incident.created_at,
                "severity": incident.severity,
                "threat_label": incident.threat_label,
                "confidence": incident.confidence,
                "anomaly_score": incident.anomaly_score,
                "source_ip": incident.source_ip,
                "dest_ip": incident.dest_ip,
            },
            shap_data={"feature_contributions": incident.shap_values or []},
            mitre_data=incident.mitre_techniques or [],
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report generation failed: {e}")

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=incident_{incident_id}.pdf"
        },
    )
