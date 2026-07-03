from __future__ import annotations

import io
import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.dependencies import CurrentUser
from api.database import get_db
from api.rate_limit import limiter
from api.services import incident_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/{incident_id}")
@limiter.limit("30/minute")
async def get_report(
    request: Request,
    incident_id: uuid.UUID,
    user: CurrentUser,
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    """Generate and stream a PDF incident report."""
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
    except Exception:
        logger.exception(
            "Report generation failed (incident_id=%s, user=%s, request_id=%s)",
            incident_id,
            user.id,
            getattr(request.state, "request_id", None),
        )
        raise HTTPException(status_code=500, detail="Report generation failed") from None

    logger.info(
        "Report generated (incident_id=%s, user=%s, bytes=%d)",
        incident_id,
        user.id,
        len(pdf_bytes),
    )
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="incident_{incident_id}.pdf"'},
    )
