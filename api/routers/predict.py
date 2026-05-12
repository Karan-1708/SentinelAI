from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from api.database import get_db
from api.schemas.ingest import IngestPayload
from api.schemas.predict import PredictionResponse
from api.services import incident_service
from api.services.broadcast_service import manager

router = APIRouter(prefix="/predict", tags=["predict"])


def get_prediction_service(request: Request):
    """FastAPI dependency: retrieves the PredictionService from app state."""
    svc = getattr(request.app.state, "prediction_service", None)
    if svc is None:
        raise HTTPException(status_code=503, detail="Prediction service not ready")
    return svc


@router.post("", response_model=PredictionResponse)
async def predict(
    payload: IngestPayload,
    db: AsyncSession = Depends(get_db),
    pred_svc=Depends(get_prediction_service),
) -> PredictionResponse:
    """
    Run the full two-stage inference pipeline on a log event:
      IsolationForest → XGBoost → MITRE mapping → SHAP → persist → broadcast
    """
    result = pred_svc.predict(
        features=payload.features,
        source_ip=payload.source_ip,
        dest_ip=payload.dest_ip,
    )

    incident = await incident_service.create(
        db=db,
        threat_label=result["threat_label"],
        severity=result["severity"],
        confidence=result["confidence"],
        anomaly_score=result["anomaly_score"],
        mitre_techniques=result["mitre_techniques"],
        raw_features=result["raw_features"],
        shap_values=result["shap_values"],
        source_ip=payload.source_ip,
        dest_ip=payload.dest_ip,
    )

    await manager.broadcast(incident.to_summary_dict())

    return PredictionResponse(
        incident_id=incident.id,
        threat_label=result["threat_label"],
        severity=result["severity"],
        confidence=result["confidence"],
        anomaly_score=result["anomaly_score"],
        is_anomaly=result["is_anomaly"],
        mitre_techniques=result["mitre_techniques"],
        top_shap_features=result["top_shap_features"],
    )
