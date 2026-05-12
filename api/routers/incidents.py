from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from api.database import get_db
from api.schemas.incident import IncidentDetail, IncidentListResponse, IncidentSummary
from api.services import incident_service

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("", response_model=IncidentListResponse)
async def list_incidents(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: Optional[str] = Query(None, pattern="^(CRITICAL|HIGH|MEDIUM|LOW|INFO)$"),
    status: Optional[str] = Query(None, pattern="^(OPEN|IN_PROGRESS|CLOSED)$"),
    db: AsyncSession = Depends(get_db),
) -> IncidentListResponse:
    items, total = await incident_service.list_incidents(
        db, page=page, page_size=page_size, severity=severity, status=status
    )
    return IncidentListResponse(
        items=[IncidentSummary.model_validate(item) for item in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{incident_id}", response_model=IncidentDetail)
async def get_incident(
    incident_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> IncidentDetail:
    incident = await incident_service.get_by_id(db, incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return IncidentDetail.model_validate(incident)


@router.patch("/{incident_id}/status")
async def update_status(
    incident_id: uuid.UUID,
    status: str,
    db: AsyncSession = Depends(get_db),
) -> dict:
    if status not in ("OPEN", "IN_PROGRESS", "CLOSED"):
        raise HTTPException(status_code=400, detail="Invalid status value")
    incident = await incident_service.update_status(db, incident_id, status)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return {"id": str(incident.id), "status": incident.status}
