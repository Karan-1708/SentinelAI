"""PostgreSQL CRUD operations for incidents."""

from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.models.incident import Incident


async def create(
    db: AsyncSession,
    threat_label: str,
    severity: str,
    confidence: float,
    anomaly_score: float,
    mitre_techniques: list[dict],
    raw_features: dict,
    shap_values: Optional[list],
    source_ip: Optional[str] = None,
    dest_ip: Optional[str] = None,
) -> Incident:
    incident = Incident(
        severity=severity,
        threat_label=threat_label,
        confidence=confidence,
        anomaly_score=anomaly_score,
        mitre_techniques=mitre_techniques,
        raw_features=raw_features,
        shap_values=shap_values,
        source_ip=source_ip,
        dest_ip=dest_ip,
        status="OPEN",
    )
    db.add(incident)
    await db.commit()
    await db.refresh(incident)
    return incident


async def get_by_id(db: AsyncSession, incident_id: uuid.UUID) -> Optional[Incident]:
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    return result.scalar_one_or_none()


async def list_incidents(
    db: AsyncSession,
    page: int = 1,
    page_size: int = 20,
    severity: Optional[str] = None,
    status: Optional[str] = None,
) -> tuple[list[Incident], int]:
    query = select(Incident).order_by(Incident.created_at.desc())
    count_query = select(func.count()).select_from(Incident)

    if severity:
        query = query.where(Incident.severity == severity)
        count_query = count_query.where(Incident.severity == severity)
    if status:
        query = query.where(Incident.status == status)
        count_query = count_query.where(Incident.status == status)

    total_result = await db.execute(count_query)
    total = total_result.scalar_one()

    offset = (page - 1) * page_size
    query = query.offset(offset).limit(page_size)
    result = await db.execute(query)
    items = list(result.scalars().all())

    return items, total


async def update_status(
    db: AsyncSession,
    incident_id: uuid.UUID,
    status: str,
) -> Optional[Incident]:
    incident = await get_by_id(db, incident_id)
    if incident is None:
        return None
    incident.status = status
    await db.commit()
    await db.refresh(incident)
    return incident


async def set_report_path(
    db: AsyncSession,
    incident_id: uuid.UUID,
    path: str,
) -> None:
    incident = await get_by_id(db, incident_id)
    if incident:
        incident.report_path = path
        await db.commit()
