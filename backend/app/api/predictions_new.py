"""
Anomalies and predictions API endpoints.
"""
from fastapi import APIRouter, Query
from sqlalchemy import select, and_, desc
from datetime import datetime, timedelta
from typing import Optional

from app.core.database import async_session_maker
from app.models.database_models import Anomaly, Flow

router = APIRouter()


@router.get("/anomalies")
async def get_anomalies(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None
):
    """Get detected anomalies."""
    async with async_session_maker() as session:
        # Build query
        query = select(Anomaly, Flow).join(Flow, Anomaly.flow_id == Flow.id)
        
        # Apply filters
        filters = [Anomaly.is_anomaly == True]
        
        if severity:
            filters.append(Anomaly.severity == severity.upper())
        
        if start_time:
            filters.append(Anomaly.timestamp >= start_time)
        
        if end_time:
            filters.append(Anomaly.timestamp <= end_time)
        
        query = query.where(and_(*filters))
        query = query.order_by(desc(Anomaly.timestamp))
        query = query.limit(limit).offset(offset)
        
        result = await session.execute(query)
        rows = result.all()
        
        return {
            "anomalies": [
                {
                    "id": anomaly.id,
                    "timestamp": anomaly.timestamp.isoformat(),
                    "reconstruction_error": anomaly.reconstruction_error,
                    "threshold": anomaly.threshold,
                    "anomaly_score": anomaly.anomaly_score,
                    "severity": anomaly.severity,
                    "model_id": anomaly.model_id,
                    "investigated": anomaly.investigated,
                    "false_positive": anomaly.false_positive,
                    "flow": {
                        "uid": flow.uid,
                        "orig_ip": flow.orig_ip,
                        "orig_port": flow.orig_port,
                        "resp_ip": flow.resp_ip,
                        "resp_port": flow.resp_port,
                        "protocol": flow.protocol,
                        "service": flow.service,
                        "duration": flow.duration,
                        "orig_bytes": flow.orig_bytes,
                        "resp_bytes": flow.resp_bytes,
                        "conn_state": flow.conn_state
                    }
                }
                for anomaly, flow in rows
            ],
            "total": len(rows),
            "limit": limit,
            "offset": offset
        }


@router.get("/anomalies/stats")
async def get_anomaly_stats(
    hours: int = Query(24, ge=1, le=168)
):
    """Get anomaly statistics."""
    start_time = datetime.now() - timedelta(hours=hours)
    
    async with async_session_maker() as session:
        # Get all anomalies in time range
        result = await session.execute(
            select(Anomaly).where(
                and_(
                    Anomaly.is_anomaly == True,
                    Anomaly.timestamp >= start_time
                )
            )
        )
        anomalies = result.scalars().all()
        
        # Calculate statistics
        total = len(anomalies)
        
        # By severity
        severity_counts = {}
        for anomaly in anomalies:
            sev = anomaly.severity or 'UNKNOWN'
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        # Investigated/false positives
        investigated = sum(1 for a in anomalies if a.investigated)
        false_positives = sum(1 for a in anomalies if a.false_positive)
        
        return {
            "time_range_hours": hours,
            "start_time": start_time.isoformat(),
            "total_anomalies": total,
            "by_severity": severity_counts,
            "investigated": investigated,
            "false_positives": false_positives,
            "true_positives": investigated - false_positives
        }


@router.patch("/anomalies/{anomaly_id}")
async def update_anomaly(
    anomaly_id: int,
    investigated: Optional[bool] = None,
    false_positive: Optional[bool] = None,
    notes: Optional[str] = None
):
    """Update anomaly investigation status."""
    async with async_session_maker() as session:
        result = await session.execute(
            select(Anomaly).where(Anomaly.id == anomaly_id)
        )
        anomaly = result.scalars().first()
        
        if not anomaly:
            from fastapi import HTTPException
            raise HTTPException(status_code=404, detail="Anomaly not found")
        
        if investigated is not None:
            anomaly.investigated = investigated
        
        if false_positive is not None:
            anomaly.false_positive = false_positive
        
        if notes is not None:
            anomaly.notes = notes
        
        await session.commit()
        
        return {
            "id": anomaly.id,
            "investigated": anomaly.investigated,
            "false_positive": anomaly.false_positive,
            "notes": anomaly.notes
        }
