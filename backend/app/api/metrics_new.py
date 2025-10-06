"""
Metrics API endpoints for performance and evaluation.
"""
from fastapi import APIRouter, Query
from sqlalchemy import select
from datetime import datetime, timedelta

from app.core.database import async_session_maker
from app.models.database_models import Model, Flow, Anomaly

router = APIRouter()


@router.get("/metrics/system")
async def get_system_metrics():
    """Get system performance metrics."""
    from app.ml.anomaly_detector import get_anomaly_detector
    
    detector = get_anomaly_detector()
    stats = detector.get_stats() if detector.model else {}
    
    async with async_session_maker() as session:
        # Count records
        result = await session.execute(select(Flow))
        total_flows = len(result.scalars().all())
        
        result = await session.execute(select(Anomaly))
        total_anomalies = len(result.scalars().all())
        
        result = await session.execute(select(Model))
        total_models = len(result.scalars().all())
    
    return {
        "timestamp": datetime.now().isoformat(),
        "database": {
            "total_flows": total_flows,
            "total_anomalies": total_anomalies,
            "total_models": total_models
        },
        "detector": stats
    }


@router.get("/metrics/timeline")
async def get_timeline_metrics(
    hours: int = Query(24, ge=1, le=168),
    interval_minutes: int = Query(60, ge=1, le=1440)
):
    """Get time-series metrics for visualization."""
    start_time = datetime.now() - timedelta(hours=hours)
    
    async with async_session_maker() as session:
        # Get anomalies in time range
        result = await session.execute(
            select(Anomaly).where(Anomaly.timestamp >= start_time).order_by(Anomaly.timestamp)
        )
        anomalies = result.scalars().all()
        
        # Bin by interval
        interval_seconds = interval_minutes * 60
        bins = {}
        
        for anomaly in anomalies:
            # Calculate bin
            seconds_since_start = (anomaly.timestamp - start_time).total_seconds()
            bin_index = int(seconds_since_start // interval_seconds)
            bin_time = start_time + timedelta(seconds=bin_index * interval_seconds)
            
            bin_key = bin_time.isoformat()
            if bin_key not in bins:
                bins[bin_key] = {
                    "timestamp": bin_key,
                    "count": 0,
                    "avg_score": 0.0,
                    "max_score": 0.0,
                    "severity_counts": {}
                }
            
            bins[bin_key]["count"] += 1
            bins[bin_key]["avg_score"] += anomaly.anomaly_score
            bins[bin_key]["max_score"] = max(
                bins[bin_key]["max_score"],
                anomaly.anomaly_score
            )
            
            sev = anomaly.severity or 'UNKNOWN'
            bins[bin_key]["severity_counts"][sev] = \
                bins[bin_key]["severity_counts"].get(sev, 0) + 1
        
        # Calculate averages
        for bin_data in bins.values():
            if bin_data["count"] > 0:
                bin_data["avg_score"] /= bin_data["count"]
        
        # Convert to list and sort
        timeline = sorted(bins.values(), key=lambda x: x["timestamp"])
        
        return {
            "start_time": start_time.isoformat(),
            "interval_minutes": interval_minutes,
            "timeline": timeline
        }
