"""
Traffic and flows API endpoints.
"""
from fastapi import APIRouter, Query
from sqlalchemy import select, and_, desc
from datetime import datetime, timedelta
from typing import Optional

from app.core.database import async_session_maker
from app.models.database_models import Flow

router = APIRouter()


@router.get("/flows")
async def get_flows(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    protocol: Optional[str] = None,
    is_normal: Optional[bool] = None
):
    """Get network flows."""
    async with async_session_maker() as session:
        # Build query
        query = select(Flow)
        
        # Apply filters
        filters = []
        
        if start_time:
            filters.append(Flow.timestamp >= start_time)
        
        if end_time:
            filters.append(Flow.timestamp <= end_time)
        
        if protocol:
            filters.append(Flow.protocol == protocol.lower())
        
        if is_normal is not None:
            filters.append(Flow.is_normal == is_normal)
        
        if filters:
            query = query.where(and_(*filters))
        
        query = query.order_by(desc(Flow.timestamp))
        query = query.limit(limit).offset(offset)
        
        result = await session.execute(query)
        flows = result.scalars().all()
        
        return {
            "flows": [
                {
                    "id": flow.id,
                    "timestamp": flow.timestamp.isoformat(),
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
                    "orig_pkts": flow.orig_pkts,
                    "resp_pkts": flow.resp_pkts,
                    "conn_state": flow.conn_state,
                    "is_normal": flow.is_normal
                }
                for flow in flows
            ],
            "total": len(flows),
            "limit": limit,
            "offset": offset
        }


@router.get("/flows/stats")
async def get_flow_stats(
    hours: int = Query(24, ge=1, le=168)
):
    """Get flow statistics."""
    start_time = datetime.now() - timedelta(hours=hours)
    
    async with async_session_maker() as session:
        result = await session.execute(
            select(Flow).where(Flow.timestamp >= start_time)
        )
        flows = result.scalars().all()
        
        # Calculate statistics
        total = len(flows)
        normal = sum(1 for f in flows if f.is_normal)
        anomalous = total - normal
        
        # By protocol
        protocol_counts = {}
        for flow in flows:
            proto = flow.protocol or 'unknown'
            protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
        
        # Traffic volume
        total_bytes = sum((f.orig_bytes or 0) + (f.resp_bytes or 0) for f in flows)
        total_packets = sum((f.orig_pkts or 0) + (f.resp_pkts or 0) for f in flows)
        
        return {
            "time_range_hours": hours,
            "start_time": start_time.isoformat(),
            "total_flows": total,
            "normal_flows": normal,
            "anomalous_flows": anomalous,
            "by_protocol": protocol_counts,
            "total_bytes": total_bytes,
            "total_packets": total_packets
        }
