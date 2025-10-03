from fastapi import APIRouter, HTTPException, Query, Depends
from typing import List, Optional
from datetime import datetime, timedelta
from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.schemas import TrafficLogResponse
from app.core.database import get_db
from app.models.database_models import TrafficLog


router = APIRouter(prefix="/traffic", tags=["traffic"])


@router.get("", response_model=List[TrafficLogResponse])
async def get_traffic_logs(
    limit: int = Query(default=100, le=1000),
    skip: int = Query(default=0, ge=0),
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    protocol: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Get traffic logs with optional filtering.
    
    Args:
        limit: Maximum number of logs to return
        skip: Number of logs to skip
        source_ip: Filter by source IP
        destination_ip: Filter by destination IP
        protocol: Filter by protocol
        db: Database session
        
    Returns:
        List of traffic logs
    """
    query = select(TrafficLog).order_by(desc(TrafficLog.timestamp))
    
    if source_ip:
        query = query.where(TrafficLog.source_ip == source_ip)
    
    if destination_ip:
        query = query.where(TrafficLog.destination_ip == destination_ip)
    
    if protocol:
        query = query.where(TrafficLog.protocol == protocol)
    
    query = query.offset(skip).limit(limit)
    
    result = await db.execute(query)
    logs = result.scalars().all()
    
    return logs


@router.get("/recent", response_model=List[TrafficLogResponse])
async def get_recent_traffic(
    minutes: int = Query(default=5, ge=1, le=60),
    db: AsyncSession = Depends(get_db)
):
    """
    Get traffic logs from the last N minutes.
    
    Args:
        minutes: Number of minutes to look back
        db: Database session
        
    Returns:
        List of recent traffic logs
    """
    cutoff_time = datetime.utcnow() - timedelta(minutes=minutes)
    
    query = (
        select(TrafficLog)
        .where(TrafficLog.timestamp >= cutoff_time)
        .order_by(desc(TrafficLog.timestamp))
    )
    
    result = await db.execute(query)
    logs = result.scalars().all()
    
    return logs


@router.get("/stats")
async def get_traffic_stats(
    minutes: int = Query(default=60, ge=1, le=1440),
    db: AsyncSession = Depends(get_db)
):
    """
    Get traffic statistics for the last N minutes.
    
    Args:
        minutes: Number of minutes to look back
        db: Database session
        
    Returns:
        Dictionary of traffic statistics
    """
    cutoff_time = datetime.utcnow() - timedelta(minutes=minutes)
    
    # Total packet count
    count_query = select(func.count(TrafficLog.id)).where(
        TrafficLog.timestamp >= cutoff_time
    )
    result = await db.execute(count_query)
    total_packets = result.scalar()
    
    # Protocol distribution
    protocol_query = (
        select(TrafficLog.protocol, func.count(TrafficLog.id))
        .where(TrafficLog.timestamp >= cutoff_time)
        .group_by(TrafficLog.protocol)
    )
    result = await db.execute(protocol_query)
    protocols = dict(result.all())
    
    # Top source IPs
    source_query = (
        select(TrafficLog.source_ip, func.count(TrafficLog.id))
        .where(TrafficLog.timestamp >= cutoff_time)
        .group_by(TrafficLog.source_ip)
        .order_by(desc(func.count(TrafficLog.id)))
        .limit(10)
    )
    result = await db.execute(source_query)
    top_sources = [{"ip": ip, "count": count} for ip, count in result.all()]
    
    # Top destination IPs
    dest_query = (
        select(TrafficLog.destination_ip, func.count(TrafficLog.id))
        .where(TrafficLog.timestamp >= cutoff_time)
        .group_by(TrafficLog.destination_ip)
        .order_by(desc(func.count(TrafficLog.id)))
        .limit(10)
    )
    result = await db.execute(dest_query)
    top_destinations = [{"ip": ip, "count": count} for ip, count in result.all()]
    
    return {
        "time_window_minutes": minutes,
        "total_packets": total_packets,
        "protocols": protocols,
        "top_sources": top_sources,
        "top_destinations": top_destinations
    }


@router.get("/{log_id}", response_model=TrafficLogResponse)
async def get_traffic_log(
    log_id: int,
    db: AsyncSession = Depends(get_db)
):
    """
    Get a specific traffic log by ID.
    
    Args:
        log_id: Traffic log ID
        db: Database session
        
    Returns:
        Traffic log details
    """
    query = select(TrafficLog).where(TrafficLog.id == log_id)
    result = await db.execute(query)
    log = result.scalar_one_or_none()
    
    if not log:
        raise HTTPException(status_code=404, detail="Traffic log not found")
    
    return log


@router.delete("/clear")
async def clear_traffic_logs(
    confirm: bool = Query(default=False),
    db: AsyncSession = Depends(get_db)
):
    """
    Clear all traffic log data from the database.
    
    Args:
        confirm: Must be True to actually delete data
        db: Database session
        
    Returns:
        Dictionary with deletion results
    """
    from sqlalchemy import delete
    
    if not confirm:
        raise HTTPException(
            status_code=400, 
            detail="Must set confirm=true to delete data"
        )
    
    # Count records before deletion
    count_query = select(func.count(TrafficLog.id))
    result = await db.execute(count_query)
    total_logs = result.scalar() or 0
    
    # Delete all traffic logs
    delete_query = delete(TrafficLog)
    await db.execute(delete_query)
    await db.commit()
    
    return {
        "message": "All traffic logs cleared successfully",
        "deleted_count": total_logs
    }
