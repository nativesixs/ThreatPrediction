from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional
from datetime import datetime, timedelta

from app.schemas.schemas import (
    PredictionResponse,
    ModelMetricsResponse
)
from app.core.database import get_db
from app.models.database_models import Prediction, ModelMetrics
from app.services.prediction_service import get_prediction_service
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import Depends


router = APIRouter(prefix="/predictions", tags=["predictions"])


@router.get("", response_model=List[PredictionResponse])
async def get_predictions(
    limit: int = Query(default=100, le=1000),
    skip: int = Query(default=0, ge=0),
    is_attack: Optional[bool] = None,
    model_name: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Get prediction history with optional filtering.
    
    Args:
        limit: Maximum number of predictions to return
        skip: Number of predictions to skip
        is_attack: Filter by attack/benign (None = all)
        model_name: Filter by model name (None = all)
        db: Database session
        
    Returns:
        List of predictions
    """
    query = select(Prediction).order_by(desc(Prediction.timestamp))
    
    if is_attack is not None:
        query = query.where(Prediction.is_attack == is_attack)
    
    if model_name:
        query = query.where(Prediction.model_name == model_name)
    
    query = query.offset(skip).limit(limit)
    
    result = await db.execute(query)
    predictions = result.scalars().all()
    
    return predictions


@router.get("/recent", response_model=List[PredictionResponse])
async def get_recent_predictions(
    minutes: int = Query(default=5, ge=1, le=60),
    db: AsyncSession = Depends(get_db)
):
    """
    Get predictions from the last N minutes.
    
    Args:
        minutes: Number of minutes to look back
        db: Database session
        
    Returns:
        List of recent predictions
    """
    cutoff_time = datetime.utcnow() - timedelta(minutes=minutes)
    
    query = (
        select(Prediction)
        .where(Prediction.timestamp >= cutoff_time)
        .order_by(desc(Prediction.timestamp))
    )
    
    result = await db.execute(query)
    predictions = result.scalars().all()
    
    return predictions


@router.get("/stats")
async def get_prediction_stats(
    minutes: int = Query(default=60, ge=1, le=1440),
    db: AsyncSession = Depends(get_db)
):
    """
    Get prediction statistics for the last N minutes.
    
    Args:
        minutes: Number of minutes to look back
        db: Database session
        
    Returns:
        Dictionary of prediction statistics
    """
    from sqlalchemy import func
    from app.models.database_models import TrafficLog
    
    cutoff_time = datetime.utcnow() - timedelta(minutes=minutes)
    
    # Total predictions
    count_query = select(func.count(Prediction.id)).where(
        Prediction.timestamp >= cutoff_time
    )
    result = await db.execute(count_query)
    total_predictions = result.scalar() or 0
    
    # Attack predictions
    attack_query = select(func.count(Prediction.id)).where(
        Prediction.timestamp >= cutoff_time,
        Prediction.is_attack == True
    )
    result = await db.execute(attack_query)
    attack_count = result.scalar() or 0
    
    # Total packets (from traffic logs)
    packet_query = select(func.count(TrafficLog.id)).where(
        TrafficLog.timestamp >= cutoff_time
    )
    result = await db.execute(packet_query)
    total_packets = result.scalar() or 0
    
    # Attack types distribution
    attack_types_query = (
        select(Prediction.predicted_class, func.count(Prediction.id))
        .where(
            Prediction.timestamp >= cutoff_time,
            Prediction.is_attack == True
        )
        .group_by(Prediction.predicted_class)
    )
    result = await db.execute(attack_types_query)
    attack_types = dict(result.all())
    
    return {
        "time_window_minutes": minutes,
        "total_predictions": total_predictions,
        "total_attacks": attack_count,
        "total_packets": total_packets,
        "benign_count": total_predictions - attack_count,
        "attack_types": attack_types
    }


@router.get("/attacks", response_model=List[PredictionResponse])
async def get_attack_predictions(
    limit: int = Query(default=100, le=1000),
    db: AsyncSession = Depends(get_db)
):
    """
    Get only attack predictions.
    
    Args:
        limit: Maximum number of predictions to return
        db: Database session
        
    Returns:
        List of attack predictions
    """
    query = (
        select(Prediction)
        .where(Prediction.is_attack == True)
        .order_by(desc(Prediction.timestamp))
        .limit(limit)
    )
    
    result = await db.execute(query)
    predictions = result.scalars().all()
    
    return predictions


@router.get("/attacks/detailed")
async def get_detailed_attacks(
    limit: int = Query(default=100, le=1000),
    db: AsyncSession = Depends(get_db)
):
    """
    Get attack predictions with detailed packet information.
    
    Args:
        limit: Maximum number of predictions to return
        db: Database session
        
    Returns:
        List of attack predictions with packet details
    """
    from sqlalchemy.orm import selectinload
    from app.models.database_models import TrafficLog
    
    query = (
        select(Prediction)
        .where(Prediction.is_attack == True)
        .order_by(desc(Prediction.timestamp))
        .limit(limit)
    )
    
    result = await db.execute(query)
    predictions = result.scalars().all()
    
    # Fetch related traffic logs
    detailed_results = []
    for pred in predictions:
        traffic_log = None
        if pred.traffic_log_id:
            log_query = select(TrafficLog).where(TrafficLog.id == pred.traffic_log_id)
            log_result = await db.execute(log_query)
            traffic_log = log_result.scalar_one_or_none()
        
        detailed_results.append({
            "id": pred.id,
            "timestamp": pred.timestamp,
            "predicted_class": pred.predicted_class,
            "confidence_score": pred.confidence_score,
            "severity": pred.severity,
            "model_version": pred.model_version,
            "packet_info": {
                "source_ip": traffic_log.source_ip if traffic_log else "unknown",
                "destination_ip": traffic_log.destination_ip if traffic_log else "unknown",
                "source_port": traffic_log.source_port if traffic_log else 0,
                "destination_port": traffic_log.destination_port if traffic_log else 0,
                "protocol": traffic_log.protocol if traffic_log else "unknown",
                "packet_length": traffic_log.packet_length if traffic_log else 0,
            }
        })
    
    return detailed_results


@router.get("/{prediction_id}", response_model=PredictionResponse)
async def get_prediction(
    prediction_id: int,
    db: AsyncSession = Depends(get_db)
):
    """
    Get a specific prediction by ID.
    
    Args:
        prediction_id: Prediction ID
        db: Database session
        
    Returns:
        Prediction details
    """
    query = select(Prediction).where(Prediction.id == prediction_id)
    result = await db.execute(query)
    prediction = result.scalar_one_or_none()
    
    if not prediction:
        raise HTTPException(status_code=404, detail="Prediction not found")
    
    return prediction


@router.delete("/clear")
async def clear_predictions(
    confirm: bool = Query(default=False),
    db: AsyncSession = Depends(get_db)
):
    """
    Clear all prediction data from the database.
    
    Args:
        confirm: Must be True to actually delete data
        db: Database session
        
    Returns:
        Dictionary with deletion results
    """
    from sqlalchemy import delete, func
    
    if not confirm:
        raise HTTPException(
            status_code=400, 
            detail="Must set confirm=true to delete data"
        )
    
    # Count records before deletion
    count_query = select(func.count(Prediction.id))
    result = await db.execute(count_query)
    total_predictions = result.scalar() or 0
    
    # Delete all predictions
    delete_query = delete(Prediction)
    await db.execute(delete_query)
    await db.commit()
    
    return {
        "message": "All predictions cleared successfully",
        "deleted_count": total_predictions
    }


@router.get("/model/info")
async def get_model_info(
    model_type: str = Query(default="lstm")
):
    """
    Get model information including v7 metadata.
    
    Args:
        model_type: Model type (lstm or cnn)
        
    Returns:
        Dictionary with model information
    """
    try:
        service = get_prediction_service(model_type)
        stats = service.get_statistics()
        
        return {
            "model_type": model_type,
            "model_version": stats.get("model_version", "unknown"),
            "device": stats.get("device", "unknown"),
            "num_features": stats.get("num_features", 0),
            "num_classes": stats.get("num_classes", 0),
            "label_mapping": stats.get("label_mapping", {}),
            "confidence_threshold": stats.get("confidence_threshold", 0.70),
            "high_confidence_threshold": stats.get("high_confidence_threshold", 0.85),
            "expected_metrics": stats.get("expected_metrics", {}),
            "predictions_made": stats.get("predictions_made", 0),
            "average_inference_time": stats.get("average_inference_time", 0)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get model info: {str(e)}")


@router.get("/model/stats")
async def get_model_stats(
    model_type: str = Query(default="lstm")
):
    """
    Get model statistics from prediction service.
    
    Args:
        model_type: Model type (lstm or cnn)
        
    Returns:
        Dictionary with model statistics
    """
    try:
        service = get_prediction_service(model_type)
        return service.get_statistics()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get model stats: {str(e)}")
