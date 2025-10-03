from fastapi import APIRouter, HTTPException, Query, Depends
from typing import List, Optional
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.schemas import ModelMetricsResponse
from app.core.database import get_db
from app.models.database_models import ModelMetrics


router = APIRouter(prefix="/metrics", tags=["metrics"])


@router.get("/", response_model=List[ModelMetricsResponse])
async def get_all_metrics(
    limit: int = Query(default=10, le=100),
    model_name: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Get model training/evaluation metrics.
    
    Args:
        limit: Maximum number of metric records to return
        model_name: Filter by model name (None = all)
        db: Database session
        
    Returns:
        List of model metrics
    """
    query = select(ModelMetrics).order_by(desc(ModelMetrics.timestamp))
    
    if model_name:
        query = query.where(ModelMetrics.model_name == model_name)
    
    query = query.limit(limit)
    
    result = await db.execute(query)
    metrics = result.scalars().all()
    
    return metrics


@router.get("/latest", response_model=ModelMetricsResponse)
async def get_latest_metrics(
    model_name: str = Query(..., description="Model name (lstm or cnn)"),
    db: AsyncSession = Depends(get_db)
):
    """
    Get the latest metrics for a specific model.
    
    Args:
        model_name: Model name
        db: Database session
        
    Returns:
        Latest model metrics
    """
    query = (
        select(ModelMetrics)
        .where(ModelMetrics.model_name == model_name)
        .order_by(desc(ModelMetrics.timestamp))
        .limit(1)
    )
    
    result = await db.execute(query)
    metrics = result.scalar_one_or_none()
    
    if not metrics:
        raise HTTPException(
            status_code=404,
            detail=f"No metrics found for model '{model_name}'"
        )
    
    return metrics


@router.get("/compare")
async def compare_models(db: AsyncSession = Depends(get_db)):
    """
    Compare performance of all models.
    
    Args:
        db: Database session
        
    Returns:
        Comparison of model metrics
    """
    query = select(ModelMetrics).order_by(desc(ModelMetrics.timestamp))
    result = await db.execute(query)
    all_metrics = result.scalars().all()

    models_dict = {}
    for metric in all_metrics:
        if metric.model_name not in models_dict:
            models_dict[metric.model_name] = {
                "model_name": metric.model_name,
                "accuracy": metric.accuracy,
                "precision": metric.precision,
                "recall": metric.recall,
                "f1_score": metric.f1_score,
                "timestamp": metric.timestamp.isoformat() if metric.timestamp else None
            }
    
    return {
        "models": list(models_dict.values()),
        "best_accuracy": max(
            (m["accuracy"] for m in models_dict.values() if m["accuracy"]),
            default=0
        ),
        "best_f1": max(
            (m["f1_score"] for m in models_dict.values() if m["f1_score"]),
            default=0
        )
    }
