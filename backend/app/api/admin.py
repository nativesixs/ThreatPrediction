from fastapi import APIRouter, HTTPException, Query, Depends
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.database_models import Prediction, TrafficLog, ModelMetrics


router = APIRouter(prefix="/admin", tags=["admin"])


@router.delete("/clear-all")
async def clear_all_data(
    confirm: bool = Query(default=False),
    db: AsyncSession = Depends(get_db)
):
    if not confirm:
        raise HTTPException(
            status_code=400, 
            detail="Must set confirm=true to delete data. This action cannot be undone!"
        )
    
    pred_count_query = select(func.count(Prediction.id))
    result = await db.execute(pred_count_query)
    total_predictions = result.scalar() or 0
    
    traffic_count_query = select(func.count(TrafficLog.id))
    result = await db.execute(traffic_count_query)
    total_traffic = result.scalar() or 0
    
    await db.execute(delete(Prediction))
    await db.execute(delete(TrafficLog))
    await db.commit()
    
    return {
        "message": "All data cleared successfully",
        "predictions_deleted": total_predictions,
        "traffic_logs_deleted": total_traffic,
        "total_deleted": total_predictions + total_traffic
    }


@router.get("/stats")
async def get_database_stats(db: AsyncSession = Depends(get_db)):

    pred_count_query = select(func.count(Prediction.id))
    result = await db.execute(pred_count_query)
    total_predictions = result.scalar() or 0
    
    traffic_count_query = select(func.count(TrafficLog.id))
    result = await db.execute(traffic_count_query)
    total_traffic = result.scalar() or 0

    attack_count_query = select(func.count(Prediction.id)).where(Prediction.is_attack == True)
    result = await db.execute(attack_count_query)
    total_attacks = result.scalar() or 0

    metrics_count_query = select(func.count(ModelMetrics.id))
    result = await db.execute(metrics_count_query)
    total_metrics = result.scalar() or 0
    
    return {
        "total_predictions": total_predictions,
        "total_traffic_logs": total_traffic,
        "total_attacks": total_attacks,
        "total_metrics": total_metrics,
        "benign_count": total_predictions - total_attacks
    }
