from fastapi import APIRouter, HTTPException, Query, Depends
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.database_models import Anomaly, Flow, Model


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
    
    anomaly_count_query = select(func.count(Anomaly.id))
    result = await db.execute(anomaly_count_query)
    total_anomalies = result.scalar() or 0
    
    flow_count_query = select(func.count(Flow.id))
    result = await db.execute(flow_count_query)
    total_flows = result.scalar() or 0
    
    await db.execute(delete(Anomaly))
    await db.execute(delete(Flow))
    await db.commit()
    
    return {
        "message": "All data cleared successfully",
        "anomalies_deleted": total_anomalies,
        "flows_deleted": total_flows,
        "total_deleted": total_anomalies + total_flows
    }


@router.get("/stats")
async def get_database_stats(db: AsyncSession = Depends(get_db)):

    anomaly_count_query = select(func.count(Anomaly.id))
    result = await db.execute(anomaly_count_query)
    total_anomalies = result.scalar() or 0
    
    flow_count_query = select(func.count(Flow.id))
    result = await db.execute(flow_count_query)
    total_flows = result.scalar() or 0

    critical_count_query = select(func.count(Anomaly.id)).where(Anomaly.severity == 'CRITICAL')
    result = await db.execute(critical_count_query)
    total_critical = result.scalar() or 0

    model_count_query = select(func.count(Model.id))
    result = await db.execute(model_count_query)
    total_models = result.scalar() or 0
    
    return {
        "total_anomalies": total_anomalies,
        "total_flows": total_flows,
        "total_critical": total_critical,
        "total_models": total_models,
        "normal_flows": total_flows - total_anomalies
    }
