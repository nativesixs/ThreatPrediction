"""
Admin API endpoints for model management and retraining.
"""
from fastapi import APIRouter, BackgroundTasks, HTTPException
from sqlalchemy import select
from datetime import datetime
import logging

from app.core.database import async_session_maker
from app.models.database_models import Model
from app.ml.anomaly_detector import load_detector

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/models")
async def list_models():
    """List all trained models."""
    async with async_session_maker() as session:
        result = await session.execute(
            select(Model).order_by(Model.created_at.desc())
        )
        models = result.scalars().all()
        
        return {
            "models": [
                {
                    "id": model.id,
                    "version": model.version,
                    "created_at": model.created_at.isoformat(),
                    "training_size": model.training_size,
                    "threshold": model.threshold,
                    "validation_loss": model.validation_loss,
                    "is_active": model.is_active
                }
                for model in models
            ]
        }


@router.get("/models/{model_id}")
async def get_model(model_id: int):
    """Get detailed model information."""
    async with async_session_maker() as session:
        result = await session.execute(
            select(Model).where(Model.id == model_id)
        )
        model = result.scalars().first()
        
        if not model:
            raise HTTPException(status_code=404, detail="Model not found")
        
        return {
            "id": model.id,
            "version": model.version,
            "model_type": model.model_type,
            "created_at": model.created_at.isoformat(),
            "training_size": model.training_size,
            "validation_size": model.validation_size,
            "num_features": model.num_features,
            "architecture": model.architecture,
            "threshold": model.threshold,
            "threshold_percentile": model.threshold_percentile,
            "validation_loss": model.validation_loss,
            "training_duration_seconds": model.training_duration_seconds,
            "is_active": model.is_active,
            "metadata": model.metadata
        }


@router.post("/models/{model_id}/activate")
async def activate_model(model_id: int):
    """Activate a specific model."""
    async with async_session_maker() as session:
        # Get target model
        result = await session.execute(
            select(Model).where(Model.id == model_id)
        )
        target_model = result.scalars().first()
        
        if not target_model:
            raise HTTPException(status_code=404, detail="Model not found")
        
        # Deactivate all models
        result = await session.execute(select(Model))
        all_models = result.scalars().all()
        for model in all_models:
            model.is_active = False
        
        # Activate target model
        target_model.is_active = True
        await session.commit()
        
        # Reload detector
        try:
            load_detector(model_id=target_model.id)
            logger.info(f"Activated and loaded model {model_id}")
        except Exception as e:
            logger.error(f"Failed to load model {model_id}: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to load model: {e}")
        
        return {
            "message": f"Model {model_id} activated",
            "model_id": model_id,
            "version": target_model.version
        }


async def run_retraining(lookback_hours: int, min_samples: int):
    """Background task for retraining."""
    from app.scripts.retrain_model import retrain_model
    try:
        logger.info(f"Starting background retraining (lookback={lookback_hours}h)")
        model_id = await retrain_model(
            lookback_hours=lookback_hours,
            min_samples=min_samples
        )
        if model_id:
            # Reload detector with new model
            load_detector(model_id=model_id)
            logger.info(f"Retraining complete, model {model_id} activated")
        else:
            logger.warning("Retraining failed")
    except Exception as e:
        logger.error(f"Retraining error: {e}", exc_info=True)


@router.post("/retrain")
async def trigger_retrain(
    background_tasks: BackgroundTasks,
    lookback_hours: int = 72,
    min_samples: int = 1000
):
    """Trigger model retraining in background."""
    background_tasks.add_task(
        run_retraining,
        lookback_hours=lookback_hours,
        min_samples=min_samples
    )
    
    return {
        "message": "Retraining started in background",
        "lookback_hours": lookback_hours,
        "min_samples": min_samples
    }


@router.get("/status")
async def get_status():
    """Get system status."""
    from app.ml.anomaly_detector import get_anomaly_detector
    
    detector = get_anomaly_detector()
    stats = detector.get_stats() if detector.model else None
    
    # Get active model
    async with async_session_maker() as session:
        result = await session.execute(
            select(Model).where(Model.is_active == True)
        )
        active_model = result.scalars().first()
    
    return {
        "timestamp": datetime.now().isoformat(),
        "model_loaded": detector.model is not None,
        "active_model": {
            "id": active_model.id,
            "version": active_model.version,
            "threshold": active_model.threshold
        } if active_model else None,
        "detector_stats": stats
    }
