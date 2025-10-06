"""
FastAPI application for network intrusion detection system.
Provides REST API and live traffic monitoring with anomaly detection.
"""
import logging
import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from datetime import datetime

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.database import init_db
from app.api import admin, metrics, predictions, traffic, websocket
from app.ml.anomaly_detector import load_detector, get_anomaly_detector
from app.services.log_watcher import LogWatcher

# Configure logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# Global log watcher instance
log_watcher = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.
    Initialize services on startup, cleanup on shutdown.
    """
    logger.info("=" * 80)
    logger.info(f"Starting {settings.PROJECT_NAME} v{settings.VERSION}")
    logger.info("=" * 80)
    
    # Create necessary directories
    settings.DATA_DIR.mkdir(parents=True, exist_ok=True)
    settings.ZEEK_LOG_DIR.mkdir(parents=True, exist_ok=True)
    settings.ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    logger.info(f"Data directory: {settings.DATA_DIR}")
    logger.info(f"Zeek log directory: {settings.ZEEK_LOG_DIR}")
    logger.info(f"Artifacts directory: {settings.ARTIFACTS_DIR}")
    
    # Initialize database
    try:
        await init_db()
        logger.info("✓ Database initialized")
    except Exception as e:
        logger.error(f"✗ Failed to initialize database: {e}")
        raise
    
    # Load anomaly detection model
    try:
        from app.models.database_models import Model
        from app.core.database import async_session_maker
        from sqlalchemy import select
        
        # Get active model from database
        async with async_session_maker() as session:
            result = await session.execute(
                select(Model).where(Model.is_active == True).order_by(Model.created_at.desc())
            )
            active_model = result.scalars().first()
        
        if active_model:
            logger.info(f"Loading model: {active_model.version}")
            load_detector(model_id=active_model.id)
            logger.info(f"✓ Anomaly detector loaded")
            logger.info(f"  Model ID: {active_model.id}")
            logger.info(f"  Version: {active_model.version}")
            logger.info(f"  Threshold: {active_model.threshold:.6f}")
        else:
            logger.warning("✗ No active model found in database")
            logger.warning("  Train a model first: poetry run train-model")
    except FileNotFoundError as e:
        logger.warning(f"✗ Model artifacts not found: {e}")
        logger.warning("  Train a model first: poetry run train-model")
    except Exception as e:
        logger.error(f"✗ Failed to load model: {e}")
    
    # Start log watcher if Zeek logs exist
    global log_watcher
    try:
        detector = get_anomaly_detector()
        if detector.model is not None:
            log_watcher = LogWatcher(
                log_dir=settings.ZEEK_LOG_DIR,
                detector=detector
            )
            
            # Start watcher in background
            asyncio.create_task(log_watcher.start())
            logger.info("✓ Log watcher started")
            logger.info(f"  Monitoring: {settings.ZEEK_LOG_DIR}")
        else:
            logger.info("  Log watcher not started (no model loaded)")
    except Exception as e:
        logger.warning(f"  Could not start log watcher: {e}")
    
    logger.info("=" * 80)
    logger.info("Application startup complete")
    logger.info(f"API available at: http://0.0.0.0:8000{settings.API_PREFIX}")
    logger.info("=" * 80)
    
    yield  # Application runs
    
    # Shutdown
    logger.info("Shutting down application...")
    
    if log_watcher:
        try:
            await log_watcher.stop()
            logger.info("✓ Log watcher stopped")
        except Exception as e:
            logger.error(f"Error stopping log watcher: {e}")
    
    logger.info("Shutdown complete")


# Create FastAPI application
app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(admin.router, prefix=settings.API_PREFIX, tags=["admin"])
app.include_router(metrics.router, prefix=settings.API_PREFIX, tags=["metrics"])
app.include_router(predictions.router, prefix=settings.API_PREFIX, tags=["predictions"])
app.include_router(traffic.router, prefix=settings.API_PREFIX, tags=["traffic"])
app.include_router(websocket.router, prefix=settings.API_PREFIX, tags=["websocket"])


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "name": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "running"
    }


@app.get("/health")
async def health():
    """Health check endpoint."""
    detector = get_anomaly_detector()
    
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "model_loaded": detector.model is not None,
        "log_watcher_active": log_watcher is not None and log_watcher.running if log_watcher else False
    }


def run():
    """Run application (for poetry script)."""
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level=settings.LOG_LEVEL.lower()
    )


if __name__ == "__main__":
    run()
