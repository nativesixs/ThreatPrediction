import logging
import asyncio
import numpy as np
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.api import predictions, traffic, metrics, websocket, admin
from app.services.packet_processor import get_processor
from app.services.packet_capturer import PacketCapturer
from app.services.prediction_service import load_models, get_prediction_service
from app.api.websocket import broadcast_prediction, get_connection_count
from app.core.database import get_db
from app.models.database_models import Prediction, TrafficLog
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import Depends


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan handler.
    Initializes services on startup and cleans up on shutdown.
    """
    logger.info("Starting application...")
    
    # Load ML models
    try:
        load_models()
        logger.info("Models loaded successfully")
    except Exception as e:
        logger.warning(f"Failed to load models: {e}")
    
    # Initialize database
    try:
        from app.core.database import init_db
        await init_db()
        logger.info("Database initialized")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
    
    # Start packet processor with prediction callback
    try:
        processor = get_processor()
        predictor = get_prediction_service()  # Get predictor instance
        
        logger.info("Starting ONE-STAGE classification system (no anomaly pre-filtering)")
        logger.info("Confidence threshold filtering will reduce false positives")
        
        # Set up prediction callback
        async def handle_predictions(features: np.ndarray, packet_batch: list, anomaly_results: list = None):
            """Handle predictions from packet processor (One-Stage: Direct Classification)."""
            try:
                logger.debug(f"Classifying batch of {len(features)} samples")
                
                # Make predictions (One-Stage: classify all traffic)
                import time
                start_time = time.time()
                _, _, prediction_details = predictor.predict_batch(features)
                processing_time = (time.time() - start_time) * 1000  # Convert to ms
                
                # Apply confidence threshold filtering
                # REALITY CHECK: ALL models (v7-v10) produce false positives
                # Problem: Training datasets don't understand modern encrypted traffic (TLS 1.3, QUIC, HTTP/3)
                # GitHub, Microsoft, Google all get flagged as attacks
                # SOLUTION: Use 99.9% threshold - only flag EXTREMELY obvious attacks
                # This will miss some real attacks but it's the only way to stop false positives
                filtered_predictions = []
                for pred in prediction_details:
                    # If predicted as NORMAL, always keep it
                    if pred["predicted_label"].upper() in ["NORMAL", "BENIGN"]:
                        filtered_predictions.append(pred)
                    # For attacks, require 99.9% confidence
                    # Only the most obvious attacks will be flagged
                    elif pred["confidence"] >= 0.999:
                        # High confidence attack - likely real
                        # Make sure is_attack is True (should already be set by prediction service)
                        if not pred.get("is_attack", False):
                            logger.warning(f"Prediction service returned is_attack=False for {pred['predicted_label']} ({pred['confidence']:.2%}), overriding to True")
                            pred["is_attack"] = True
                        filtered_predictions.append(pred)
                        logger.info(f"High-confidence attack detected: {pred['predicted_label']} ({pred['confidence']:.2%}) | is_attack={pred['is_attack']}")
                    else:
                        # Low confidence attack - treat as false positive
                        logger.debug(f"Low-confidence prediction filtered: {pred['predicted_label']} ({pred['confidence']:.2%}) -> reclassified as NORMAL")
                        # Reclassify as NORMAL
                        original_label = pred["predicted_label"]  # Save before changing
                        pred["predicted_label"] = "NORMAL"
                        pred["is_attack"] = False
                        pred["original_prediction"] = original_label  # Keep for debugging
                        filtered_predictions.append(pred)
                
                prediction_details = filtered_predictions
                
                # Save to database
                from app.core.database import async_session_maker
                from datetime import datetime
                
                async with async_session_maker() as session:
                    # Save traffic logs and predictions
                    for i, pred in enumerate(prediction_details):
                        packet = packet_batch[i] if i < len(packet_batch) else {}
                        
                        # Create traffic log
                        traffic_log = TrafficLog(
                            timestamp=datetime.fromisoformat(packet.get("timestamp")) if packet.get("timestamp") else datetime.now(),
                            source_ip=packet.get("source_ip", "unknown"),
                            destination_ip=packet.get("destination_ip", "unknown"),
                            source_port=packet.get("source_port", 0),
                            destination_port=packet.get("destination_port", 0),
                            protocol=packet.get("transport_protocol", "unknown"),
                            packet_length=packet.get("total_length", 0),
                            flags=packet.get("tcp_flags", ""),
                            features=packet.get("features", {}),
                            raw_data=None
                        )
                        session.add(traffic_log)
                        await session.flush()  # Get the ID
                        
                        # Create prediction with v7 fields
                        prediction = Prediction(
                            traffic_log_id=traffic_log.id,
                            model_name="lstm",
                            model_version=pred.get("model_version"),
                            predicted_class=pred["predicted_label"],
                            confidence_score=pred["confidence"],
                            is_attack=pred["is_attack"],
                            is_confident=pred.get("is_confident", True),
                            severity=pred.get("severity"),
                            all_probabilities=pred["all_probabilities"],
                            processing_time_ms=processing_time / len(prediction_details)
                        )
                        session.add(prediction)
                        
                        # Broadcast to WebSocket
                        broadcast_data = {
                            "prediction": pred,
                            "packet_info": {
                                "source_ip": packet.get("source_ip"),
                                "destination_ip": packet.get("destination_ip"),
                                "protocol": packet.get("transport_protocol"),
                                "timestamp": packet.get("timestamp")
                            }
                        }
                        await broadcast_prediction(broadcast_data)
                    
                    await session.commit()
                
                logger.info(f"Processed and saved {len(prediction_details)} predictions")
                
            except Exception as e:
                logger.error(f"Error handling predictions: {e}")
                import traceback
                logger.error(traceback.format_exc())
        
        processor.set_prediction_callback(handle_predictions)
        await processor.start()
        logger.info("Packet processor started")
    except Exception as e:
        logger.warning(f"Failed to start packet processor: {e}")
    
    # Start packet capture as async task
    capturer = None
    capture_task = None
    try:
        processor = get_processor()
        
        # Create packet capturer with callback to processor
        async def packet_callback(packet_features):
            """Callback to send captured packets to processor."""
            await processor.add_packet(packet_features)
        
        capturer = PacketCapturer(packet_callback=packet_callback)
        
        # Start capture as background task
        capture_task = asyncio.create_task(capturer.start_capture())
        logger.info("Packet capture task created")
        
    except Exception as e:
        logger.warning(f"Failed to start packet capture: {e}")
        logger.info("System will run without live packet capture")
    
    yield
    
    # Shutdown
    logger.info("Shutting down application...")
    
    # Stop packet capture
    if capturer:
        try:
            capturer.stop_capture()
            if capture_task and not capture_task.done():
                capture_task.cancel()
                try:
                    await capture_task
                except asyncio.CancelledError:
                    pass
            logger.info("Packet capture stopped")
        except Exception as e:
            logger.error(f"Error stopping capture: {e}")
    
    # Stop packet processor
    try:
        processor = get_processor()
        await processor.stop()
        logger.info("Packet processor stopped")
    except Exception as e:
        logger.error(f"Error stopping processor: {e}")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Network Traffic Monitoring and Cyber Attack Prediction API",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(predictions.router, prefix=settings.API_PREFIX)
app.include_router(traffic.router, prefix=settings.API_PREFIX)
app.include_router(metrics.router, prefix=settings.API_PREFIX)
app.include_router(admin.router, prefix=settings.API_PREFIX)
app.include_router(websocket.router)


@app.get("/health")
async def health_check():
    """Health check endpoint with service status."""
    processor = get_processor()
    stats = processor.get_statistics()
    
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "packet_processor": {
            "running": stats['is_running'],
            "packets_received": stats['packets_received'],
            "packets_processed": stats['packets_processed'],
            "batches_processed": stats['batches_processed'],
            "queue_size": stats['queue_size']
        },
        "websocket_connections": get_connection_count()
    }


@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "message": "Threat Prediction API",
        "docs": "/docs",
        "health": "/health",
        "websocket": "/ws",
        "endpoints": {
            "predictions": f"{settings.API_PREFIX}/predictions",
            "traffic": f"{settings.API_PREFIX}/traffic",
            "metrics": f"{settings.API_PREFIX}/metrics"
        }
    }


def run_dev():
    """Entry point for development server"""
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )


def run_prod():
    """Entry point for production server"""
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        workers=4,
        log_level="info"
    )
