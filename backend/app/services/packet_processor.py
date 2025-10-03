"""
Real-time packet processing service using async queues.
One-stage classification: All traffic goes directly to v7 LSTM.
Confidence thresholding filters false positives.
"""
import logging
import asyncio
from typing import Dict, Any, Optional, Callable
from datetime import datetime
import numpy as np

from app.services.live_feature_extractor import LiveFeatureExtractor
from app.core.config import settings

logger = logging.getLogger(__name__)


class PacketProcessor:
    """Process network packets in real-time using async queue with direct classification."""
    
    def __init__(
        self,
        batch_size: int = 32,
        batch_timeout: float = 5.0
    ):
        """
        Initialize packet processor.
        
        Args:
            batch_size: Number of packets to batch for prediction
            batch_timeout: Maximum time to wait before processing partial batch
        """
        self.batch_size = batch_size
        self.batch_timeout = batch_timeout
        
        # Async queue for packet processing
        self.packet_queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
        
        # Feature extractor with StandardScaler from training
        from pathlib import Path
        scaler_path = None
        if settings.SCALER_FILE:  # Only if not empty string
            scaler_path = Path(settings.MODEL_PATH).parent / "data" / "processed" / settings.SCALER_FILE
        self.feature_extractor = LiveFeatureExtractor(scaler_path=scaler_path)
        
        # NO ANOMALY DETECTOR - using one-stage direct classification
        
        # Callback for handling predictions
        self.prediction_callback: Optional[Callable] = None
        
        # State
        self.is_running = False
        self.packet_buffer = []
        self.last_batch_time = datetime.now()
        
        # Statistics
        self.packets_received = 0
        self.packets_processed = 0
        self.batches_processed = 0
        self.errors = 0
    
    def set_prediction_callback(self, callback: Callable):
        """
        Set callback function for handling predictions.
        
        Args:
            callback: Async function that takes (features, packet_batch)
        """
        self.prediction_callback = callback
    
    async def add_packet(self, packet_data: Dict[str, Any]):
        """
        Add packet to processing queue.
        
        Args:
            packet_data: Raw packet data dictionary
        """
        try:
            await self.packet_queue.put(packet_data)
            self.packets_received += 1
        except asyncio.QueueFull:
            logger.warning("Packet queue is full, dropping packet")
            self.errors += 1
    
    async def process_batch(self):
        """Process accumulated packets and trigger prediction (one-stage: direct classification)."""
        if not self.packet_buffer:
            return
        
        try:
            logger.debug(f"Processing batch of {len(self.packet_buffer)} packets")
            
            # Extract features from batch
            features = self.feature_extractor.process_batch(self.packet_buffer)
            
            if features.size == 0:
                logger.warning("No valid features extracted from batch")
                self.packet_buffer.clear()
                return
            
            # ONE-STAGE: Direct ML Classification (no anomaly pre-filtering)
            # Classify ALL traffic through v7 LSTM
            # Confidence threshold will filter false positives later
            if self.prediction_callback:
                logger.info(f"Classifying batch of {len(features)} samples")
                await self.prediction_callback(
                    features,
                    self.packet_buffer,
                    anomaly_results=None  # No anomaly detection in one-stage mode
                )
            
            self.packets_processed += len(self.packet_buffer)
            self.batches_processed += 1
            self.packet_buffer.clear()
            self.last_batch_time = datetime.now()
            
            logger.debug(f"Batch processed successfully")
            
        except Exception as e:
            logger.error(f"Error processing batch: {e}")
            import traceback
            logger.error(traceback.format_exc())
            self.errors += 1
            self.packet_buffer.clear()
    
    async def processing_loop(self):
        """Main processing loop - consumes from queue and batches packets."""
        logger.info("Starting packet processing loop...")
        self.is_running = True
        
        try:
            while self.is_running:
                try:
                    # Try to get packet with timeout
                    packet = await asyncio.wait_for(
                        self.packet_queue.get(),
                        timeout=1.0
                    )
                    
                    self.packet_buffer.append(packet)
                    
                    # Process batch if full
                    if len(self.packet_buffer) >= self.batch_size:
                        await self.process_batch()
                
                except asyncio.TimeoutError:
                    # Check if we should process partial batch due to timeout
                    elapsed = (datetime.now() - self.last_batch_time).total_seconds()
                    if self.packet_buffer and elapsed >= self.batch_timeout:
                        await self.process_batch()
                
                except Exception as e:
                    logger.error(f"Error in processing loop: {e}")
                    self.errors += 1
                
                # Periodic cleanup
                if self.batches_processed % 100 == 0:
                    self.feature_extractor.cleanup_old_flows()
        
        except Exception as e:
            logger.error(f"Fatal error in processing loop: {e}")
            raise
        finally:
            # Process remaining packets
            if self.packet_buffer:
                await self.process_batch()
    
    async def start(self):
        """Start the packet processor."""
        if self.is_running:
            logger.warning("Processor already running")
            return
        
        logger.info("Starting packet processor...")
        asyncio.create_task(self.processing_loop())
    
    async def stop(self):
        """Stop the packet processor."""
        logger.info("Stopping packet processor...")
        self.is_running = False
        
        # Process remaining packets
        if self.packet_buffer:
            await self.process_batch()
        
        # Log statistics
        logger.info("Processor statistics:")
        logger.info(f"  Packets received: {self.packets_received}")
        logger.info(f"  Packets processed: {self.packets_processed}")
        logger.info(f"  Batches processed: {self.batches_processed}")
        logger.info(f"  Errors: {self.errors}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get processor statistics."""
        return {
            'packets_received': self.packets_received,
            'packets_processed': self.packets_processed,
            'batches_processed': self.batches_processed,
            'errors': self.errors,
            'is_running': self.is_running,
            'queue_size': self.packet_queue.qsize(),
            'buffer_size': len(self.packet_buffer)
        }


# Global processor instance
_processor: Optional[PacketProcessor] = None


def get_processor() -> PacketProcessor:
    """Get or create global processor instance."""
    global _processor
    if _processor is None:
        _processor = PacketProcessor()
    return _processor
