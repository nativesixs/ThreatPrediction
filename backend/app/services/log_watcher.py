"""
Log watcher service for monitoring Zeek logs in real-time.
Tails conn.log and processes new flows through anomaly detector.
"""
import asyncio
from pathlib import Path
from typing import Optional
import logging
from datetime import datetime

from app.core.config import settings
from app.core.database import async_session_maker
from app.models.database_models import Flow, Anomaly
from app.ml.zeek_parser import ZeekLogParser
from app.ml.flow_feature_extractor import FlowFeatureExtractor
from app.ml.anomaly_detector import AnomalyDetector
from sqlalchemy import select

logger = logging.getLogger(__name__)


class LogWatcher:
    """
    Watches Zeek log directory for new conn.log entries.
    Processes new flows through anomaly detection pipeline.
    """
    
    def __init__(
        self,
        log_dir: Path,
        detector: AnomalyDetector,
        check_interval: float = None
    ):
        """
        Initialize log watcher.
        
        Args:
            log_dir: Directory containing Zeek logs
            detector: Anomaly detector instance
            check_interval: Seconds between checks
        """
        self.log_dir = log_dir
        self.detector = detector
        self.check_interval = check_interval or settings.LOG_WATCH_INTERVAL
        
        self.parser = ZeekLogParser()
        self.extractor = FlowFeatureExtractor()
        
        self.running = False
        self.file_position = 0
        self.conn_log_path: Optional[Path] = None
        
        self.flows_processed = 0
        self.anomalies_detected = 0
    
    async def find_conn_log(self) -> Optional[Path]:
        """Find the active conn.log file."""
        # Look for conn.log or conn.<timestamp>.log
        candidates = list(self.log_dir.glob("conn.log"))
        
        if candidates:
            return candidates[0]
        
        # Try timestamped logs
        candidates = sorted(self.log_dir.glob("conn.*.log"), reverse=True)
        if candidates:
            return candidates[0]
        
        return None
    
    async def process_new_flows(self):
        """Process new entries from conn.log."""
        if not self.conn_log_path or not self.conn_log_path.exists():
            # Try to find log file
            self.conn_log_path = await self.find_conn_log()
            if not self.conn_log_path:
                return
            logger.info(f"Found conn.log: {self.conn_log_path}")
            self.file_position = 0
        
        # Read new entries
        new_flows, new_position = self.parser.tail_file(
            self.conn_log_path,
            self.file_position
        )
        
        if new_flows:
            logger.info(f"Processing {len(new_flows)} new flows")
            
            # Extract features
            features = self.extractor.extract_batch(new_flows)
            
            # Run anomaly detection
            predictions = self.detector.predict_batch(features)
            
            # Store in database
            async with async_session_maker() as session:
                for flow_data, flow_features, prediction in zip(
                    new_flows, features, predictions
                ):
                    # Check if flow already exists (avoid duplicates)
                    existing_flow = await session.scalar(
                        select(Flow).where(Flow.uid == flow_data['uid'])
                    )
                    
                    if existing_flow:
                        logger.debug(f"Flow {flow_data['uid']} already exists, skipping")
                        continue
                        
                    # Create flow record
                    flow = Flow(
                        timestamp=flow_data['timestamp'],
                        uid=flow_data['uid'],
                        orig_ip=flow_data['orig_ip'],
                        orig_port=flow_data['orig_port'],
                        resp_ip=flow_data['resp_ip'],
                        resp_port=flow_data['resp_port'],
                        protocol=flow_data['protocol'],
                        service=flow_data['service'],
                        duration=flow_data['duration'],
                        orig_bytes=flow_data['orig_bytes'],
                        resp_bytes=flow_data['resp_bytes'],
                        orig_pkts=flow_data['orig_pkts'],
                        resp_pkts=flow_data['resp_pkts'],
                        orig_ip_bytes=flow_data.get('orig_ip_bytes'),
                        resp_ip_bytes=flow_data.get('resp_ip_bytes'),
                        conn_state=flow_data['conn_state'],
                        features=flow_features.tolist(),
                        is_normal=not prediction['is_anomaly'],
                        zeek_metadata=flow_data.get('zeek_metadata')
                    )
                    session.add(flow)
                    await session.flush()  # Get flow.id
                    
                    # Create anomaly record for ALL flows (normal and anomalous)
                    anomaly = Anomaly(
                        timestamp=datetime.now(),
                        flow_id=flow.id,
                        reconstruction_error=prediction['reconstruction_error'],
                        threshold=prediction['threshold'],
                        anomaly_score=prediction['anomaly_score'],
                        is_anomaly=prediction['is_anomaly'],
                        model_id=prediction['model_id'],
                        severity=prediction['severity']
                    )
                    session.add(anomaly)
                    
                    if prediction['is_anomaly']:
                        self.anomalies_detected += 1
                    
                    self.flows_processed += 1
                
                await session.commit()
            
            logger.info(
                f"Processed {len(new_flows)} flows "
                f"({self.anomalies_detected} anomalies total)"
            )
        
        # Update file position
        self.file_position = new_position
    
    async def start(self):
        """Start watching logs."""
        logger.info("Starting log watcher")
        self.running = True
        
        while self.running:
            try:
                await self.process_new_flows()
            except Exception as e:
                logger.error(f"Error processing flows: {e}", exc_info=True)
            
            # Wait before next check
            await asyncio.sleep(self.check_interval)
    
    async def stop(self):
        """Stop watching logs."""
        logger.info("Stopping log watcher")
        self.running = False
        logger.info(
            f"Log watcher stopped. "
            f"Processed {self.flows_processed} flows, "
            f"detected {self.anomalies_detected} anomalies"
        )
