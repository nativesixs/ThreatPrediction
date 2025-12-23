"""
Evidence logging service for IDS audit trail.
Logs all predictions, attacks, and system events to CSV files.
"""
import logging
import csv
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
import threading

logger = logging.getLogger(__name__)


class EvidenceLogger:
    """Logs IDS events to CSV files for audit and analysis."""
    
    def __init__(self, log_dir: str = "logs/evidence"):
        """
        Initialize evidence logger.
        
        Args:
            log_dir: Directory to store log files
        """
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Thread lock for safe concurrent writes
        self.lock = threading.Lock()
        
        # Get today's date for file naming
        self.current_date = datetime.now().strftime("%Y%m%d")
        
        # Initialize CSV files
        self.predictions_file = self.log_dir / f"predictions_{self.current_date}.csv"
        self.attacks_file = self.log_dir / f"attacks_{self.current_date}.csv"
        self.system_events_file = self.log_dir / f"system_events_{self.current_date}.csv"
        
        self._init_csv_files()
        
        logger.info(f"Evidence logger initialized. Logs at: {self.log_dir}")
    
    def _init_csv_files(self):
        """Initialize CSV files with headers if they don't exist."""
        # Predictions log
        if not self.predictions_file.exists():
            with open(self.predictions_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'timestamp', 'flow_id', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
                    'protocol', 'duration', 'packets', 'bytes',
                    'predicted_class', 'confidence', 'is_attack', 'severity',
                    'anomaly_score', 'flagged_by_gate', 'threshold_used',
                    'original_prediction', 'model_version'
                ])
        
        # Attacks log
        if not self.attacks_file.exists():
            with open(self.attacks_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'timestamp', 'flow_id', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
                    'attack_type', 'confidence', 'severity', 'anomaly_score',
                    'description'
                ])
        
        # System events log
        if not self.system_events_file.exists():
            with open(self.system_events_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'timestamp', 'event_type', 'severity', 'message', 'details'
                ])
    
    def log_prediction(
        self,
        flow_info: Dict[str, Any],
        prediction: Dict[str, Any]
    ):
        """
        Log a prediction to CSV.
        
        Args:
            flow_info: Flow metadata (IPs, ports, duration, etc.)
            prediction: Prediction details
        """
        try:
            with self.lock:
                # Check if we need to roll over to new date
                current_date = datetime.now().strftime("%Y%m%d")
                if current_date != self.current_date:
                    self.current_date = current_date
                    self.predictions_file = self.log_dir / f"predictions_{self.current_date}.csv"
                    self._init_csv_files()
                
                with open(self.predictions_file, 'a', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        datetime.now().isoformat(),
                        f"{flow_info.get('source_ip')}:{flow_info.get('source_port')}-{flow_info.get('destination_ip')}:{flow_info.get('destination_port')}",
                        flow_info.get('source_ip', 'unknown'),
                        flow_info.get('destination_ip', 'unknown'),
                        flow_info.get('source_port', 0),
                        flow_info.get('destination_port', 0),
                        flow_info.get('protocol', 'unknown'),
                        flow_info.get('duration', 0.0),
                        flow_info.get('packet_count', 0),
                        flow_info.get('byte_count', 0),
                        prediction.get('predicted_label', 'UNKNOWN'),
                        prediction.get('confidence', 0.0),
                        prediction.get('is_attack', False),
                        prediction.get('severity', 'UNKNOWN'),
                        prediction.get('anomaly_score', 0.0),
                        prediction.get('flagged_by_anomaly_gate', False),
                        prediction.get('threshold_used', 0.0),
                        prediction.get('original_prediction', ''),
                        prediction.get('model_version', 'unknown')
                    ])
        
        except Exception as e:
            logger.error(f"Failed to log prediction: {e}")
    
    def log_attack(
        self,
        flow_info: Dict[str, Any],
        prediction: Dict[str, Any]
    ):
        """
        Log a detected attack to CSV.
        
        Args:
            flow_info: Flow metadata
            prediction: Attack prediction details
        """
        try:
            with self.lock:
                current_date = datetime.now().strftime("%Y%m%d")
                if current_date != self.current_date:
                    self.current_date = current_date
                    self.attacks_file = self.log_dir / f"attacks_{self.current_date}.csv"
                    self._init_csv_files()
                
                with open(self.attacks_file, 'a', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        datetime.now().isoformat(),
                        f"{flow_info.get('source_ip')}:{flow_info.get('source_port')}-{flow_info.get('destination_ip')}:{flow_info.get('destination_port')}",
                        flow_info.get('source_ip', 'unknown'),
                        flow_info.get('destination_ip', 'unknown'),
                        flow_info.get('source_port', 0),
                        flow_info.get('destination_port', 0),
                        prediction.get('predicted_label', 'UNKNOWN'),
                        prediction.get('confidence', 0.0),
                        prediction.get('severity', 'UNKNOWN'),
                        prediction.get('anomaly_score', 0.0),
                        f"Attack detected: {prediction.get('predicted_label')} with {prediction.get('confidence', 0)*100:.1f}% confidence"
                    ])
        
        except Exception as e:
            logger.error(f"Failed to log attack: {e}")
    
    def log_system_event(
        self,
        event_type: str,
        severity: str,
        message: str,
        details: Optional[str] = None
    ):
        """
        Log a system event to CSV.
        
        Args:
            event_type: Type of event (STARTUP, SHUTDOWN, ERROR, etc.)
            severity: Severity level (INFO, WARNING, ERROR, CRITICAL)
            message: Event message
            details: Additional details (optional)
        """
        try:
            with self.lock:
                current_date = datetime.now().strftime("%Y%m%d")
                if current_date != self.current_date:
                    self.current_date = current_date
                    self.system_events_file = self.log_dir / f"system_events_{self.current_date}.csv"
                    self._init_csv_files()
                
                with open(self.system_events_file, 'a', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        datetime.now().isoformat(),
                        event_type,
                        severity,
                        message,
                        details or ''
                    ])
        
        except Exception as e:
            logger.error(f"Failed to log system event: {e}")


# Global evidence logger instance
_evidence_logger: Optional[EvidenceLogger] = None


def get_evidence_logger() -> EvidenceLogger:
    """Get or create global evidence logger instance."""
    global _evidence_logger
    if _evidence_logger is None:
        _evidence_logger = EvidenceLogger()
    return _evidence_logger
