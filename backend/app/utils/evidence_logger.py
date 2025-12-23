"""
Evidence Logger for comprehensive debugging and analysis.
Logs all predictions, features, and metadata to CSV files for analysis.
"""

import csv
import json
import os
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
import threading

logger = logging.getLogger(__name__)

@dataclass
class PredictionEvidence:
    """Structure for prediction evidence"""
    timestamp: str
    flow_id: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    packet_length: int
    flags: str
    
    # Model outputs
    model_name: str
    model_version: str
    predicted_class: str
    confidence_score: float
    is_attack: bool
    is_confident: bool
    severity: str
    all_probabilities: str  # JSON string
    processing_time_ms: float
    
    # Features (will be JSON string)
    raw_features: str
    feature_count: int
    
    # Context
    session_id: Optional[str] = None
    attack_label: Optional[str] = None  # Ground truth if available
    notes: Optional[str] = None

class EvidenceLogger:
    """Thread-safe evidence logger for debugging and analysis"""
    
    def __init__(self, logs_dir: str = "logs/evidence"):
        self.logs_dir = Path(logs_dir)
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        
        # Create timestamped files
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.predictions_file = self.logs_dir / f"predictions_{timestamp}.csv"
        self.attacks_file = self.logs_dir / f"attacks_{timestamp}.csv"
        self.system_events_file = self.logs_dir / f"system_events_{timestamp}.csv"
        
        # Initialize CSV files with headers
        self._init_csv_files()
        
        logger.info(f"Evidence logger initialized:")
        logger.info(f"  Predictions: {self.predictions_file}")
        logger.info(f"  Attacks: {self.attacks_file}")
        logger.info(f"  System events: {self.system_events_file}")
    
    def _init_csv_files(self):
        """Initialize CSV files with headers"""
        # Predictions CSV
        with open(self.predictions_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'timestamp', 'flow_id', 'source_ip', 'destination_ip', 
                'source_port', 'destination_port', 'protocol', 'packet_length', 'flags',
                'model_name', 'model_version', 'predicted_class', 'confidence_score',
                'is_attack', 'is_confident', 'severity', 'all_probabilities',
                'processing_time_ms', 'raw_features', 'feature_count',
                'session_id', 'attack_label', 'notes'
            ])
        
        # Attacks CSV (ground truth events)
        with open(self.attacks_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'timestamp', 'attack_type', 'source_ip', 'target_ip', 'target_port',
                'intensity', 'duration_seconds', 'packets_sent', 'command_used',
                'expected_detection', 'notes'
            ])
        
        # System events CSV
        with open(self.system_events_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                'timestamp', 'event_type', 'source', 'message', 'data'
            ])
    
    def log_prediction(self, evidence: PredictionEvidence):
        """Log a prediction with all evidence"""
        with self._lock:
            try:
                with open(self.predictions_file, 'a', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        evidence.timestamp, evidence.flow_id, evidence.source_ip,
                        evidence.destination_ip, evidence.source_port, evidence.destination_port,
                        evidence.protocol, evidence.packet_length, evidence.flags,
                        evidence.model_name, evidence.model_version, evidence.predicted_class,
                        evidence.confidence_score, evidence.is_attack, evidence.is_confident,
                        evidence.severity, evidence.all_probabilities, evidence.processing_time_ms,
                        evidence.raw_features, evidence.feature_count, evidence.session_id,
                        evidence.attack_label, evidence.notes
                    ])
                    f.flush()  # Ensure immediate write
            except Exception as e:
                logger.error(f"Failed to log prediction evidence: {e}")
    
    def log_attack_event(self, attack_type: str, source_ip: str, target_ip: str, 
                        target_port: int, intensity: int, duration_seconds: float,
                        packets_sent: int, command_used: str, expected_detection: str,
                        notes: str = ""):
        """Log a ground truth attack event"""
        with self._lock:
            try:
                timestamp = datetime.now().isoformat()
                with open(self.attacks_file, 'a', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        timestamp, attack_type, source_ip, target_ip, target_port,
                        intensity, duration_seconds, packets_sent, command_used,
                        expected_detection, notes
                    ])
                    f.flush()
                logger.info(f"Attack event logged: {attack_type} from {source_ip} to {target_ip}:{target_port}")
            except Exception as e:
                logger.error(f"Failed to log attack event: {e}")
    
    def log_system_event(self, event_type: str, source: str, message: str, data: Dict[str, Any] = None):
        """Log system events (model loading, threshold changes, etc.)"""
        with self._lock:
            try:
                timestamp = datetime.now().isoformat()
                data_str = json.dumps(data) if data else ""
                with open(self.system_events_file, 'a', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow([timestamp, event_type, source, message, data_str])
                    f.flush()
                logger.info(f"System event logged: {event_type} - {message}")
            except Exception as e:
                logger.error(f"Failed to log system event: {e}")
    
    def get_recent_predictions(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent predictions for analysis"""
        try:
            predictions = []
            with open(self.predictions_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    predictions.append(row)
            return predictions[-limit:] if len(predictions) > limit else predictions
        except Exception as e:
            logger.error(f"Failed to read predictions: {e}")
            return []
    
    def get_attack_events(self) -> List[Dict[str, Any]]:
        """Get all logged attack events"""
        try:
            attacks = []
            with open(self.attacks_file, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    attacks.append(row)
            return attacks
        except Exception as e:
            logger.error(f"Failed to read attack events: {e}")
            return []

# Global evidence logger instance
_evidence_logger = None

def get_evidence_logger() -> EvidenceLogger:
    """Get global evidence logger instance"""
    global _evidence_logger
    if _evidence_logger is None:
        _evidence_logger = EvidenceLogger()
    return _evidence_logger

def log_prediction_evidence(
    timestamp: str, flow_id: str, source_ip: str, destination_ip: str,
    source_port: int, destination_port: int, protocol: str, packet_length: int,
    flags: str, model_name: str, model_version: str, predicted_class: str,
    confidence_score: float, is_attack: bool, is_confident: bool, severity: str,
    all_probabilities: Dict[str, float], processing_time_ms: float,
    raw_features: Dict[str, Any], session_id: str = None, attack_label: str = None,
    notes: str = None
):
    """Convenience function to log prediction evidence"""
    evidence = PredictionEvidence(
        timestamp=timestamp,
        flow_id=flow_id,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        protocol=protocol,
        packet_length=packet_length,
        flags=flags,
        model_name=model_name,
        model_version=model_version,
        predicted_class=predicted_class,
        confidence_score=confidence_score,
        is_attack=is_attack,
        is_confident=is_confident,
        severity=severity,
        all_probabilities=json.dumps(all_probabilities),
        processing_time_ms=processing_time_ms,
        raw_features=json.dumps(raw_features),
        feature_count=len(raw_features),
        session_id=session_id,
        attack_label=attack_label,
        notes=notes
    )
    get_evidence_logger().log_prediction(evidence)

def log_attack_evidence(attack_type: str, source_ip: str, target_ip: str, 
                       target_port: int, intensity: int, duration_seconds: float,
                       packets_sent: int, command_used: str, expected_detection: str,
                       notes: str = ""):
    """Convenience function to log attack evidence"""
    get_evidence_logger().log_attack_event(
        attack_type, source_ip, target_ip, target_port, intensity,
        duration_seconds, packets_sent, command_used, expected_detection, notes
    )

def log_system_evidence(event_type: str, source: str, message: str, data: Dict[str, Any] = None):
    """Convenience function to log system evidence"""
    get_evidence_logger().log_system_event(event_type, source, message, data)