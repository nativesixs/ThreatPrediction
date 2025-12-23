"""
Unsupervised Anomaly Detection Gate
Implements the expert's recommendation for two-stage detection:
1. Anomaly detection filters normal traffic
2. BiLSTM classifies only suspicious flows
"""
import numpy as np
import logging
from typing import Dict, List, Tuple, Optional
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pickle
from pathlib import Path

logger = logging.getLogger(__name__)


class AnomalyDetectionGate:
    """
    Unsupervised anomaly detector that acts as a gating filter.
    Only passes suspicious traffic to the supervised BiLSTM classifier.
    """
    
    def __init__(self, contamination: float = 0.01, random_state: int = 42):
        """
        Initialize anomaly detection gate.
        
        Args:
            contamination: Expected proportion of anomalies (0.01 = 1%)
            random_state: Random seed for reproducibility
        """
        self.contamination = contamination
        self.random_state = random_state
        
        # Isolation Forest for anomaly detection
        self.detector = IsolationForest(
            contamination=contamination,
            random_state=random_state,
            n_estimators=100,
            max_samples=256,  # Limit samples for better performance
            bootstrap=False,
            n_jobs=-1
        )
        
        # Scaler for anomaly detection features
        self.scaler = StandardScaler()
        
        # State
        self.is_fitted = False
        
        # Statistics
        self.total_packets = 0
        self.anomalies_detected = 0
        self.false_positive_rate = 0.0
        
        logger.info(f"AnomalyDetectionGate initialized with contamination={contamination}")
    
    def fit(self, features: np.ndarray, sample_size: int = 10000):
        """
        Fit the anomaly detector on normal traffic samples.
        
        Args:
            features: Feature vectors from normal traffic
            sample_size: Maximum samples to use for training
        """
        if len(features) == 0:
            raise ValueError("Cannot fit on empty feature set")
        
        # Sample if too many features
        if len(features) > sample_size:
            indices = np.random.choice(len(features), sample_size, replace=False)
            features = features[indices]
        
        logger.info(f"Fitting anomaly detector on {len(features)} samples...")
        
        # Normalize features
        features_scaled = self.scaler.fit_transform(features)
        
        # Fit detector
        self.detector.fit(features_scaled)
        
        # Use the built-in outlier prediction instead of manual threshold
        predictions = self.detector.predict(features_scaled)
        # -1 means outlier, 1 means inlier in sklearn
        outlier_rate = np.sum(predictions == -1) / len(predictions)
        
        self.is_fitted = True
        
        logger.info(f"✓ Anomaly detector fitted successfully")
        logger.info(f"  Outlier rate on training: {outlier_rate:.1%}")
        logger.info(f"  Expected anomaly rate: {self.contamination:.1%}")
    
    def predict_anomaly(self, features: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Detect anomalies in feature vectors.
        
        Args:
            features: Feature vectors to analyze
            
        Returns:
            Tuple of (anomaly_flags, anomaly_scores)
            - anomaly_flags: Boolean array (True = anomaly)
            - anomaly_scores: Continuous anomaly scores
        """
        if not self.is_fitted:
            raise RuntimeError("Anomaly detector not fitted. Call fit() first.")
        
        if len(features) == 0:
            return np.array([]), np.array([])
        
        # Scale features
        features_scaled = self.scaler.transform(features)
        
        # Use built-in predict method (-1 = outlier, 1 = inlier)
        predictions = self.detector.predict(features_scaled)
        anomaly_flags = (predictions == -1)
        
        # Get continuous scores for reference
        anomaly_scores = self.detector.decision_function(features_scaled)
        
        # Update statistics
        self.total_packets += len(features)
        self.anomalies_detected += np.sum(anomaly_flags)
        
        logger.debug(f"Anomaly detection: {np.sum(anomaly_flags)}/{len(features)} anomalies")
        
        return anomaly_flags, anomaly_scores
    
    def filter_for_classification(self, features: np.ndarray, packets: List[Dict]) -> Tuple[np.ndarray, List[Dict], np.ndarray]:
        """
        Filter traffic for supervised classification.
        Only returns suspicious flows that need detailed analysis.
        
        Args:
            features: Feature vectors
            packets: Corresponding packet data
            
        Returns:
            Tuple of (suspicious_features, suspicious_packets, anomaly_scores)
        """
        anomaly_flags, anomaly_scores = self.predict_anomaly(features)
        
        # Filter only anomalous traffic
        suspicious_indices = np.where(anomaly_flags)[0]
        
        if len(suspicious_indices) == 0:
            logger.debug("No anomalies detected - all traffic filtered as normal")
            return np.array([]), [], anomaly_scores
        
        suspicious_features = features[suspicious_indices]
        suspicious_packets = [packets[i] for i in suspicious_indices]
        
        logger.info(f"🚨 Anomaly gate: {len(suspicious_indices)}/{len(features)} flows need classification")
        
        return suspicious_features, suspicious_packets, anomaly_scores
    
    def get_statistics(self) -> Dict:
        """Get anomaly detection statistics."""
        if self.total_packets == 0:
            anomaly_rate = 0.0
        else:
            anomaly_rate = self.anomalies_detected / self.total_packets
        
        return {
            'total_packets': self.total_packets,
            'anomalies_detected': self.anomalies_detected,
            'anomaly_rate': anomaly_rate,
            'expected_rate': self.contamination,
            'is_fitted': self.is_fitted
        }
    
    def save(self, path: Path):
        """Save the fitted anomaly detector."""
        if not self.is_fitted:
            raise RuntimeError("Cannot save unfitted detector")
        
        model_data = {
            'detector': self.detector,
            'scaler': self.scaler,
            'contamination': self.contamination,
            'statistics': self.get_statistics()
        }
        
        with open(path, 'wb') as f:
            pickle.dump(model_data, f)
        
        logger.info(f"✓ Anomaly detector saved to {path}")
    
    def load(self, path: Path):
        """Load a pre-fitted anomaly detector."""
        with open(path, 'rb') as f:
            model_data = pickle.load(f)
        
        self.detector = model_data['detector']
        self.scaler = model_data['scaler']
        self.contamination = model_data['contamination']
        self.is_fitted = True
        
        logger.info(f"✓ Anomaly detector loaded from {path}")
        logger.info(f"  Contamination: {self.contamination:.1%}")


def create_anomaly_gate(contamination: float = 0.01) -> AnomalyDetectionGate:
    """
    Create and configure anomaly detection gate with expert's recommendations.
    
    Args:
        contamination: Expected anomaly rate (default 1% as expert suggested)
        
    Returns:
        Configured AnomalyDetectionGate
    """
    return AnomalyDetectionGate(contamination=contamination)