"""
Anomaly detection inference service.
Loads trained autoencoder and scores flows in real-time.
"""
import torch
import numpy as np
from pathlib import Path
from typing import Dict, Tuple, Optional
import json
import joblib
import logging

from app.ml.models import Autoencoder
from app.core.config import settings

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """
    Service for real-time anomaly detection using trained autoencoder.
    
    Loads:
    - Trained autoencoder model
    - StandardScaler for feature normalization
    - Anomaly threshold from validation
    
    Inference:
    - Normalize features
    - Compute reconstruction error
    - Compare to threshold
    - Return anomaly score and decision
    """
    
    def __init__(
        self,
        artifacts_dir: Path = None,
        device: str = None
    ):
        """
        Initialize anomaly detector.
        
        Args:
            artifacts_dir: Directory containing model artifacts
            device: Device to run inference on
        """
        self.artifacts_dir = artifacts_dir or settings.ARTIFACTS_DIR
        self.device = device or ('cuda' if torch.cuda.is_available() else 'cpu')
        
        self.model: Optional[Autoencoder] = None
        self.scaler = None
        self.threshold: Optional[float] = None
        self.metadata: Optional[Dict] = None
        self.model_id: Optional[int] = None
        
        # Performance tracking
        self.predictions_made = 0
        self.total_inference_time = 0.0
    
    def load_artifacts(self, model_id: Optional[int] = None):
        """
        Load model artifacts from disk.
        
        Args:
            model_id: Database ID of model to load (for tracking)
        """
        logger.info(f"Loading artifacts from {self.artifacts_dir}")
        
        # Load metadata
        metadata_path = self.artifacts_dir / settings.THRESHOLD_FILE
        if not metadata_path.exists():
            raise FileNotFoundError(f"Metadata file not found: {metadata_path}")
        
        with open(metadata_path, 'r') as f:
            self.metadata = json.load(f)
        
        # Extract configuration
        architecture = self.metadata['architecture']
        input_size = architecture['input_size']
        encoder_layers = architecture['encoder_layers']
        self.threshold = self.metadata['threshold']
        
        logger.info(f"Model metadata loaded")
        logger.info(f"  Input size: {input_size}")
        logger.info(f"  Threshold: {self.threshold:.6f}")
        
        # Load scaler
        scaler_path = self.artifacts_dir / settings.SCALER_FILE
        if scaler_path.exists():
            self.scaler = joblib.load(scaler_path)
            logger.info(f"Scaler loaded from {scaler_path}")
        else:
            logger.warning("No scaler found, features will not be normalized")
        
        # Load model
        self.model = Autoencoder(input_size, encoder_layers)
        model_path = self.artifacts_dir / settings.AUTOENCODER_MODEL_FILE
        
        if not model_path.exists():
            raise FileNotFoundError(f"Model file not found: {model_path}")
        
        self.model.load_state_dict(torch.load(model_path, map_location=self.device))
        self.model.to(self.device)
        self.model.eval()
        
        logger.info(f"Model loaded from {model_path}")
        logger.info(f"Device: {self.device}")
        
        self.model_id = model_id
    
    def preprocess(self, X: np.ndarray) -> torch.Tensor:
        """
        Preprocess features for inference.
        
        Args:
            X: Feature matrix (num_samples, num_features)
        
        Returns:
            Preprocessed tensor
        """
        # Apply scaler if available
        if self.scaler is not None:
            X = self.scaler.transform(X)
        
        # Convert to tensor
        X_tensor = torch.FloatTensor(X).to(self.device)
        return X_tensor
    
    def compute_reconstruction_error(self, X: torch.Tensor) -> np.ndarray:
        """
        Compute reconstruction errors for batch.
        
        Args:
            X: Preprocessed feature tensor
        
        Returns:
            Array of reconstruction errors (MSE per sample)
        """
        with torch.no_grad():
            reconstructed = self.model(X)
            errors = torch.mean((X - reconstructed) ** 2, dim=1)
        
        return errors.cpu().numpy()
    
    def predict_single(self, features: np.ndarray) -> Dict:
        """
        Predict anomaly for a single flow.
        
        Args:
            features: Feature vector (1D array)
        
        Returns:
            Dictionary with prediction results
        """
        # Reshape to 2D
        if len(features.shape) == 1:
            features = features.reshape(1, -1)
        
        return self.predict_batch(features)[0]
    
    def predict_batch(self, features: np.ndarray) -> list[Dict]:
        """
        Predict anomalies for a batch of flows.
        
        Args:
            features: Feature matrix (num_samples, num_features)
        
        Returns:
            List of prediction dictionaries
        """
        import time
        start_time = time.time()
        
        # Preprocess
        X = self.preprocess(features)
        
        # Compute reconstruction errors
        errors = self.compute_reconstruction_error(X)
        
        # Make predictions
        predictions = []
        for error in errors:
            is_anomaly = bool(error > self.threshold)
            
            # Normalize anomaly score (0-1 scale)
            # Score = how much error exceeds threshold
            if is_anomaly:
                anomaly_score = min(1.0, error / (self.threshold * 2))  # Cap at 2x threshold
            else:
                anomaly_score = error / self.threshold if self.threshold > 0 else 0
            
            # Determine severity
            if not is_anomaly:
                severity = 'NORMAL'
            elif error > self.threshold * 3:
                severity = 'CRITICAL'
            elif error > self.threshold * 2:
                severity = 'HIGH'
            elif error > self.threshold * 1.5:
                severity = 'MEDIUM'
            else:
                severity = 'LOW'
            
            predictions.append({
                'is_anomaly': is_anomaly,
                'reconstruction_error': float(error),
                'threshold': float(self.threshold),
                'anomaly_score': float(anomaly_score),
                'severity': severity,
                'model_id': self.model_id
            })
        
        # Update metrics
        inference_time = (time.time() - start_time) * 1000  # Convert to ms
        self.predictions_made += len(predictions)
        self.total_inference_time += inference_time
        
        return predictions
    
    def get_stats(self) -> Dict:
        """Get performance statistics."""
        avg_time = self.total_inference_time / self.predictions_made if self.predictions_made > 0 else 0
        return {
            'predictions_made': self.predictions_made,
            'total_inference_time_ms': self.total_inference_time,
            'avg_inference_time_ms': avg_time,
            'model_id': self.model_id,
            'threshold': self.threshold
        }


# Global instance
_detector_instance: Optional[AnomalyDetector] = None


def get_anomaly_detector() -> AnomalyDetector:
    """Get global anomaly detector instance."""
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = AnomalyDetector()
    return _detector_instance


def load_detector(model_id: Optional[int] = None):
    """Load anomaly detector with artifacts."""
    detector = get_anomaly_detector()
    detector.load_artifacts(model_id)
    return detector
