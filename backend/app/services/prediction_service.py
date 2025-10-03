"""
Prediction service for real-time attack detection.
Loads trained models and performs batch predictions on live traffic.
"""
import logging
import torch
import numpy as np
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import json

from app.ml.models import LSTMModel, CNNModel
from app.core.config import settings


logger = logging.getLogger(__name__)


class PredictionService:
    """Service for running ML predictions on live traffic."""
    
    def __init__(
        self,
        model_path: Path = None,
        model_type: str = "lstm",
        device: str = None,
        metadata_path: Path = None
    ):
        """
        Initialize prediction service.
        
        Args:
            model_path: Path to saved model file
            model_type: Type of model ('lstm' or 'cnn')
            device: Device to run predictions on ('cuda' or 'cpu')
            metadata_path: Path to model metadata JSON file (optional)
        """
        self.model_path = model_path
        self.model_type = model_type.lower()
        self.device = device or ('cuda' if torch.cuda.is_available() else 'cpu')
        self.metadata_path = metadata_path
        
        self.model: Optional[torch.nn.Module] = None
        self.label_mapping: Optional[Dict[int, str]] = None
        self.num_features: Optional[int] = None
        self.num_classes: Optional[int] = None
        self.model_version: Optional[str] = None
        self.model_metadata: Optional[Dict] = None
        
        # Confidence thresholds from metadata
        self.confidence_threshold = 0.70
        self.high_confidence_threshold = 0.85
        
        # Performance tracking
        self.predictions_made = 0
        self.total_inference_time = 0.0
    
    def load_model(self):
        """Load trained model from disk with metadata."""
        if not self.model_path or not self.model_path.exists():
            raise FileNotFoundError(f"Model file not found: {self.model_path}")
        
        logger.info(f"Loading {self.model_type} model from {self.model_path}")
        
        try:
            # Load metadata if available
            if self.metadata_path and self.metadata_path.exists():
                logger.info(f"Loading model metadata from {self.metadata_path}")
                with open(self.metadata_path, 'r') as f:
                    self.model_metadata = json.load(f)
                
                # Extract configuration from metadata
                arch = self.model_metadata.get('architecture', {})
                self.num_features = arch.get('input_size')
                self.num_classes = arch.get('num_classes')
                self.label_mapping = {
                    int(k): v for k, v in self.model_metadata.get('label_mapping', {}).items()
                }
                self.model_version = self.model_metadata.get('model_version', 'unknown')
                
                # Get confidence thresholds
                deploy_info = self.model_metadata.get('deployment_info', {})
                self.confidence_threshold = deploy_info.get('recommended_confidence_threshold', 0.70)
                self.high_confidence_threshold = deploy_info.get('high_confidence_threshold', 0.85)
                
                logger.info(f"  Model version: {self.model_version}")
                logger.info(f"  Confidence thresholds: {self.confidence_threshold}/{self.high_confidence_threshold}")
            
            # Load checkpoint
            checkpoint = torch.load(self.model_path, map_location=self.device)
            
            # If metadata not loaded from file, try checkpoint (backward compatibility)
            if self.num_features is None:
                # Handle both 'num_features' and 'input_size' keys
                self.num_features = checkpoint.get('num_features') or checkpoint.get('input_size')
                self.num_classes = checkpoint.get('num_classes')
                self.label_mapping = checkpoint.get('label_mapping', {})
                
                # If no label mapping in checkpoint, use default
                if not self.label_mapping and self.num_classes == 7:
                    self.label_mapping = {
                        0: "NORMAL",
                        1: "DOS", 
                        2: "PROBE",
                        3: "R2L",
                        4: "U2R",
                        5: "MALWARE",
                        6: "EXPLOIT"
                    }
                    logger.info("Using default 7-class label mapping")
            
            if not all([self.num_features, self.num_classes]):
                raise ValueError("Model checkpoint missing required metadata")
            
            # Initialize model architecture
            if self.model_type == 'lstm':
                # Get architecture params from metadata or checkpoint
                if self.model_metadata:
                    arch = self.model_metadata['architecture']
                    hidden_size = arch.get('hidden_size', 128)
                    num_layers = arch.get('num_layers', 2)
                    dropout = arch.get('dropout', 0.3)
                else:
                    hidden_size = checkpoint.get('hidden_size', 128)
                    num_layers = checkpoint.get('num_layers', 2)
                    dropout = checkpoint.get('dropout', 0.3)
                
                self.model = LSTMModel(
                    input_size=self.num_features,
                    hidden_size=hidden_size,
                    num_layers=num_layers,
                    num_classes=self.num_classes,
                    dropout=dropout
                )
            elif self.model_type == 'cnn':
                self.model = CNNModel(
                    input_size=self.num_features,
                    num_classes=self.num_classes
                )
            else:
                raise ValueError(f"Unknown model type: {self.model_type}")
            
            # Load model weights (handle both formats: direct state_dict or nested)
            if 'model_state_dict' in checkpoint:
                self.model.load_state_dict(checkpoint['model_state_dict'])
            else:
                # v8 format: state dict saved directly
                self.model.load_state_dict(checkpoint)
            self.model.to(self.device)
            self.model.eval()
            
            logger.info(f"Model loaded successfully:")
            logger.info(f"  Version: {self.model_version or 'unknown'}")
            logger.info(f"  Features: {self.num_features}")
            logger.info(f"  Classes: {self.num_classes}")
            logger.info(f"  Device: {self.device}")
            logger.info(f"  Label mapping: {self.label_mapping}")
            
            # Log performance metrics if available
            if self.model_metadata and 'performance_metrics' in self.model_metadata:
                metrics = self.model_metadata['performance_metrics']
                logger.info(f"  Expected accuracy: {metrics.get('overall_accuracy', 0)*100:.2f}%")
                logger.info(f"  False positive rate: {metrics.get('false_positive_rate', 0)*100:.2f}%")
            
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            raise
    
    def predict_batch(
        self,
        features: np.ndarray,
        return_probabilities: bool = True
    ) -> Tuple[np.ndarray, np.ndarray, List[Dict]]:
        """
        Make predictions on a batch of feature vectors.
        
        Args:
            features: NumPy array of shape (batch_size, num_features)
            return_probabilities: Whether to return probability distributions
            
        Returns:
            Tuple of (predictions, probabilities, prediction_details)
            - predictions: Array of predicted class indices
            - probabilities: Array of class probabilities (if return_probabilities=True)
            - prediction_details: List of dicts with detailed prediction info
        """
        if self.model is None:
            raise RuntimeError("Model not loaded. Call load_model() first.")
        
        if features.shape[1] != self.num_features:
            raise ValueError(
                f"Feature dimension mismatch. Expected {self.num_features}, got {features.shape[1]}"
            )
        
        import time
        start_time = time.time()
        
        try:
            # Convert to tensor
            X = torch.FloatTensor(features).to(self.device)
            
            # Run inference
            with torch.no_grad():
                if self.model_type == 'lstm':
                    # LSTM expects (batch, seq_len=1, features)
                    X = X.unsqueeze(1)
                outputs = self.model(X)
                
                # Get probabilities
                probabilities = torch.softmax(outputs, dim=1)
                predictions = torch.argmax(probabilities, dim=1)
            
            # Convert to numpy
            predictions_np = predictions.cpu().numpy()
            probabilities_np = probabilities.cpu().numpy()
            
            # Create detailed predictions
            prediction_details = []
            for i in range(len(predictions_np)):
                pred_class = int(predictions_np[i])
                pred_label = self.label_mapping.get(pred_class, f"class_{pred_class}")
                confidence = float(probabilities_np[i][pred_class])
                
                # Get all class probabilities
                all_probs = {
                    self.label_mapping.get(j, f"class_{j}"): float(probabilities_np[i][j])
                    for j in range(self.num_classes)
                }
                
                # Determine if this is an attack
                is_benign = pred_label.upper() in ['BENIGN', 'NORMAL']
                
                # Apply confidence thresholds from metadata
                # For attacks: require at least confidence_threshold
                # For critical attacks (MALWARE, U2R, R2L): require high_confidence_threshold
                critical_attacks = ['MALWARE', 'U2R', 'R2L']
                is_critical = pred_label.upper() in critical_attacks
                
                if is_benign:
                    # For benign classification, accept if confidence > threshold
                    is_confident = confidence > self.confidence_threshold
                    is_attack = False
                else:
                    # For attacks, apply appropriate threshold
                    threshold = self.high_confidence_threshold if is_critical else self.confidence_threshold
                    is_confident = confidence > threshold
                    is_attack = is_confident
                
                # Determine severity based on attack type
                severity_map = {
                    'MALWARE': 'CRITICAL',
                    'U2R': 'CRITICAL',
                    'R2L': 'HIGH',
                    'EXPLOIT': 'HIGH',
                    'PROBE': 'MEDIUM',
                    'DOS': 'HIGH',
                    'NORMAL': 'BENIGN'
                }
                severity = severity_map.get(pred_label.upper(), 'UNKNOWN')
                
                detail = {
                    'predicted_class': pred_class,
                    'predicted_label': pred_label,
                    'confidence': confidence,
                    'is_attack': is_attack,
                    'is_confident': is_confident,
                    'severity': severity,
                    'all_probabilities': all_probs,
                    'model_version': self.model_version
                }
                prediction_details.append(detail)
            
            # Update statistics
            inference_time = time.time() - start_time
            self.predictions_made += len(predictions_np)
            self.total_inference_time += inference_time
            
            logger.debug(
                f"Predicted {len(predictions_np)} samples in {inference_time*1000:.2f}ms "
                f"({inference_time*1000/len(predictions_np):.2f}ms per sample)"
            )
            
            if return_probabilities:
                return predictions_np, probabilities_np, prediction_details
            else:
                return predictions_np, None, prediction_details
        
        except Exception as e:
            logger.error(f"Error during prediction: {e}")
            raise
    
    def predict_single(self, features: np.ndarray) -> Dict:
        """
        Make prediction on a single feature vector.
        
        Args:
            features: NumPy array of shape (num_features,)
            
        Returns:
            Dictionary with prediction details
        """
        # Reshape to batch format
        features_batch = features.reshape(1, -1)
        
        # Get prediction
        _, _, details = self.predict_batch(features_batch)
        
        return details[0]
    
    def get_statistics(self) -> Dict:
        """Get prediction service statistics."""
        avg_time = (
            self.total_inference_time / self.predictions_made
            if self.predictions_made > 0 else 0.0
        )
        
        stats = {
            'predictions_made': self.predictions_made,
            'total_inference_time': self.total_inference_time,
            'average_inference_time': avg_time,
            'model_type': self.model_type,
            'model_version': self.model_version or 'unknown',
            'device': self.device,
            'num_classes': self.num_classes,
            'confidence_threshold': self.confidence_threshold,
            'high_confidence_threshold': self.high_confidence_threshold
        }
        
        # Add performance metrics if available
        if self.model_metadata and 'performance_metrics' in self.model_metadata:
            stats['expected_metrics'] = self.model_metadata['performance_metrics']
        
        return stats


# Global prediction service instances
_lstm_service: Optional[PredictionService] = None
_cnn_service: Optional[PredictionService] = None


def get_prediction_service(model_type: str = "lstm") -> PredictionService:
    """
    Get or create prediction service instance.
    
    Args:
        model_type: Type of model ('lstm' or 'cnn')
        
    Returns:
        PredictionService instance
    """
    global _lstm_service, _cnn_service
    
    if model_type.lower() == "lstm":
        if _lstm_service is None:
            # Try v10 (modern datasets), then fall back to v7
            v10_model_path = Path(settings.MODEL_PATH) / "best_lstm_model_v10.pth"
            v10_metadata_path = Path(settings.MODEL_PATH) / "model_v10_metadata.json"
            
            if v10_model_path.exists():
                model_path = v10_model_path
                metadata_path = v10_metadata_path if v10_metadata_path.exists() else None
                logger.info("Loading v10 model (Modern datasets 2015-2023, NO NSL-KDD, 92.82% accuracy)")
            else:
                model_path = Path(settings.MODEL_PATH) / settings.LSTM_MODEL_FILE
                metadata_path = Path(settings.MODEL_PATH) / "model_v7_metadata.json"
                if not metadata_path.exists():
                    metadata_path = None
                logger.info("Loading v7 model (with NSL-KDD)")
            
            _lstm_service = PredictionService(
                model_path=model_path,
                model_type="lstm",
                metadata_path=metadata_path
            )
            _lstm_service.load_model()
        return _lstm_service
    
    elif model_type.lower() == "cnn":
        if _cnn_service is None:
            model_path = Path(settings.MODEL_PATH) / settings.CNN_MODEL_FILE
            _cnn_service = PredictionService(model_path=model_path, model_type="cnn")
            _cnn_service.load_model()
        return _cnn_service
    
    else:
        raise ValueError(f"Unknown model type: {model_type}")


def load_models():
    """Load all models on startup."""
    try:
        logger.info("Loading prediction models...")
        
        # Try to load LSTM model
        try:
            get_prediction_service("lstm")
            logger.info("LSTM model loaded")
        except Exception as e:
            logger.warning(f"Failed to load LSTM model: {e}")
        
        # Try to load CNN model
        try:
            get_prediction_service("cnn")
            logger.info("CNN model loaded")
        except Exception as e:
            logger.warning(f"Failed to load CNN model: {e}")
        
    except Exception as e:
        logger.error(f"Error loading models: {e}")
