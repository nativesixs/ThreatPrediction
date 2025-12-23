"""
Model Confidence Calibration
Apply temperature scaling to fix overconfidence issues
"""
import numpy as np
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)


class TemperatureScaling:
    """Apply temperature scaling to calibrate model confidence."""
    
    def __init__(self, temperature: float = 2.0):
        """
        Initialize temperature scaling.
        
        Args:
            temperature: Temperature parameter (>1 reduces overconfidence)
        """
        self.temperature = temperature
        logger.info(f"Temperature scaling initialized with T={temperature}")
    
    def calibrate_probabilities(self, logits: np.ndarray) -> np.ndarray:
        """
        Apply temperature scaling to logits to calibrate probabilities.
        
        Args:
            logits: Raw model outputs (before softmax)
            
        Returns:
            Calibrated probabilities
        """
        try:
            # Apply temperature scaling: logits / T
            scaled_logits = logits / self.temperature
            
            # Apply softmax to get probabilities
            exp_logits = np.exp(scaled_logits - np.max(scaled_logits, axis=-1, keepdims=True))
            probabilities = exp_logits / np.sum(exp_logits, axis=-1, keepdims=True)
            
            return probabilities
            
        except Exception as e:
            logger.error(f"Temperature scaling failed: {e}")
            # Fallback: uniform distribution
            return np.ones_like(logits) / logits.shape[-1]
    
    def calibrate_prediction(self, prediction: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calibrate a single prediction dictionary.
        
        Args:
            prediction: Prediction with all_probabilities
            
        Returns:
            Calibrated prediction
        """
        try:
            if "all_probabilities" not in prediction:
                return prediction
            
            # Extract probabilities
            probs = prediction["all_probabilities"]
            if isinstance(probs, dict):
                prob_values = np.array(list(probs.values()))
                prob_keys = list(probs.keys())
            else:
                return prediction
            
            # Convert to logits (inverse softmax)
            # Add small epsilon to avoid log(0)
            epsilon = 1e-8
            prob_values = np.clip(prob_values, epsilon, 1 - epsilon)
            logits = np.log(prob_values)
            
            # Apply temperature scaling
            calibrated_probs = self.calibrate_probabilities(logits.reshape(1, -1))[0]
            
            # Update prediction
            calibrated_prediction = prediction.copy()
            calibrated_prediction["all_probabilities"] = dict(zip(prob_keys, calibrated_probs))
            
            # CRITICAL FIX: Don't change the predicted label, just calibrate confidence for that label
            original_label = prediction["predicted_label"]
            original_label_index = prob_keys.index(original_label) if original_label in prob_keys else 0
            calibrated_prediction["confidence"] = float(calibrated_probs[original_label_index])
            calibrated_prediction["predicted_label"] = original_label  # Keep original prediction
            
            # Add calibration metadata
            calibrated_prediction["calibrated"] = True
            calibrated_prediction["original_confidence"] = prediction.get("confidence", 0.0)
            
            # Debug: Show calibration effect
            original_conf = prediction.get("confidence", 0.0)
            new_conf = calibrated_prediction["confidence"]
            logger.debug(f"Calibration effect: {original_conf:.3f} -> {new_conf:.3f} for {original_label}")
            
            return calibrated_prediction
            
        except Exception as e:
            logger.error(f"Prediction calibration failed: {e}")
            return prediction


def create_calibrator(overconfident_threshold: float = 0.95) -> TemperatureScaling:
    """
    Create a temperature scaling calibrator for overconfident models.
    
    Args:
        overconfident_threshold: Confidence above which to apply stronger calibration
        
    Returns:
        Configured TemperatureScaling instance
    """
    # Higher temperature for more overconfident models
    temperature = 3.0 if overconfident_threshold > 0.9 else 2.0
    return TemperatureScaling(temperature=temperature)