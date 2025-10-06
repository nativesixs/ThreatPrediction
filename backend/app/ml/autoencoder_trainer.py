"""
Autoencoder trainer for anomaly detection.
Trains model on normal traffic only and calculates threshold.
"""
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import numpy as np
from pathlib import Path
from typing import Tuple, Dict, Optional
import json
import joblib
from datetime import datetime
import logging

from app.ml.models import Autoencoder
from app.core.config import settings

logger = logging.getLogger(__name__)


class AutoencoderTrainer:
    """
    Trainer for autoencoder-based anomaly detection.
    
    Training process:
    1. Load normal traffic data
    2. Split into training and validation sets
    3. Fit StandardScaler on training data
    4. Train autoencoder to minimize reconstruction error
    5. Calculate threshold from validation reconstruction errors
    6. Save model, scaler, and threshold
    """
    
    def __init__(
        self,
        input_size: int,
        hidden_layers: list = None,
        device: str = None,
        artifacts_dir: Path = None
    ):
        """
        Initialize trainer.
        
        Args:
            input_size: Number of input features
            hidden_layers: List of hidden layer sizes
            device: Device to train on ('cuda' or 'cpu')
            artifacts_dir: Directory to save artifacts
        """
        self.input_size = input_size
        self.hidden_layers = hidden_layers or [128, 64, 32, 16]
        self.device = device or ('cuda' if torch.cuda.is_available() else 'cpu')
        self.artifacts_dir = artifacts_dir or settings.ARTIFACTS_DIR
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        
        # Create model
        self.model = Autoencoder(input_size, hidden_layers)
        self.model.to(self.device)
        
        # Training components
        self.criterion = nn.MSELoss()
        self.optimizer = None
        self.scaler = None
        
        # Training history
        self.history = {
            'train_loss': [],
            'val_loss': [],
            'epoch_times': []
        }
        
        logger.info(f"Trainer initialized with {input_size} features")
        logger.info(f"Architecture: {self.hidden_layers}")
        logger.info(f"Device: {self.device}")
    
    def prepare_data(
        self,
        X: np.ndarray,
        validation_split: float = 0.2,
        batch_size: int = 64,
        fit_scaler: bool = True
    ) -> Tuple[DataLoader, DataLoader]:
        """
        Prepare data for training.
        
        Args:
            X: Feature matrix (num_samples, num_features)
            validation_split: Fraction of data for validation
            batch_size: Batch size for training
            fit_scaler: Whether to fit scaler on training data
        
        Returns:
            Tuple of (train_loader, val_loader)
        """
        # Split data
        split_idx = int(len(X) * (1 - validation_split))
        X_train = X[:split_idx]
        X_val = X[split_idx:]
        
        logger.info(f"Training samples: {len(X_train)}, Validation samples: {len(X_val)}")
        
        # Fit and apply scaler
        if fit_scaler:
            from sklearn.preprocessing import StandardScaler
            self.scaler = StandardScaler()
            X_train = self.scaler.fit_transform(X_train)
            X_val = self.scaler.transform(X_val)
            logger.info("StandardScaler fitted on training data")
        else:
            if self.scaler is not None:
                X_train = self.scaler.transform(X_train)
                X_val = self.scaler.transform(X_val)
        
        # Convert to tensors
        X_train_tensor = torch.FloatTensor(X_train)
        X_val_tensor = torch.FloatTensor(X_val)
        
        # Create dataloaders
        train_dataset = TensorDataset(X_train_tensor, X_train_tensor)  # Target = input
        val_dataset = TensorDataset(X_val_tensor, X_val_tensor)
        
        train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
        val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)
        
        return train_loader, val_loader
    
    def train_epoch(self, train_loader: DataLoader) -> float:
        """Train for one epoch."""
        self.model.train()
        total_loss = 0
        num_batches = 0
        
        for batch_x, _ in train_loader:
            batch_x = batch_x.to(self.device)
            
            # Forward pass
            self.optimizer.zero_grad()
            reconstructed = self.model(batch_x)
            loss = self.criterion(reconstructed, batch_x)
            
            # Backward pass
            loss.backward()
            self.optimizer.step()
            
            total_loss += loss.item()
            num_batches += 1
        
        return total_loss / num_batches
    
    def validate(self, val_loader: DataLoader) -> Tuple[float, np.ndarray]:
        """
        Validate model and compute reconstruction errors.
        
        Returns:
            Tuple of (average loss, array of reconstruction errors)
        """
        self.model.eval()
        total_loss = 0
        num_batches = 0
        errors = []
        
        with torch.no_grad():
            for batch_x, _ in val_loader:
                batch_x = batch_x.to(self.device)
                
                # Forward pass
                reconstructed = self.model(batch_x)
                loss = self.criterion(reconstructed, batch_x)
                
                # Compute per-sample reconstruction errors
                batch_errors = torch.mean((batch_x - reconstructed) ** 2, dim=1)
                errors.extend(batch_errors.cpu().numpy())
                
                total_loss += loss.item()
                num_batches += 1
        
        return total_loss / num_batches, np.array(errors)
    
    def train(
        self,
        X: np.ndarray,
        validation_split: float = None,
        batch_size: int = None,
        learning_rate: float = None,
        max_epochs: int = None,
        early_stopping_patience: int = None
    ) -> Dict:
        """
        Train autoencoder on normal traffic.
        
        Args:
            X: Feature matrix of normal traffic
            validation_split: Fraction for validation
            batch_size: Batch size
            learning_rate: Learning rate
            max_epochs: Maximum number of epochs
            early_stopping_patience: Patience for early stopping
        
        Returns:
            Dictionary with training results
        """
        # Use settings defaults if not provided
        validation_split = validation_split or settings.VALIDATION_SPLIT
        batch_size = batch_size or settings.BATCH_SIZE
        learning_rate = learning_rate or settings.LEARNING_RATE
        max_epochs = max_epochs or settings.MAX_EPOCHS
        early_stopping_patience = early_stopping_patience or settings.EARLY_STOPPING_PATIENCE
        
        logger.info(f"Starting training with {len(X)} samples")
        logger.info(f"Config: lr={learning_rate}, batch_size={batch_size}, max_epochs={max_epochs}")
        
        # Prepare data
        train_loader, val_loader = self.prepare_data(X, validation_split, batch_size)
        
        # Setup optimizer
        self.optimizer = optim.Adam(self.model.parameters(), lr=learning_rate)
        
        # Training loop
        best_val_loss = float('inf')
        patience_counter = 0
        start_time = datetime.now()
        
        for epoch in range(max_epochs):
            epoch_start = datetime.now()
            
            # Train
            train_loss = self.train_epoch(train_loader)
            
            # Validate
            val_loss, val_errors = self.validate(val_loader)
            
            epoch_time = (datetime.now() - epoch_start).total_seconds()
            
            # Record history
            self.history['train_loss'].append(train_loss)
            self.history['val_loss'].append(val_loss)
            self.history['epoch_times'].append(epoch_time)
            
            logger.info(
                f"Epoch {epoch+1}/{max_epochs} | "
                f"Train Loss: {train_loss:.6f} | "
                f"Val Loss: {val_loss:.6f} | "
                f"Time: {epoch_time:.2f}s"
            )
            
            # Early stopping
            if val_loss < best_val_loss:
                best_val_loss = val_loss
                patience_counter = 0
                # Save best model
                self._save_checkpoint('best_model.pth')
            else:
                patience_counter += 1
                if patience_counter >= early_stopping_patience:
                    logger.info(f"Early stopping triggered after {epoch+1} epochs")
                    break
        
        training_duration = (datetime.now() - start_time).total_seconds()
        logger.info(f"Training completed in {training_duration:.2f} seconds")
        
        # Load best model
        self._load_checkpoint('best_model.pth')
        
        # Calculate threshold from validation errors
        _, val_errors = self.validate(val_loader)
        threshold_percentile = settings.ANOMALY_THRESHOLD_PERCENTILE
        threshold = np.percentile(val_errors, threshold_percentile)
        
        logger.info(f"Anomaly threshold ({threshold_percentile}th percentile): {threshold:.6f}")
        
        return {
            'best_val_loss': best_val_loss,
            'threshold': float(threshold),
            'threshold_percentile': threshold_percentile,
            'training_duration': training_duration,
            'num_epochs': len(self.history['train_loss']),
            'training_samples': len(train_loader.dataset),
            'validation_samples': len(val_loader.dataset)
        }
    
    def _save_checkpoint(self, filename: str):
        """Save model checkpoint."""
        checkpoint_path = self.artifacts_dir / filename
        torch.save(self.model.state_dict(), checkpoint_path)
    
    def _load_checkpoint(self, filename: str):
        """Load model checkpoint."""
        checkpoint_path = self.artifacts_dir / filename
        self.model.load_state_dict(torch.load(checkpoint_path, map_location=self.device))
    
    def save_artifacts(self, model_metadata: Dict) -> Dict[str, Path]:
        """
        Save all training artifacts.
        
        Args:
            model_metadata: Additional metadata to save
        
        Returns:
            Dictionary of saved file paths
        """
        paths = {}
        
        # Save model
        model_path = self.artifacts_dir / settings.AUTOENCODER_MODEL_FILE
        torch.save(self.model.state_dict(), model_path)
        paths['model'] = model_path
        logger.info(f"Model saved to {model_path}")
        
        # Save scaler
        if self.scaler is not None:
            scaler_path = self.artifacts_dir / settings.SCALER_FILE
            joblib.dump(self.scaler, scaler_path)
            paths['scaler'] = scaler_path
            logger.info(f"Scaler saved to {scaler_path}")
        
        # Save metadata (including threshold)
        metadata = {
            'created_at': datetime.now().isoformat(),
            'architecture': self.model.get_architecture(),
            'input_size': self.input_size,
            'device': self.device,
            'history': self.history,
            **model_metadata
        }
        
        metadata_path = self.artifacts_dir / settings.THRESHOLD_FILE
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        paths['metadata'] = metadata_path
        logger.info(f"Metadata saved to {metadata_path}")
        
        return paths
