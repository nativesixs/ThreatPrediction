import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import numpy as np
from pathlib import Path
from typing import Dict, Tuple
import json
import time
from datetime import datetime
from tqdm import tqdm

from app.ml.models import LSTMModel, CNNModel


class ModelTrainer:
    def __init__(self, model_type: str, input_size: int, num_classes: int,
                 device: str = None, model_dir: str = "./models"):
        self.model_type = model_type
        self.input_size = input_size
        self.num_classes = num_classes
        self.device = device if device else ('cuda' if torch.cuda.is_available() else 'cpu')
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
        self.model = self._create_model()
        self.model.to(self.device)
        
        self.criterion = nn.CrossEntropyLoss()
        self.optimizer = None
        self.history = {
            'train_loss': [],
            'val_loss': [],
            'train_acc': [],
            'val_acc': []
        }
        
    def _create_model(self):
        if self.model_type.lower() == 'lstm':
            return LSTMModel(
                input_size=self.input_size,
                hidden_size=128,
                num_layers=2,
                num_classes=self.num_classes,
                dropout=0.3
            )
        elif self.model_type.lower() == 'cnn':
            return CNNModel(
                input_size=self.input_size,
                num_classes=self.num_classes,
                dropout=0.3
            )
        else:
            raise ValueError(f"Unknown model type: {self.model_type}")
    
    def prepare_dataloaders(self, X_train: np.ndarray, y_train: np.ndarray,
                          X_val: np.ndarray, y_val: np.ndarray,
                          batch_size: int = 64) -> Tuple[DataLoader, DataLoader]:
        X_train_tensor = torch.FloatTensor(X_train)
        y_train_tensor = torch.LongTensor(y_train)
        X_val_tensor = torch.FloatTensor(X_val)
        y_val_tensor = torch.LongTensor(y_val)
        
        train_dataset = TensorDataset(X_train_tensor, y_train_tensor)
        val_dataset = TensorDataset(X_val_tensor, y_val_tensor)
        
        train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
        val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)
        
        return train_loader, val_loader
    
    def train_epoch(self, train_loader: DataLoader) -> Tuple[float, float]:
        self.model.train()
        total_loss = 0
        correct = 0
        total = 0
        
        pbar = tqdm(train_loader, desc="Training", leave=False)
        for inputs, labels in pbar:
            inputs, labels = inputs.to(self.device), labels.to(self.device)
            
            self.optimizer.zero_grad()
            outputs = self.model(inputs)
            loss = self.criterion(outputs, labels)
            loss.backward()
            self.optimizer.step()
            
            total_loss += loss.item()
            _, predicted = torch.max(outputs.data, 1)
            total += labels.size(0)
            correct += (predicted == labels).sum().item()
            
            # Update progress bar
            pbar.set_postfix({
                'loss': f'{loss.item():.4f}',
                'acc': f'{100 * correct / total:.2f}%'
            })
        
        avg_loss = total_loss / len(train_loader)
        accuracy = 100 * correct / total
        
        return avg_loss, accuracy
    
    def validate(self, val_loader: DataLoader) -> Tuple[float, float]:
        self.model.eval()
        total_loss = 0
        correct = 0
        total = 0
        
        pbar = tqdm(val_loader, desc="Validating", leave=False)
        
        with torch.no_grad():
            for inputs, labels in pbar:
                inputs, labels = inputs.to(self.device), labels.to(self.device)
                
                outputs = self.model(inputs)
                loss = self.criterion(outputs, labels)
                
                total_loss += loss.item()
                _, predicted = torch.max(outputs.data, 1)
                total += labels.size(0)
                correct += (predicted == labels).sum().item()
                
                # Update progress bar
                pbar.set_postfix({
                    'loss': f'{loss.item():.4f}',
                    'acc': f'{100 * correct / total:.2f}%'
                })
        
        avg_loss = total_loss / len(val_loader)
        accuracy = 100 * correct / total
        
        return avg_loss, accuracy
    
    def train(self, X_train: np.ndarray, y_train: np.ndarray,
             X_val: np.ndarray, y_val: np.ndarray,
             epochs: int = 50, batch_size: int = 64,
             learning_rate: float = 0.001, patience: int = 10) -> Dict:
        
        print(f"\nTraining {self.model_type.upper()} model...")
        print(f"Device: {self.device}")
        print(f"Train samples: {len(X_train)}, Val samples: {len(X_val)}")
        
        self.optimizer = optim.Adam(self.model.parameters(), lr=learning_rate)
        train_loader, val_loader = self.prepare_dataloaders(
            X_train, y_train, X_val, y_val, batch_size
        )
        
        best_val_loss = float('inf')
        patience_counter = 0
        start_time = time.time()
        
        for epoch in range(epochs):
            train_loss, train_acc = self.train_epoch(train_loader)
            val_loss, val_acc = self.validate(val_loader)
            
            self.history['train_loss'].append(train_loss)
            self.history['val_loss'].append(val_loss)
            self.history['train_acc'].append(train_acc)
            self.history['val_acc'].append(val_acc)
            
            print(f"Epoch {epoch+1}/{epochs} - "
                  f"Train Loss: {train_loss:.4f}, Train Acc: {train_acc:.2f}% - "
                  f"Val Loss: {val_loss:.4f}, Val Acc: {val_acc:.2f}%")
            
            if val_loss < best_val_loss:
                best_val_loss = val_loss
                patience_counter = 0
                self.save_model(f"best_{self.model_type.lower()}_model.pth")
            else:
                patience_counter += 1
                if patience_counter >= patience:
                    print(f"Early stopping triggered after {epoch+1} epochs")
                    break
        
        training_time = time.time() - start_time
        
        return {
            'model_type': self.model_type,
            'epochs_trained': epoch + 1,
            'best_val_loss': best_val_loss,
            'final_train_acc': self.history['train_acc'][-1],
            'final_val_acc': self.history['val_acc'][-1],
            'training_time_seconds': training_time,
            'device': self.device
        }
    
    def save_model(self, filename: str):
        model_path = self.model_dir / filename
        torch.save({
            'model_state_dict': self.model.state_dict(),
            'model_type': self.model_type,
            'input_size': self.input_size,
            'num_classes': self.num_classes,
            'history': self.history
        }, model_path)
        
    def save_history(self, dataset_name: str):
        history_path = self.model_dir / f"{dataset_name}_{self.model_type.lower()}_history.json"
        with open(history_path, 'w') as f:
            json.dump(self.history, f, indent=2)
