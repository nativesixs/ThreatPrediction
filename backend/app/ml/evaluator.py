import torch
import numpy as np
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score, roc_curve
)
from typing import Dict, Tuple
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import json

from app.ml.models import LSTMModel, CNNModel


class ModelEvaluator:
    def __init__(self, model_path: str, device: str = None):
        self.device = device if device else ('cuda' if torch.cuda.is_available() else 'cpu')
        self.model_path = Path(model_path)
        self.model = None
        self.model_type = None
        self.load_model()
        
    def load_model(self):
        checkpoint = torch.load(self.model_path, map_location=self.device)
        
        self.model_type = checkpoint['model_type']
        input_size = checkpoint['input_size']
        num_classes = checkpoint['num_classes']
        
        if self.model_type.lower() == 'lstm':
            self.model = LSTMModel(
                input_size=input_size,
                hidden_size=128,
                num_layers=2,
                num_classes=num_classes,
                dropout=0.3
            )
        elif self.model_type.lower() == 'cnn':
            self.model = CNNModel(
                input_size=input_size,
                num_classes=num_classes,
                dropout=0.3
            )
        
        self.model.load_state_dict(checkpoint['model_state_dict'])
        self.model.to(self.device)
        self.model.eval()
    
    def predict(self, X: np.ndarray, batch_size: int = 64) -> Tuple[np.ndarray, np.ndarray]:
        self.model.eval()
        
        X_tensor = torch.FloatTensor(X).to(self.device)
        predictions = []
        probabilities = []
        
        with torch.no_grad():
            for i in range(0, len(X), batch_size):
                batch = X_tensor[i:i+batch_size]
                outputs = self.model(batch)
                probs = torch.softmax(outputs, dim=1)
                _, preds = torch.max(outputs, 1)
                
                predictions.extend(preds.cpu().numpy())
                probabilities.extend(probs.cpu().numpy())
        
        return np.array(predictions), np.array(probabilities)
    
    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray, 
                label_mapping: Dict[int, str]) -> Dict:
        print(f"\nEvaluating {self.model_type.upper()} model...")
        print(f"Test samples: {len(X_test)}")
        
        y_pred, y_prob = self.predict(X_test)
        
        metrics = {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision_macro': precision_score(y_test, y_pred, average='macro', zero_division=0),
            'recall_macro': recall_score(y_test, y_pred, average='macro', zero_division=0),
            'f1_macro': f1_score(y_test, y_pred, average='macro', zero_division=0),
            'precision_weighted': precision_score(y_test, y_pred, average='weighted', zero_division=0),
            'recall_weighted': recall_score(y_test, y_pred, average='weighted', zero_division=0),
            'f1_weighted': f1_score(y_test, y_pred, average='weighted', zero_division=0),
        }
        
        cm = confusion_matrix(y_test, y_pred)
        metrics['confusion_matrix'] = cm.tolist()
        
        # Get unique labels present in test set
        unique_labels = sorted(set(y_test.tolist() + y_pred.tolist()))
        class_names = [label_mapping[i] for i in unique_labels]
        report = classification_report(y_test, y_pred, labels=unique_labels,
                                      target_names=class_names,
                                      output_dict=True, zero_division=0)
        metrics['classification_report'] = report
        
        print(f"\nOverall Metrics:")
        print(f"  Accuracy:  {metrics['accuracy']:.4f}")
        print(f"  Precision: {metrics['precision_weighted']:.4f}")
        print(f"  Recall:    {metrics['recall_weighted']:.4f}")
        print(f"  F1-Score:  {metrics['f1_weighted']:.4f}")
        
        return metrics
    
    def plot_confusion_matrix(self, cm: np.ndarray, label_mapping: Dict[int, str], 
                             output_path: Path):
        class_names = [label_mapping[i] for i in sorted(label_mapping.keys())]
        
        plt.figure(figsize=(10, 8))
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                   xticklabels=class_names, yticklabels=class_names)
        plt.title(f'Confusion Matrix - {self.model_type.upper()}')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        plt.tight_layout()
        plt.savefig(output_path)
        plt.close()
        
        print(f"Confusion matrix saved to {output_path}")
    
    def plot_metrics_comparison(self, metrics: Dict, output_path: Path):
        metric_names = ['Accuracy', 'Precision', 'Recall', 'F1-Score']
        metric_values = [
            metrics['accuracy'],
            metrics['precision_weighted'],
            metrics['recall_weighted'],
            metrics['f1_weighted']
        ]
        
        plt.figure(figsize=(10, 6))
        bars = plt.bar(metric_names, metric_values, color=['#3498db', '#2ecc71', '#f39c12', '#e74c3c'])
        plt.ylim(0, 1.0)
        plt.ylabel('Score')
        plt.title(f'Model Performance - {self.model_type.upper()}')
        
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height,
                    f'{height:.3f}',
                    ha='center', va='bottom')
        
        plt.tight_layout()
        plt.savefig(output_path)
        plt.close()
        
        print(f"Metrics plot saved to {output_path}")
    
    def plot_roc_curves(self, y_test: np.ndarray, y_prob: np.ndarray, 
                       label_mapping: Dict[int, str], output_path: Path):
        n_classes = len(label_mapping)
        
        if n_classes == 2:
            fpr, tpr, _ = roc_curve(y_test, y_prob[:, 1])
            roc_auc = roc_auc_score(y_test, y_prob[:, 1])
            
            plt.figure(figsize=(8, 6))
            plt.plot(fpr, tpr, color='darkorange', lw=2, 
                    label=f'ROC curve (AUC = {roc_auc:.2f})')
            plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
            plt.xlim([0.0, 1.0])
            plt.ylim([0.0, 1.05])
            plt.xlabel('False Positive Rate')
            plt.ylabel('True Positive Rate')
            plt.title(f'ROC Curve - {self.model_type.upper()}')
            plt.legend(loc="lower right")
            plt.tight_layout()
            plt.savefig(output_path)
            plt.close()
        else:
            from sklearn.preprocessing import label_binarize
            y_test_bin = label_binarize(y_test, classes=list(range(n_classes)))
            
            plt.figure(figsize=(10, 8))
            class_names = [label_mapping[i] for i in sorted(label_mapping.keys())]
            
            for i in range(min(n_classes, 5)):
                fpr, tpr, _ = roc_curve(y_test_bin[:, i], y_prob[:, i])
                roc_auc = roc_auc_score(y_test_bin[:, i], y_prob[:, i])
                plt.plot(fpr, tpr, lw=2, 
                        label=f'{class_names[i]} (AUC = {roc_auc:.2f})')
            
            plt.plot([0, 1], [0, 1], 'k--', lw=2)
            plt.xlim([0.0, 1.0])
            plt.ylim([0.0, 1.05])
            plt.xlabel('False Positive Rate')
            plt.ylabel('True Positive Rate')
            plt.title(f'ROC Curves - {self.model_type.upper()} (Top 5 Classes)')
            plt.legend(loc="lower right")
            plt.tight_layout()
            plt.savefig(output_path)
            plt.close()
        
        print(f"ROC curves saved to {output_path}")
    
    def save_evaluation_report(self, metrics: Dict, dataset_name: str, output_dir: Path):
        output_dir.mkdir(parents=True, exist_ok=True)
        
        report_path = output_dir / f"{dataset_name}_{self.model_type.lower()}_evaluation.json"
        with open(report_path, 'w') as f:
            json.dump(metrics, f, indent=2)
        
        print(f"Evaluation report saved to {report_path}")
