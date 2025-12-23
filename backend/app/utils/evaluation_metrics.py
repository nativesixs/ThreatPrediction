"""
Enhanced evaluation metrics for multi-class threat detection.
Provides per-class precision, recall, F1, ROC curves, and confusion matrices.
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_curve, auc,
    precision_recall_curve, average_precision_score
)
from typing import Dict, List, Tuple, Any
import json
import logging
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)

class ThreatDetectionEvaluator:
    """Enhanced evaluator for threat detection with per-class analysis"""
    
    def __init__(self, class_names: List[str] = None):
        self.class_names = class_names or ['NORMAL', 'DOS', 'PROBE', 'EXPLOIT', 'MALWARE']
        self.class_to_idx = {name: idx for idx, name in enumerate(self.class_names)}
        self.results_dir = Path("logs/evaluation")
        self.results_dir.mkdir(parents=True, exist_ok=True)
    
    def evaluate_predictions(self, y_true: List[str], y_pred: List[str], 
                           y_proba: List[List[float]], save_plots: bool = True) -> Dict[str, Any]:
        """
        Comprehensive evaluation of predictions
        
        Args:
            y_true: True class labels
            y_pred: Predicted class labels  
            y_proba: Prediction probabilities for each class
            save_plots: Whether to save plots to disk
            
        Returns:
            Dictionary with all evaluation metrics
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        results = {
            'timestamp': timestamp,
            'total_samples': len(y_true),
            'class_distribution': self._get_class_distribution(y_true),
            'overall_accuracy': self._calculate_accuracy(y_true, y_pred),
            'classification_report': self._get_classification_report(y_true, y_pred),
            'confusion_matrix': self._get_confusion_matrix(y_true, y_pred),
            'per_class_metrics': self._get_per_class_metrics(y_true, y_pred, y_proba),
            'roc_analysis': self._get_roc_analysis(y_true, y_proba),
            'threshold_analysis': self._analyze_thresholds(y_true, y_proba)
        }
        
        if save_plots:
            self._save_plots(results, timestamp)
        
        # Save results as JSON
        results_file = self.results_dir / f"evaluation_{timestamp}.json"
        with open(results_file, 'w') as f:
            # Convert numpy arrays to lists for JSON serialization
            json_results = self._convert_for_json(results)
            json.dump(json_results, f, indent=2)
        
        logger.info(f"Evaluation completed. Results saved to {results_file}")
        return results
    
    def _get_class_distribution(self, y_true: List[str]) -> Dict[str, int]:
        """Get distribution of true classes"""
        unique, counts = np.unique(y_true, return_counts=True)
        return dict(zip(unique, counts.tolist()))
    
    def _calculate_accuracy(self, y_true: List[str], y_pred: List[str]) -> float:
        """Calculate overall accuracy"""
        return np.mean(np.array(y_true) == np.array(y_pred))
    
    def _get_classification_report(self, y_true: List[str], y_pred: List[str]) -> Dict[str, Any]:
        """Get detailed classification report"""
        report = classification_report(y_true, y_pred, output_dict=True, zero_division=0)
        return report
    
    def _get_confusion_matrix(self, y_true: List[str], y_pred: List[str]) -> List[List[int]]:
        """Get confusion matrix"""
        labels = sorted(list(set(y_true + y_pred)))
        cm = confusion_matrix(y_true, y_pred, labels=labels)
        return cm.tolist()
    
    def _get_per_class_metrics(self, y_true: List[str], y_pred: List[str], 
                              y_proba: List[List[float]]) -> Dict[str, Dict[str, float]]:
        """Get detailed per-class metrics"""
        metrics = {}
        
        # Convert to numpy arrays
        y_true_arr = np.array(y_true)
        y_pred_arr = np.array(y_pred)
        y_proba_arr = np.array(y_proba)
        
        for class_name in self.class_names:
            if class_name not in set(y_true):
                continue
                
            # Binary classification for this class
            true_binary = (y_true_arr == class_name).astype(int)
            pred_binary = (y_pred_arr == class_name).astype(int)
            
            # Get class probabilities
            if class_name in self.class_to_idx and y_proba_arr.shape[1] > self.class_to_idx[class_name]:
                class_proba = y_proba_arr[:, self.class_to_idx[class_name]]
            else:
                class_proba = np.zeros(len(y_true))
            
            metrics[class_name] = {
                'true_positives': int(np.sum((true_binary == 1) & (pred_binary == 1))),
                'false_positives': int(np.sum((true_binary == 0) & (pred_binary == 1))),
                'true_negatives': int(np.sum((true_binary == 0) & (pred_binary == 0))),
                'false_negatives': int(np.sum((true_binary == 1) & (pred_binary == 0))),
                'precision': float(self._safe_divide(
                    np.sum((true_binary == 1) & (pred_binary == 1)),
                    np.sum(pred_binary == 1)
                )),
                'recall': float(self._safe_divide(
                    np.sum((true_binary == 1) & (pred_binary == 1)),
                    np.sum(true_binary == 1)
                )),
                'f1_score': 0.0,  # Will calculate after precision/recall
                'support': int(np.sum(true_binary == 1)),
                'avg_confidence': float(np.mean(class_proba[pred_binary == 1])) if np.sum(pred_binary == 1) > 0 else 0.0,
                'max_confidence': float(np.max(class_proba)) if len(class_proba) > 0 else 0.0,
                'min_confidence': float(np.min(class_proba)) if len(class_proba) > 0 else 0.0
            }
            
            # Calculate F1 score
            p = metrics[class_name]['precision']
            r = metrics[class_name]['recall']
            metrics[class_name]['f1_score'] = float(self._safe_divide(2 * p * r, p + r))
        
        return metrics
    
    def _get_roc_analysis(self, y_true: List[str], y_proba: List[List[float]]) -> Dict[str, Any]:
        """Analyze ROC curves for each class"""
        roc_data = {}
        y_proba_arr = np.array(y_proba)
        
        for class_name in self.class_names:
            if class_name not in set(y_true) or class_name not in self.class_to_idx:
                continue
            
            # Binary labels for this class
            y_binary = (np.array(y_true) == class_name).astype(int)
            class_idx = self.class_to_idx[class_name]
            
            if y_proba_arr.shape[1] > class_idx:
                class_proba = y_proba_arr[:, class_idx]
                
                # Calculate ROC curve
                fpr, tpr, thresholds = roc_curve(y_binary, class_proba)
                roc_auc = auc(fpr, tpr)
                
                # Calculate precision-recall curve
                precision, recall, pr_thresholds = precision_recall_curve(y_binary, class_proba)
                avg_precision = average_precision_score(y_binary, class_proba)
                
                roc_data[class_name] = {
                    'fpr': fpr.tolist(),
                    'tpr': tpr.tolist(),
                    'thresholds': thresholds.tolist(),
                    'auc': float(roc_auc),
                    'precision': precision.tolist(),
                    'recall': recall.tolist(),
                    'pr_thresholds': pr_thresholds.tolist(),
                    'average_precision': float(avg_precision)
                }
        
        return roc_data
    
    def _analyze_thresholds(self, y_true: List[str], y_proba: List[List[float]]) -> Dict[str, Any]:
        """Analyze optimal thresholds for each class"""
        threshold_analysis = {}
        y_proba_arr = np.array(y_proba)
        
        for class_name in self.class_names:
            if class_name not in set(y_true) or class_name not in self.class_to_idx:
                continue
            
            y_binary = (np.array(y_true) == class_name).astype(int)
            class_idx = self.class_to_idx[class_name]
            
            if y_proba_arr.shape[1] > class_idx:
                class_proba = y_proba_arr[:, class_idx]
                
                # Find optimal threshold using different criteria
                thresholds = np.linspace(0, 1, 101)
                metrics = []
                
                for threshold in thresholds:
                    pred_binary = (class_proba >= threshold).astype(int)
                    
                    tp = np.sum((y_binary == 1) & (pred_binary == 1))
                    fp = np.sum((y_binary == 0) & (pred_binary == 1))
                    tn = np.sum((y_binary == 0) & (pred_binary == 0))
                    fn = np.sum((y_binary == 1) & (pred_binary == 0))
                    
                    precision = self._safe_divide(tp, tp + fp)
                    recall = self._safe_divide(tp, tp + fn)
                    f1 = self._safe_divide(2 * precision * recall, precision + recall)
                    fpr = self._safe_divide(fp, fp + tn)
                    
                    metrics.append({
                        'threshold': float(threshold),
                        'precision': float(precision),
                        'recall': float(recall),
                        'f1': float(f1),
                        'fpr': float(fpr),
                        'tp': int(tp), 'fp': int(fp), 'tn': int(tn), 'fn': int(fn)
                    })
                
                # Find best thresholds
                best_f1_idx = np.argmax([m['f1'] for m in metrics])
                best_precision_idx = np.argmax([m['precision'] for m in metrics])
                
                # Find threshold for 95% precision (if possible)
                high_precision_idx = next(
                    (i for i, m in enumerate(metrics) if m['precision'] >= 0.95),
                    best_precision_idx
                )
                
                threshold_analysis[class_name] = {
                    'all_metrics': metrics,
                    'best_f1_threshold': metrics[best_f1_idx]['threshold'],
                    'best_f1_score': metrics[best_f1_idx]['f1'],
                    'best_precision_threshold': metrics[best_precision_idx]['threshold'],
                    'best_precision_score': metrics[best_precision_idx]['precision'],
                    'high_precision_threshold': metrics[high_precision_idx]['threshold'],
                    'high_precision_score': metrics[high_precision_idx]['precision'],
                    'recommended_threshold': metrics[best_f1_idx]['threshold']  # Default to F1-optimal
                }
        
        return threshold_analysis
    
    def _save_plots(self, results: Dict[str, Any], timestamp: str):
        """Save evaluation plots"""
        # Confusion matrix heatmap
        if 'confusion_matrix' in results:
            plt.figure(figsize=(10, 8))
            cm = np.array(results['confusion_matrix'])
            labels = list(results['class_distribution'].keys())
            sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                       xticklabels=labels, yticklabels=labels)
            plt.title('Confusion Matrix')
            plt.ylabel('True Label')
            plt.xlabel('Predicted Label')
            plt.tight_layout()
            plt.savefig(self.results_dir / f"confusion_matrix_{timestamp}.png", dpi=300)
            plt.close()
        
        # ROC curves
        if 'roc_analysis' in results:
            plt.figure(figsize=(12, 8))
            for class_name, roc_data in results['roc_analysis'].items():
                plt.plot(roc_data['fpr'], roc_data['tpr'], 
                        label=f'{class_name} (AUC = {roc_data["auc"]:.3f})')
            
            plt.plot([0, 1], [0, 1], 'k--', label='Random')
            plt.xlim([0.0, 1.0])
            plt.ylim([0.0, 1.05])
            plt.xlabel('False Positive Rate')
            plt.ylabel('True Positive Rate')
            plt.title('ROC Curves by Class')
            plt.legend()
            plt.grid(True, alpha=0.3)
            plt.tight_layout()
            plt.savefig(self.results_dir / f"roc_curves_{timestamp}.png", dpi=300)
            plt.close()
        
        # Per-class metrics bar chart
        if 'per_class_metrics' in results:
            metrics_df = pd.DataFrame(results['per_class_metrics']).T
            
            fig, axes = plt.subplots(2, 2, figsize=(15, 10))
            
            # Precision
            metrics_df['precision'].plot(kind='bar', ax=axes[0,0], title='Precision by Class')
            axes[0,0].set_ylim(0, 1)
            axes[0,0].grid(True, alpha=0.3)
            
            # Recall
            metrics_df['recall'].plot(kind='bar', ax=axes[0,1], title='Recall by Class')
            axes[0,1].set_ylim(0, 1)
            axes[0,1].grid(True, alpha=0.3)
            
            # F1 Score
            metrics_df['f1_score'].plot(kind='bar', ax=axes[1,0], title='F1 Score by Class')
            axes[1,0].set_ylim(0, 1)
            axes[1,0].grid(True, alpha=0.3)
            
            # Support (sample count)
            metrics_df['support'].plot(kind='bar', ax=axes[1,1], title='Support by Class')
            axes[1,1].grid(True, alpha=0.3)
            
            plt.tight_layout()
            plt.savefig(self.results_dir / f"per_class_metrics_{timestamp}.png", dpi=300)
            plt.close()
    
    def _safe_divide(self, numerator: float, denominator: float) -> float:
        """Safe division to avoid division by zero"""
        return numerator / denominator if denominator != 0 else 0.0
    
    def _convert_for_json(self, obj):
        """Convert numpy arrays and other non-serializable objects for JSON"""
        if isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, dict):
            return {key: self._convert_for_json(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._convert_for_json(item) for item in obj]
        else:
            return obj

def evaluate_from_csv(predictions_file: str, output_dir: str = None) -> Dict[str, Any]:
    """
    Evaluate predictions from CSV file
    
    Args:
        predictions_file: Path to CSV file with predictions
        output_dir: Directory to save results (optional)
        
    Returns:
        Evaluation results dictionary
    """
    df = pd.read_csv(predictions_file)
    
    # Extract required columns
    y_true = df['attack_label'].fillna('NORMAL').tolist()  # Use ground truth if available
    y_pred = df['predicted_class'].tolist()
    
    # Parse probabilities from JSON strings
    y_proba = []
    class_names = ['NORMAL', 'DOS', 'PROBE', 'EXPLOIT', 'MALWARE']
    
    for prob_str in df['all_probabilities']:
        try:
            probs_dict = json.loads(prob_str)
            probs_list = [probs_dict.get(class_name, 0.0) for class_name in class_names]
            y_proba.append(probs_list)
        except:
            # Fallback to zero probabilities
            y_proba.append([0.0] * len(class_names))
    
    # Create evaluator and run evaluation
    evaluator = ThreatDetectionEvaluator(class_names)
    if output_dir:
        evaluator.results_dir = Path(output_dir)
        evaluator.results_dir.mkdir(parents=True, exist_ok=True)
    
    return evaluator.evaluate_predictions(y_true, y_pred, y_proba)