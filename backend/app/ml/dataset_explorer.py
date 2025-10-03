import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
from typing import Dict, List, Tuple
import json


class DatasetExplorer:
    def __init__(self, data_dir: str = "./data/raw"):
        self.data_dir = Path(data_dir)
        self.report = {}
    
    def explore_csv_files(self, dataset_name: str) -> Dict:
        dataset_path = self.data_dir / dataset_name
        
        if not dataset_path.exists():
            print(f"Dataset {dataset_name} not found at {dataset_path}")
            return {}
        
        print(f"\n{'='*60}")
        print(f"Exploring: {dataset_name}")
        print(f"{'='*60}")
        
        csv_files = list(dataset_path.rglob("*.csv"))
        
        if not csv_files:
            print(f"No CSV files found in {dataset_path}")
            return {}
        
        dataset_info = {
            "name": dataset_name,
            "path": str(dataset_path),
            "files": []
        }
        
        for csv_file in csv_files:
            print(f"\nFile: {csv_file.name}")
            
            try:
                df = pd.read_csv(csv_file, nrows=1000)
                
                file_info = {
                    "filename": csv_file.name,
                    "shape": df.shape,
                    "columns": list(df.columns),
                    "dtypes": {col: str(dtype) for col, dtype in df.dtypes.items()},
                    "missing_values": df.isnull().sum().to_dict(),
                    "sample_values": {}
                }
                
                print(f"  Shape: {df.shape}")
                print(f"  Columns: {len(df.columns)}")
                print(f"  Memory: {df.memory_usage(deep=True).sum() / 1024**2:.2f} MB")
                
                label_column = self._detect_label_column(df)
                if label_column:
                    print(f"  Label column: {label_column}")
                    print(f"  Classes: {df[label_column].unique()[:10]}")
                    print(f"  Class distribution:")
                    class_dist = df[label_column].value_counts()
                    for cls, count in class_dist.head(10).items():
                        print(f"    {cls}: {count}")
                    
                    file_info["label_column"] = label_column
                    file_info["classes"] = list(df[label_column].unique()[:20])
                    file_info["class_distribution"] = class_dist.head(20).to_dict()
                
                dataset_info["files"].append(file_info)
                
            except Exception as e:
                print(f"  Error reading file: {e}")
        
        self.report[dataset_name] = dataset_info
        return dataset_info
    
    def _detect_label_column(self, df: pd.DataFrame) -> str:
        possible_names = ['label', 'attack', 'class', 'type', 'category', 'attack_type', 
                         'Label', 'Attack', 'Class', 'Type', 'Category']
        
        for name in possible_names:
            if name in df.columns:
                return name
        
        for col in df.columns:
            if df[col].dtype == 'object' and df[col].nunique() < 50:
                return col
        
        return None
    
    def explore_all(self):
        datasets = ["tii-ssrc-23", "ics-flow", "nsl-kdd", "unsw-nb15", "cse-cic-ids2018"]
        
        for dataset in datasets:
            self.explore_csv_files(dataset)
        
        self.save_report()
    
    def save_report(self, output_file: str = "./data/exploration_report.json"):
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Convert numpy types to Python native types
        def convert_numpy(obj):
            if isinstance(obj, np.integer):
                return int(obj)
            elif isinstance(obj, np.floating):
                return float(obj)
            elif isinstance(obj, np.ndarray):
                return obj.tolist()
            elif isinstance(obj, dict):
                return {k: convert_numpy(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_numpy(item) for item in obj]
            return obj
        
        with open(output_path, 'w') as f:
            json.dump(convert_numpy(self.report), f, indent=2)
        
        print(f"\n{'='*60}")
        print(f"Exploration report saved to: {output_path}")
        print(f"{'='*60}")


def explore_all_datasets():
    """Entry point for poetry script"""
    explorer = DatasetExplorer()
    explorer.explore_all()


if __name__ == "__main__":
    explore_all_datasets()
