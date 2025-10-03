import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import pickle
from pathlib import Path
from typing import Tuple, Dict, List
import json


class FeatureExtractor:
    def __init__(self, output_dir: str = "./data/processed"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_columns = []
        self.label_mapping = {}
        
    def load_dataset(self, dataset_path: Path) -> pd.DataFrame:
        csv_files = list(dataset_path.rglob("*.csv"))
        
        if not csv_files:
            raise ValueError(f"No CSV files found in {dataset_path}")
        
        dfs = []
        for csv_file in csv_files:
            try:
                df = pd.read_csv(csv_file, low_memory=False)
                dfs.append(df)
            except Exception as e:
                print(f"Warning: Could not load {csv_file}: {e}")
        
        if not dfs:
            raise ValueError(f"Failed to load any CSV files from {dataset_path}")
        
        return pd.concat(dfs, ignore_index=True)
    
    def identify_label_column(self, df: pd.DataFrame) -> str:
        possible_names = ['label', 'attack', 'class', 'type', 'category', 'attack_type',
                         'Label', 'Attack', 'Class', 'Type', 'Category', 'attack_cat']
        
        for name in possible_names:
            if name in df.columns:
                return name
        
        for col in df.columns:
            if df[col].dtype == 'object' and df[col].nunique() < 100:
                return col
        
        raise ValueError("Could not identify label column")
    
    def clean_data(self, df: pd.DataFrame) -> pd.DataFrame:
        df = df.copy()
        
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        
        numeric_columns = df.select_dtypes(include=[np.number]).columns
        df[numeric_columns] = df[numeric_columns].fillna(df[numeric_columns].median())
        
        categorical_columns = df.select_dtypes(include=['object']).columns
        for col in categorical_columns:
            df[col] = df[col].fillna(df[col].mode()[0] if not df[col].mode().empty else 'unknown')
        
        return df
    
    def extract_features(self, df: pd.DataFrame, label_column: str) -> Tuple[pd.DataFrame, pd.Series]:
        df = self.clean_data(df)
        
        X = df.drop(columns=[label_column])
        y = df[label_column]
        
        categorical_columns = X.select_dtypes(include=['object']).columns
        for col in categorical_columns:
            le = LabelEncoder()
            X[col] = le.fit_transform(X[col].astype(str))
        
        if X.isnull().any().any():
            X = X.fillna(0)
        
        self.feature_columns = list(X.columns)
        
        return X, y
    
    def normalize_labels(self, y: pd.Series) -> Tuple[np.ndarray, Dict[int, str]]:
        y = y.astype(str).str.lower().str.strip()
        
        attack_mapping = {
            'normal': 'normal',
            'benign': 'normal',
            'ddos': 'ddos',
            'dos': 'ddos',
            'probe': 'probe',
            'scan': 'probe',
            'portscan': 'probe',
            'u2r': 'privilege_escalation',
            'r2l': 'unauthorized_access',
            'brute': 'brute_force',
            'bruteforce': 'brute_force',
            'bot': 'botnet',
            'infiltration': 'infiltration',
            'web': 'web_attack',
            'injection': 'injection',
        }
        
        y_normalized = y.copy()
        for old_label, new_label in attack_mapping.items():
            y_normalized = y_normalized.str.replace(old_label, new_label, regex=False)
        
        y_encoded = self.label_encoder.fit_transform(y_normalized)
        
        self.label_mapping = {
            i: label for i, label in enumerate(self.label_encoder.classes_)
        }
        
        return y_encoded, self.label_mapping
    
    def scale_features(self, X_train: pd.DataFrame, X_val: pd.DataFrame, 
                      X_test: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_val_scaled = self.scaler.transform(X_val)
        X_test_scaled = self.scaler.transform(X_test)
        
        return X_train_scaled, X_val_scaled, X_test_scaled
    
    def create_splits(self, X: pd.DataFrame, y: np.ndarray, 
                     test_size: float = 0.2, val_size: float = 0.1,
                     random_state: int = 42) -> Tuple:
        X_temp, X_test, y_temp, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )
        
        val_ratio = val_size / (1 - test_size)
        X_train, X_val, y_train, y_val = train_test_split(
            X_temp, y_temp, test_size=val_ratio, random_state=random_state, stratify=y_temp
        )
        
        X_train_scaled, X_val_scaled, X_test_scaled = self.scale_features(
            X_train, X_val, X_test
        )
        
        return X_train_scaled, X_val_scaled, X_test_scaled, y_train, y_val, y_test
    
    def save_artifacts(self, dataset_name: str):
        scaler_path = self.output_dir / f"{dataset_name}_scaler.pkl"
        with open(scaler_path, 'wb') as f:
            pickle.dump(self.scaler, f)
        
        label_encoder_path = self.output_dir / f"{dataset_name}_label_encoder.pkl"
        with open(label_encoder_path, 'wb') as f:
            pickle.dump(self.label_encoder, f)
        
        metadata = {
            "feature_columns": self.feature_columns,
            "label_mapping": self.label_mapping,
            "n_features": len(self.feature_columns),
            "n_classes": len(self.label_mapping)
        }
        
        metadata_path = self.output_dir / f"{dataset_name}_metadata.json"
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        print(f"Artifacts saved to {self.output_dir}")
    
    def process_dataset(self, dataset_path: Path, dataset_name: str) -> Dict:
        print(f"\nProcessing {dataset_name}...")
        
        df = self.load_dataset(dataset_path)
        print(f"Loaded {len(df)} samples")
        
        label_column = self.identify_label_column(df)
        print(f"Identified label column: {label_column}")
        
        X, y = self.extract_features(df, label_column)
        print(f"Extracted {X.shape[1]} features")
        
        y_encoded, label_mapping = self.normalize_labels(y)
        print(f"Classes: {list(label_mapping.values())}")
        
        X_train, X_val, X_test, y_train, y_val, y_test = self.create_splits(X, y_encoded)
        
        print(f"Train: {X_train.shape[0]}, Val: {X_val.shape[0]}, Test: {X_test.shape[0]}")
        
        output_data = {
            "X_train": X_train,
            "X_val": X_val,
            "X_test": X_test,
            "y_train": y_train,
            "y_val": y_val,
            "y_test": y_test
        }
        
        for key, data in output_data.items():
            output_path = self.output_dir / f"{dataset_name}_{key}.npy"
            np.save(output_path, data)
        
        self.save_artifacts(dataset_name)
        
        return {
            "dataset_name": dataset_name,
            "n_samples": len(df),
            "n_features": X.shape[1],
            "n_classes": len(label_mapping),
            "label_mapping": label_mapping,
            "train_size": len(y_train),
            "val_size": len(y_val),
            "test_size": len(y_test)
        }
