#!/usr/bin/env python3
"""
Train v10 model WITHOUT NSL-KDD dataset.
Uses only modern datasets: CIC-IDS2018 (2018), TII-SSRC-23 (2023), UNSW-NB15 (2015).
This should eliminate false positives caused by outdated 1999 attack patterns.
"""

import pandas as pd
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
from sklearn.preprocessing import StandardScaler
import pickle
import json
from pathlib import Path
from datetime import datetime
from sklearn.metrics import classification_report

print("=" * 70)
print("Training v10 Model - Modern Datasets Only (No NSL-KDD)")
print("=" * 70)

# Load data
print("\n[1/7] Loading unified datasets...")
df_train = pd.read_csv('data/processed/unified_train.csv')
df_val = pd.read_csv('data/processed/unified_val.csv')
df_test = pd.read_csv('data/processed/unified_test.csv')

print(f"  Original train size: {len(df_train):,}")
print(f"  Original val size: {len(df_val):,}")
print(f"  Original test size: {len(df_test):,}")

# Remove NSL-KDD data
print("\n[2/7] Removing NSL-KDD (1999) dataset...")
df_train_modern = df_train[df_train['dataset'] != 'nsl-kdd'].copy()
df_val_modern = df_val[df_val['dataset'] != 'nsl-kdd'].copy()
df_test_modern = df_test[df_test['dataset'] != 'nsl-kdd'].copy()

print(f"  ✓ Train: {len(df_train_modern):,} samples (removed {len(df_train) - len(df_train_modern):,})")
print(f"  ✓ Val: {len(df_val_modern):,} samples (removed {len(df_val) - len(df_val_modern):,})")
print(f"  ✓ Test: {len(df_test_modern):,} samples (removed {len(df_test) - len(df_test_modern):,})")

print("\n  Modern datasets included:")
for dataset in df_train_modern['dataset'].unique():
    count = len(df_train_modern[df_train_modern['dataset'] == dataset])
    print(f"    - {dataset}: {count:,} samples")

# Get feature columns
feature_cols = [c for c in df_train_modern.columns if c not in ['label_str', 'dataset', 'label_unified', 'label_numeric']]

# Fit NEW scaler on modern data only
print("\n[3/7] Fitting StandardScaler on modern data...")
X_train_raw = df_train_modern[feature_cols].values
scaler = StandardScaler()
scaler.fit(X_train_raw)

# Transform
X_train = torch.FloatTensor(scaler.transform(X_train_raw))
X_val = torch.FloatTensor(scaler.transform(df_val_modern[feature_cols].values))
X_test = torch.FloatTensor(scaler.transform(df_test_modern[feature_cols].values))

y_train = torch.LongTensor(df_train_modern['label_numeric'].values)
y_val = torch.LongTensor(df_val_modern['label_numeric'].values)
y_test = torch.LongTensor(df_test_modern['label_numeric'].values)

print(f"  ✓ Scaler statistics:")
print(f"    Mean range: [{scaler.mean_.min():.2f}, {scaler.mean_.max():.2f}]")
print(f"    Std range: [{scaler.scale_.min():.2f}, {scaler.scale_.max():.2f}]")

# Save modern scaler
with open('data/processed/unified_modern_scaler.pkl', 'wb') as f:
    pickle.dump(scaler, f)
print(f"  ✓ Saved scaler to unified_modern_scaler.pkl")

# Create dataloaders
train_dataset = TensorDataset(X_train, y_train)
val_dataset = TensorDataset(X_val, y_val)
test_dataset = TensorDataset(X_test, y_test)

train_loader = DataLoader(train_dataset, batch_size=128, shuffle=True)
val_loader = DataLoader(val_dataset, batch_size=256, shuffle=False)
test_loader = DataLoader(test_dataset, batch_size=256, shuffle=False)

# Define model
print("\n[4/7] Building LSTM model...")

class LSTMModel(nn.Module):
    def __init__(self, input_size=35, hidden_size=128, num_layers=2, num_classes=7, dropout=0.3):
        super().__init__()
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        self.lstm = nn.LSTM(input_size, hidden_size, num_layers, batch_first=True, dropout=dropout, bidirectional=True)
        self.fc = nn.Linear(hidden_size * 2, num_classes)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x):
        x = x.unsqueeze(1)
        lstm_out, _ = self.lstm(x)
        out = self.dropout(lstm_out[:, -1, :])
        out = self.fc(out)
        return out

device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
model = LSTMModel().to(device)
print(f"  ✓ Model on device: {device}")

# Calculate class weights
print("\n[5/7] Calculating class weights...")
class_counts = np.bincount(y_train.numpy())
total = len(y_train)
# Avoid divide by zero - set weight to 0 for classes with 0 samples
class_weights = torch.FloatTensor([
    total / (len(class_counts) * count) if count > 0 else 0.0
    for count in class_counts
]).to(device)
print(f"  ✓ Class weights: {class_weights.cpu().numpy()}")
print(f"  ✓ Classes present: {np.where(class_counts > 0)[0].tolist()}")

criterion = nn.CrossEntropyLoss(weight=class_weights)
optimizer = torch.optim.Adam(model.parameters(), lr=0.001)

# Training
print("\n[6/7] Training for 40 epochs...")
best_val_acc = 0
best_epoch = 0

for epoch in range(40):
    model.train()
    train_loss = 0
    train_correct = 0
    train_total = 0

    for batch_X, batch_y in train_loader:
        batch_X, batch_y = batch_X.to(device), batch_y.to(device)
        optimizer.zero_grad()
        outputs = model(batch_X)
        loss = criterion(outputs, batch_y)
        loss.backward()
        optimizer.step()

        train_loss += loss.item()
        _, predicted = outputs.max(1)
        train_total += batch_y.size(0)
        train_correct += predicted.eq(batch_y).sum().item()

    train_acc = 100. * train_correct / train_total

    # Validation
    model.eval()
    val_correct = 0
    val_total = 0

    with torch.no_grad():
        for batch_X, batch_y in val_loader:
            batch_X, batch_y = batch_X.to(device), batch_y.to(device)
            outputs = model(batch_X)
            _, predicted = outputs.max(1)
            val_total += batch_y.size(0)
            val_correct += predicted.eq(batch_y).sum().item()

    val_acc = 100. * val_correct / val_total
    print(f"  Epoch {epoch+1}/40 - Train Acc: {train_acc:.2f}% | Val Acc: {val_acc:.2f}%")

    if val_acc > best_val_acc:
        best_val_acc = val_acc
        best_epoch = epoch + 1
        torch.save(model.state_dict(), 'models/best_lstm_model_v10.pth')

print(f"\n  ✓ Best validation accuracy: {best_val_acc:.2f}% at epoch {best_epoch}")

# Test evaluation
print("\n[7/7] Evaluating on test set...")
model.load_state_dict(torch.load('models/best_lstm_model_v10.pth'))
model.eval()

test_correct = 0
test_total = 0
all_preds = []
all_labels = []

with torch.no_grad():
    for batch_X, batch_y in test_loader:
        batch_X, batch_y = batch_X.to(device), batch_y.to(device)
        outputs = model(batch_X)
        _, predicted = outputs.max(1)
        test_total += batch_y.size(0)
        test_correct += predicted.eq(batch_y).sum().item()
        all_preds.extend(predicted.cpu().numpy())
        all_labels.extend(batch_y.cpu().numpy())

test_acc = 100. * test_correct / test_total
print(f"  ✓ Test Accuracy: {test_acc:.2f}%")

# Per-class metrics
label_names = ['NORMAL', 'DOS', 'PROBE', 'R2L', 'U2R', 'MALWARE', 'EXPLOIT']
print('\nPer-class metrics:')
print(classification_report(all_labels, all_preds, target_names=label_names, zero_division=0))

# Save metadata
metadata = {
    'model_version': 'v10',
    'model_name': 'v10_modern_datasets_only',
    'training_date': datetime.now().strftime('%Y-%m-%d'),
    'scaler_type': 'StandardScaler',
    'epochs': 40,
    'test_accuracy': test_acc,
    'best_val_accuracy': best_val_acc,
    'datasets_used': ['cic-ids2018', 'tii-ssrc-23', 'unsw-nb15', 'ics-flow'],
    'datasets_excluded': ['nsl-kdd'],
    'training_samples': len(df_train_modern),
    'architecture': {
        'input_size': 35,
        'hidden_size': 128,
        'num_layers': 2,
        'num_classes': 7,
        'dropout': 0.3,
        'bidirectional': True
    },
    'label_mapping': {str(i): name for i, name in enumerate(label_names)}
}

with open('models/model_v10_metadata.json', 'w') as f:
    json.dump(metadata, f, indent=2)

print(f"  ✓ Saved metadata to models/model_v10_metadata.json")

print("\n" + "=" * 70)
print("✓ V10 MODEL TRAINING COMPLETE")
print("=" * 70)
print(f"\nTest Accuracy: {test_acc:.2f}%")
print(f"Model: models/best_lstm_model_v10.pth")
print(f"Scaler: data/processed/unified_modern_scaler.pkl")
print(f"\nKey difference: NO 1999 NSL-KDD data!")
print(f"Only modern datasets: CIC-IDS2018, TII-SSRC-23 (2023!), UNSW-NB15")
print(f"\nThis should dramatically reduce false positives on 2025 traffic!")
