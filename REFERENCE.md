# Quick Reference Card

## Poetry Commands

```bash
# Data Collection
poetry run capture-traffic --interface eth0 --duration 24

# Dataset Creation
poetry run create-dataset --zeek-log-dir data/zeek_logs

# Model Training
poetry run train-model --min-samples 1000

# Model Retraining
poetry run retrain-model --lookback-hours 72

# Backend Deployment
poetry run backend-deploy
```

## API Endpoints

```bash
# System Status
GET /api/status

# Models
GET /api/models
GET /api/models/{id}
POST /api/models/{id}/activate
POST /api/retrain

# Anomalies
GET /api/anomalies?limit=100&severity=HIGH
GET /api/anomalies/stats?hours=24
PATCH /api/anomalies/{id}

# Flows
GET /api/flows?limit=100&protocol=tcp
GET /api/flows/stats?hours=24

# Metrics
GET /api/metrics/system
GET /api/metrics/timeline?hours=24&interval_minutes=60

# WebSocket
WS /api/ws
```

## cURL Examples

```bash
# Get system status
curl http://localhost:8000/api/status

# Get recent anomalies
curl http://localhost:8000/api/anomalies?limit=10

# Get flows
curl http://localhost:8000/api/flows?limit=10

# Get statistics
curl http://localhost:8000/api/anomalies/stats?hours=24
curl http://localhost:8000/api/flows/stats?hours=24

# Mark anomaly as investigated
curl -X PATCH http://localhost:8000/api/anomalies/1 \
  -H "Content-Type: application/json" \
  -d '{"investigated": true, "false_positive": false}'

# Trigger retraining
curl -X POST http://localhost:8000/api/retrain

# Activate a different model
curl -X POST http://localhost:8000/api/models/2/activate
```

## Database Queries

```bash
# Open database
sqlite3 nids.db

# Count flows
SELECT COUNT(*) FROM flows;

# Count anomalies
SELECT COUNT(*) FROM anomalies WHERE is_anomaly = 1;

# Recent anomalies
SELECT timestamp, severity, anomaly_score 
FROM anomalies 
WHERE is_anomaly = 1 
ORDER BY timestamp DESC 
LIMIT 10;

# Model information
SELECT id, version, threshold, is_active 
FROM models 
ORDER BY created_at DESC;

# Flows by protocol
SELECT protocol, COUNT(*) 
FROM flows 
GROUP BY protocol;

# False positives
SELECT COUNT(*) 
FROM anomalies 
WHERE false_positive = 1;
```

## File Locations

```
backend/
├── app/
│   ├── main.py              # FastAPI application
│   ├── core/config.py       # Configuration
│   ├── ml/
│   │   ├── models.py        # Autoencoder
│   │   ├── zeek_parser.py   # Log parser
│   │   └── anomaly_detector.py  # Inference
│   └── scripts/
│       ├── capture_traffic.py
│       ├── create_dataset.py
│       ├── train_model.py
│       └── retrain_model.py
├── data/
│   └── zeek_logs/           # Zeek connection logs
├── artifacts/
│   ├── autoencoder.pth      # Trained model
│   ├── scaler.pkl           # StandardScaler
│   └── threshold.json       # Metadata
└── nids.db                  # SQLite database
```

## Configuration Variables

Edit `backend/app/core/config.py`:

```python
# Paths
DATA_DIR = Path("./data")
ZEEK_LOG_DIR = Path("./data/zeek_logs")
ARTIFACTS_DIR = Path("./artifacts")

# Training
ANOMALY_THRESHOLD_PERCENTILE = 95.0  # Sensitivity
VALIDATION_SPLIT = 0.2
BATCH_SIZE = 64
LEARNING_RATE = 0.001
MAX_EPOCHS = 100
EARLY_STOPPING_PATIENCE = 10

# Monitoring
NETWORK_INTERFACE = "eth0"
LOG_WATCH_INTERVAL = 1.0  # seconds
```

## Common Tasks

### Check if Zeek is capturing

```bash
# Check process
ps aux | grep zeek

# Check log file
ls -lh data/zeek_logs/conn.log
tail -f data/zeek_logs/conn.log
```

### Monitor backend logs

```bash
# If running in terminal, logs print to stdout
# Or redirect to file:
poetry run backend-deploy > backend.log 2>&1
tail -f backend.log
```

### Count database records

```bash
sqlite3 nids.db "SELECT 
  (SELECT COUNT(*) FROM flows) as flows,
  (SELECT COUNT(*) FROM anomalies) as anomalies,
  (SELECT COUNT(*) FROM models) as models;"
```

### Clear database

```bash
rm nids.db
# Backend will recreate on next start
```

### Reset and retrain

```bash
# Stop backend (Ctrl+C)
rm -rf artifacts/*  # Remove old model
rm nids.db          # Clear database
poetry run create-dataset
poetry run train-model
poetry run backend-deploy
```

## Feature Engineering

The system extracts 24 features from each flow:

1-7. **Basic metrics**: duration, orig_bytes, resp_bytes, total_bytes, orig_pkts, resp_pkts, total_pkts
8-12. **Derived metrics**: bytes/sec, pkts/sec, orig_bytes/pkt, resp_bytes/pkt, avg_bytes/pkt
13-14. **Ratios**: orig_resp_byte_ratio, orig_resp_pkt_ratio
15-20. **Protocol one-hot**: tcp, udp, icmp, arp, ipv6, other
21. **Service code**: numeric encoding
22. **Connection state code**: numeric encoding

## Severity Levels

```python
ERROR ≤ 1.0x threshold    → NORMAL
1.0x < ERROR ≤ 1.5x       → LOW
1.5x < ERROR ≤ 2.0x       → MEDIUM
2.0x < ERROR ≤ 3.0x       → HIGH
ERROR > 3.0x threshold    → CRITICAL
```

## Troubleshooting Commands

```bash
# Check Python environment
poetry env info

# Verify dependencies
poetry show

# Check ports
lsof -i :8000
lsof -i :5173

# Test network interface
ip addr show
sudo tcpdump -i eth0 -c 10

# Check Zeek
which zeek
zeek --version

# Permissions for capture
sudo usermod -a -G pcap $USER
```

## Performance Tuning

### Speed up training

```python
# config.py
MAX_EPOCHS = 50  # Reduce max epochs
BATCH_SIZE = 128  # Larger batches
```

### Reduce false positives

```python
# config.py
ANOMALY_THRESHOLD_PERCENTILE = 99.0  # Less sensitive
```

### Increase sensitivity

```python
# config.py
ANOMALY_THRESHOLD_PERCENTILE = 90.0  # More sensitive
```

## Zeek Log Format

Example conn.log entry:
```
ts=1696608000.123456
uid=CXY9a14VfzJvGqOo1f
id.orig_h=192.168.1.100
id.orig_p=52341
id.resp_h=93.184.216.34
id.resp_p=443
proto=tcp
service=ssl
duration=5.234
orig_bytes=1234
resp_bytes=5678
conn_state=SF
orig_pkts=10
resp_pkts=12
```

## Model Architecture

```
Input (24 features)
    ↓
Encoder:
    Linear(24 → 128) → ReLU
    Linear(128 → 64) → ReLU
    Linear(64 → 32) → ReLU
    Linear(32 → 16) → ReLU
    ↓
Latent Space (16)
    ↓
Decoder:
    Linear(16 → 32) → ReLU
    Linear(32 → 64) → ReLU
    Linear(64 → 128) → ReLU
    Linear(128 → 24)
    ↓
Reconstructed Output (24 features)

Loss = MSE(Input, Output)
```

## Key Concepts

**Autoencoder**: Neural network that learns to compress and reconstruct normal data

**Reconstruction Error**: How well the model can rebuild a flow (MSE)

**Threshold**: The cutoff point - errors above this are anomalies

**Normal Traffic**: Traffic used for training - defines the baseline

**Anomaly**: Any flow with reconstruction error > threshold

**Retraining**: Training new model on recent data to adapt to changes

**False Positive**: Benign traffic flagged as anomaly

**True Positive**: Actual attack correctly identified as anomaly

## Support

- Documentation: README_NEW.md
- Quick Start: QUICK_START.md
- Architecture: PROJECT_COOKBOOK.md
- Changes: RESTRUCTURING_SUMMARY.md
- This guide: IMPLEMENTATION_COMPLETE.md
