# Network Intrusion Detection System (NIDS)

## Overview

This is an adaptive, autoencoder-based network intrusion detection system that learns what "normal" traffic looks like in your specific environment and detects anomalies in real-time.

**Key Features:**
- **Environment-specific learning**: Trained on YOUR network's normal traffic
- **Autoencoder-based anomaly detection**: Unsupervised learning approach
- **Real-time monitoring**: Processes Zeek logs as they're generated
- **Retrainable**: Adapts to changing network conditions
- **REST API**: Full API for integration and management
- **React Dashboard**: Web UI for monitoring and analysis

## Architecture

### 1. Data Capture Layer (Zeek)
- Zeek sensor captures network traffic and generates connection logs
- Provides flow-level metadata (duration, bytes, packets, etc.)
- No packet payload inspection (privacy-preserving)

### 2. ETL Pipeline
- Parses Zeek conn.log files
- Extracts and engineers features from flow records
- Stores flows in SQLite database

### 3. Machine Learning Engine
- **Autoencoder model** trained only on normal traffic
- Learns to reconstruct typical flow patterns
- Anomalies produce high reconstruction errors
- Threshold set from validation data (95th percentile)

### 4. Backend API (FastAPI)
- REST endpoints for anomalies, flows, models
- Background log watcher for real-time processing
- Model management and retraining

### 5. Frontend Dashboard (React + Material-UI)
- Real-time anomaly visualization
- Traffic statistics and trends
- Model management interface
- Retraining controls

## Installation

### Prerequisites
- Python 3.10+
- Poetry (for dependency management)
- Zeek (for traffic capture)
- Node.js & npm (for frontend)

### Backend Setup

```bash
cd backend

# Install dependencies
poetry install

# Create necessary directories
mkdir -p data/zeek_logs artifacts
```

### Frontend Setup

```bash
cd frontend

# Install dependencies
npm install
```

## Usage

### Phase 0: Install Zeek

```bash
# Ubuntu/Debian
sudo apt-get install zeek

# Check installation
zeek --version
```

### Phase 1: Collect Normal Traffic

Capture 24-72 hours of normal network traffic:

```bash
# Start Zeek capture (requires sudo for interface access)
sudo poetry run capture-traffic --interface eth0 --duration 24
```

This will create conn.log files in `data/zeek_logs/`.

### Phase 2: Create Dataset

Parse Zeek logs and create training dataset:

```bash
poetry run create-dataset --zeek-log-dir data/zeek_logs
```

This extracts features and stores flows in the database.

### Phase 3: Train Model

Train the autoencoder on normal traffic:

```bash
poetry run train-model --min-samples 1000
```

This:
1. Loads normal flows from database
2. Trains autoencoder to reconstruct flow features
3. Calculates anomaly threshold
4. Saves model artifacts to `artifacts/`

### Phase 4: Deploy Backend

Start the FastAPI backend with live monitoring:

```bash
poetry run backend-deploy
```

The backend will:
- Load the trained model
- Start monitoring Zeek logs for new flows
- Process flows through anomaly detector
- Store results in database
- Serve REST API at http://localhost:8000

### Phase 5: Launch Frontend

```bash
cd frontend
npm run dev
```

Access the dashboard at http://localhost:5173

### Phase 6: Retrain Model

When network conditions change or you encounter false positives:

```bash
poetry run retrain-model --lookback-hours 72
```

This trains a new model on recent traffic, incorporating learned patterns.

You can also trigger retraining via the API:

```bash
curl -X POST http://localhost:8000/api/retrain
```

## API Endpoints

### Admin & Models
- `GET /api/models` - List all trained models
- `GET /api/models/{id}` - Get model details
- `POST /api/models/{id}/activate` - Activate a model
- `POST /api/retrain` - Trigger retraining
- `GET /api/status` - System status

### Anomalies
- `GET /api/anomalies` - List detected anomalies
- `GET /api/anomalies/stats` - Anomaly statistics
- `PATCH /api/anomalies/{id}` - Update investigation status

### Flows
- `GET /api/flows` - List network flows
- `GET /api/flows/stats` - Flow statistics

### Metrics
- `GET /api/metrics/system` - System performance metrics
- `GET /api/metrics/timeline` - Time-series data for charts

### WebSocket
- `WS /api/ws` - Real-time anomaly notifications

## How It Works

### Training Phase

1. **Data Collection**: Zeek captures 24-72 hours of normal network traffic
2. **Feature Extraction**: ETL pipeline converts flows to numerical feature vectors:
   - Duration, bytes, packets
   - Throughput metrics (bytes/sec, packets/sec)
   - Ratios and derived statistics
   - Protocol and service encodings
3. **Normalization**: StandardScaler normalizes features (zero mean, unit variance)
4. **Autoencoder Training**:
   - Input: normalized feature vector
   - Encoder: compresses to latent space [128→64→32→16]
   - Decoder: reconstructs original input [16→32→64→128→input_size]
   - Loss: Mean Squared Error (MSE) between input and reconstruction
   - Optimizer: Adam with early stopping
5. **Threshold Calculation**: 95th percentile of validation reconstruction errors

### Inference Phase

1. **Live Monitoring**: Log watcher tails conn.log
2. **Feature Extraction**: New flows converted to feature vectors
3. **Normalization**: Applied using saved scaler
4. **Reconstruction**: Flow passed through autoencoder
5. **Error Calculation**: MSE between input and output
6. **Anomaly Decision**: Error > threshold → Anomaly
7. **Severity Classification**:
   - LOW: 1.0-1.5x threshold
   - MEDIUM: 1.5-2.0x threshold
   - HIGH: 2.0-3.0x threshold
   - CRITICAL: >3.0x threshold

### Adaptive Learning

When you encounter false positives (benign but unusual traffic):

1. Mark the anomaly as false positive in the dashboard
2. Run `retrain-model` to incorporate recent verified-normal traffic
3. New model learns to recognize these patterns as normal
4. False positive rate decreases over time

This enables the system to adapt to:
- New services deployed on the network
- Changes in usage patterns
- IoT devices
- Legitimate but unusual traffic

## Configuration

Edit `backend/app/core/config.py` or use environment variables:

```python
# Database
DATABASE_URL = "sqlite+aiosqlite:///./nids.db"

# Paths
DATA_DIR = "./data"
ZEEK_LOG_DIR = "./data/zeek_logs"
ARTIFACTS_DIR = "./artifacts"

# Training
ANOMALY_THRESHOLD_PERCENTILE = 95.0  # Threshold sensitivity
BATCH_SIZE = 64
MAX_EPOCHS = 100
LEARNING_RATE = 0.001

# Monitoring
NETWORK_INTERFACE = "eth0"
LOG_WATCH_INTERVAL = 1.0  # seconds
```

## Understanding Results

### What is Normal?
Traffic patterns typical for YOUR network during the training period.

### What is an Anomaly?
Any flow that doesn't fit the learned normal pattern:
- Port scans
- Unusual protocols
- Abnormal connection durations
- Suspicious byte/packet ratios
- Traffic to/from unusual IPs
- New services (until retrained)

### False Positives
New but legitimate traffic will initially be flagged as anomalous. This is expected behavior. Use the retraining mechanism to incorporate these patterns.

### Interpreting Scores
- **Reconstruction Error**: Raw MSE between input and reconstruction
- **Anomaly Score**: Normalized score (0-1) for easier comparison
- **Severity**: Classification based on how far error exceeds threshold

## Troubleshooting

### "No active model found"
You need to train a model first:
```bash
poetry run train-model
```

### "Insufficient training data"
Collect more normal traffic. Minimum 1000 flows recommended, 10000+ ideal:
```bash
sudo poetry run capture-traffic --duration 24
poetry run create-dataset
```

### "Permission denied to capture"
Zeek requires privileges to capture on network interfaces:
```bash
sudo poetry run capture-traffic
```

### High False Positive Rate
- Increase threshold percentile in config (e.g., 99th percentile)
- Retrain model on more diverse normal traffic
- Mark false positives and retrain

### Model Not Detecting Attacks
- Decrease threshold percentile (more sensitive)
- Ensure training data is truly "normal" (no attacks present)
- Check if attacks produce unusual flow statistics

## Project Structure

```
backend/
├── app/
│   ├── api/              # REST API endpoints
│   ├── core/             # Configuration and database
│   ├── ml/               # ML models and components
│   │   ├── models.py               # Autoencoder architecture
│   │   ├── zeek_parser.py          # Log parser
│   │   ├── flow_feature_extractor.py  # Feature engineering
│   │   ├── autoencoder_trainer.py  # Training logic
│   │   └── anomaly_detector.py     # Inference engine
│   ├── models/           # Database models
│   ├── scripts/          # CLI scripts
│   │   ├── capture_traffic.py   # Zeek interface
│   │   ├── create_dataset.py    # ETL pipeline
│   │   ├── train_model.py       # Training script
│   │   └── retrain_model.py     # Retraining script
│   ├── services/         # Background services
│   │   └── log_watcher.py       # Real-time monitoring
│   └── main.py           # FastAPI application
├── pyproject.toml        # Poetry configuration
└── artifacts/            # Saved models and scalers

frontend/
├── src/
│   ├── pages/            # Dashboard pages
│   ├── components/       # React components
│   ├── services/         # API client
│   └── types/            # TypeScript types
└── package.json

data/
└── zeek_logs/            # Zeek connection logs

nids.db                   # SQLite database
```

## Database Schema

### flows
- Network flow records from Zeek
- Features stored as JSON
- `is_normal` flag for training data labeling

### anomalies
- Detected anomalies with reconstruction errors
- Links to flow records
- Investigation tracking (false positive marking)

### models
- Model metadata and training history
- Threshold and performance metrics
- `is_active` flag for deployment

## Contributing

This project implements the architecture described in PROJECT_COOKBOOK.md. For development guidelines and algorithmic details, refer to that document.

## License

[Your License Here]
