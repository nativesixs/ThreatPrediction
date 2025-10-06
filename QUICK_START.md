# Quick Start Guide

This guide will get your Network Intrusion Detection System up and running in under 30 minutes (assuming you have normal traffic to capture).

## Prerequisites Check

```bash
# Check Python version (need 3.10+)
python3 --version

# Check Poetry
poetry --version

# Check Zeek
zeek --version

# Check Node.js (for frontend)
node --version
npm --version
```

If any are missing, install them first:

```bash
# Poetry
curl -sSL https://install.python-poetry.org | python3 -

# Zeek (Ubuntu/Debian)
sudo apt-get install zeek

# Node.js (Ubuntu/Debian)
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs
```

## Step 1: Install Backend Dependencies (2 minutes)

```bash
cd backend
poetry install
```

This installs all Python dependencies including PyTorch, FastAPI, scikit-learn, etc.

## Step 2: Set Up Directories (1 minute)

```bash
# Create necessary directories
mkdir -p data/zeek_logs artifacts
```

## Step 3: Capture Normal Traffic (1-24 hours)

**Option A: Quick Test (1 hour)**

For testing purposes, capture 1 hour of traffic:

```bash
sudo poetry run capture-traffic --interface eth0 --duration 1
```

Note: You need at least 1000 flows (connections) for training. 1 hour might not be enough for a quiet network.

**Option B: Production Setup (24-72 hours)**

For real deployment, capture 24-72 hours:

```bash
# Start capture and let it run
sudo poetry run capture-traffic --interface eth0 --duration 24
```

**Option C: Use Existing Zeek Logs**

If you already have Zeek logs, copy them to `data/zeek_logs/`:

```bash
cp /path/to/existing/conn.log data/zeek_logs/
```

**Important**: Make sure the traffic is NORMAL (no attacks). The model learns from this baseline.

## Step 4: Create Training Dataset (2-5 minutes)

Parse Zeek logs and create the training dataset:

```bash
poetry run create-dataset --zeek-log-dir data/zeek_logs
```

You should see output like:

```
Parsed 15000 flow records from data/zeek_logs/conn.log
Inserted 15000/15000 flows
Dataset statistics:
  Normal flows in database: 15000
```

## Step 5: Train the Model (5-10 minutes)

Train the autoencoder on the normal traffic:

```bash
poetry run train-model --min-samples 1000
```

You'll see training progress:

```
Training samples: 12000, Validation samples: 3000
StandardScaler fitted on training data
Starting training...
Epoch 1/100 | Train Loss: 0.524123 | Val Loss: 0.478932 | Time: 2.34s
Epoch 2/100 | Train Loss: 0.412876 | Val Loss: 0.398654 | Time: 2.12s
...
Early stopping triggered after 23 epochs
Training completed in 54.32 seconds
Anomaly threshold (95th percentile): 0.123456
Model saved with ID: 1
```

## Step 6: Start the Backend (1 minute)

Launch the FastAPI backend:

```bash
poetry run backend-deploy
```

You should see:

```
================================================================================
Starting Network Intrusion Detection System v0.1.0
================================================================================
Data directory: ./data
Zeek log directory: ./data/zeek_logs
Artifacts directory: ./artifacts
✓ Database initialized
Loading model: v20241006_143022
✓ Anomaly detector loaded
  Model ID: 1
  Threshold: 0.123456
✓ Log watcher started
  Monitoring: ./data/zeek_logs
================================================================================
Application startup complete
API available at: http://0.0.0.0:8000/api
================================================================================
INFO:     Uvicorn running on http://0.0.0.0:8000
```

## Step 7: Test the API (2 minutes)

Open a new terminal and test the endpoints:

```bash
# Check system status
curl http://localhost:8000/api/status

# Get flows
curl http://localhost:8000/api/flows?limit=10

# Get anomalies
curl http://localhost:8000/api/anomalies?limit=10

# Get statistics
curl http://localhost:8000/api/flows/stats
curl http://localhost:8000/api/anomalies/stats
```

## Step 8: Start the Frontend (2 minutes)

In a new terminal:

```bash
cd frontend
npm install  # First time only
npm run dev
```

Open your browser to: **http://localhost:5173**

## Step 9: Monitor in Real-Time

The system is now:

1. ✅ **Monitoring** `data/zeek_logs/` for new conn.log entries
2. ✅ **Processing** new flows through the anomaly detector
3. ✅ **Storing** results in the database
4. ✅ **Serving** results via REST API
5. ✅ **Displaying** on the dashboard

### Generate Some Test Traffic

To see the system in action:

```bash
# Browse some websites
curl https://www.google.com
curl https://www.github.com

# Start a service
python3 -m http.server 8888

# Scan ports (will trigger anomalies!)
# nmap localhost  # Be careful with this on production networks
```

Watch the dashboard and API to see flows and anomalies appear!

## Step 10: Retrain (Optional)

After some time, if you see false positives (legitimate traffic flagged as anomalous):

1. Mark them as false positives in the dashboard (or via API)
2. Trigger retraining:

```bash
poetry run retrain-model --lookback-hours 24
```

Or via API:

```bash
curl -X POST http://localhost:8000/api/retrain
```

This will:
- Collect recent normal traffic (including verified false positives)
- Train a new model
- Replace the old model
- Reduce future false positives

## Troubleshooting

### "No active model found"

You skipped step 5. Train a model:

```bash
poetry run train-model
```

### "Insufficient training data: 234 flows (minimum: 1000)"

You don't have enough traffic. Either:

1. Capture more traffic (longer duration)
2. Use a busier network interface
3. Lower the minimum (for testing): `--min-samples 100`

### "Permission denied" when capturing

Zeek needs root privileges to capture on interfaces:

```bash
sudo poetry run capture-traffic
```

### Backend won't start

Check if port 8000 is already in use:

```bash
lsof -i :8000
# Kill the process using the port if needed
```

### Frontend won't start

Check if port 5173 is already in use, or if there are dependency issues:

```bash
cd frontend
rm -rf node_modules package-lock.json
npm install
npm run dev
```

### No new flows appearing

1. Check if Zeek is actually running: `ps aux | grep zeek`
2. Check if conn.log is being created: `ls -lh data/zeek_logs/`
3. Check log watcher status: Look at backend logs
4. Verify network interface has traffic: `sudo tcpdump -i eth0 -c 10`

### High false positive rate

The model is too sensitive. Options:

1. **Increase threshold**: Edit config.py, set `ANOMALY_THRESHOLD_PERCENTILE = 99.0`
2. **Retrain with more data**: Capture more diverse normal traffic
3. **Mark and retrain**: Mark false positives, then retrain

### Not detecting attacks

The model is not sensitive enough. Options:

1. **Decrease threshold**: Set `ANOMALY_THRESHOLD_PERCENTILE = 90.0`
2. **Verify training data**: Make sure no attacks in training set
3. **Check if attack is detectable**: Some attacks don't produce unusual flow statistics

## What's Next?

### Production Deployment

1. **Dedicated Zeek Server**: Run Zeek on a dedicated machine with a SPAN/mirror port
2. **Database**: Consider PostgreSQL instead of SQLite for better concurrency
3. **Monitoring**: Set up alerts, email notifications for high-severity anomalies
4. **Backup**: Regularly backup models and database
5. **Logging**: Configure proper log rotation and retention

### Fine-Tuning

1. **Feature Engineering**: Add more features based on your network
2. **Architecture**: Experiment with different autoencoder sizes
3. **Threshold**: Adjust based on your false positive tolerance
4. **Retraining Schedule**: Set up automatic periodic retraining

### Integration

1. **SIEM Integration**: Forward anomalies to your SIEM
2. **Ticketing**: Create tickets for high-severity anomalies
3. **Automation**: Automatically block IPs with CRITICAL anomalies
4. **Reporting**: Generate daily/weekly reports

### Evaluation

1. **Attack Testing**: Use controlled attack traffic to measure detection rate
2. **Metrics**: Track precision, recall, F1 score over time
3. **Baselines**: Compare with other IDS systems
4. **Documentation**: Record results for thesis

## Common Commands Reference

```bash
# Backend
poetry run capture-traffic --interface eth0 --duration 24
poetry run create-dataset
poetry run train-model
poetry run retrain-model
poetry run backend-deploy

# API
curl http://localhost:8000/api/status
curl http://localhost:8000/api/anomalies
curl http://localhost:8000/api/flows
curl -X POST http://localhost:8000/api/retrain

# Frontend
cd frontend && npm run dev

# Database
sqlite3 nids.db "SELECT COUNT(*) FROM flows;"
sqlite3 nids.db "SELECT COUNT(*) FROM anomalies;"
sqlite3 nids.db "SELECT * FROM models;"

# Logs
tail -f data/zeek_logs/conn.log
```

## Success Checklist

- [ ] Dependencies installed
- [ ] Normal traffic captured (1000+ flows)
- [ ] Dataset created
- [ ] Model trained (threshold calculated)
- [ ] Backend running (API accessible)
- [ ] Frontend running (dashboard accessible)
- [ ] Real-time monitoring active (new flows processed)
- [ ] Can see flows in API/dashboard
- [ ] Can see anomalies (if any)
- [ ] Retrain command works

If all items are checked, congratulations! Your NIDS is operational. 🎉

For detailed information, see:
- `README_NEW.md` - Full documentation
- `PROJECT_COOKBOOK.md` - Architecture and algorithms
- `RESTRUCTURING_SUMMARY.md` - Implementation details
