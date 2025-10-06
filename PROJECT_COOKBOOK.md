PROJECT OVERVIEW
The system is a web-based intrusion and anomaly detection framework that learns what “normal” network traffic looks like for a specific environment, then identifies deviations in real time.
It is built from five cooperating layers:

Data capture (Zeek sensor)

ETL and feature engineering pipeline

Machine-learning engine (PyTorch autoencoder)

FastAPI backend with SQLite persistence

React + MUI dashboard for monitoring and retraining control

The distinguishing idea is not a fixed global model but a retrainable pipeline.
When moved to a new network, it collects 24–72 hours of normal traffic and regenerates a model tuned to that environment.

TECH STACK

Sensor layer
• Zeek (primary) – generates flow-level logs such as connection duration, packet counts, and byte counts.
• Scapy (optional) – used only for generating or replaying small synthetic traffic segments for safe testing on owned systems.

Backend
• FastAPI (served by Uvicorn) – REST API and orchestration.
• SQLAlchemy ORM with SQLite database – storage for flows, anomalies, and model metadata.
• Poetry – environment and dependency management.
• Watchdog – monitors Zeek log directory for new data.
• Joblib – saves and loads scaler objects.

Machine learning
• PyTorch – for the anomaly-detection autoencoder.
• Scikit-learn – for preprocessing, scaling, and evaluation metrics.
• Pandas and NumPy – for feature engineering and manipulation.

Frontend
• React 18 built with Vite.
• Material-UI for layout and design.
• Axios for HTTP requests to the backend.
• Recharts or Chart.js for time-series plots.

POETRY CONFIGURATION AND AUTOMATION SCRIPTS

Dependency management and task automation are handled entirely with Poetry.
The pyproject.toml file not only declares dependencies but also defines convenient run-scripts so the system can be operated without remembering long command lines.

Main tasks to automate:
• Capturing traffic from Zeek or importing existing Zeek logs.
• Running the ETL pipeline to create or update the training dataset.
• Training or retraining the PyTorch model.
• Starting the FastAPI backend for real-time detection.
• Optionally launching a background watcher that tails Zeek logs.

Add these sections to pyproject.toml under [tool.poetry.scripts] and [tool.poetry.dependencies].
All Python files mentioned correspond to your backend scripts described in the development cookbook.

Example structure (expressed in descriptive form, not literal code):

• Under [tool.poetry.dependencies], list packages such as
fastapi, uvicorn, sqlalchemy, aiosqlite, pandas, numpy, scikit-learn, torch, joblib, watchdog, pydantic, loguru, and any others used in your backend.

• Add a [tool.poetry.scripts] section mapping simple commands to your module entry points.
These entries will look like:
capture-traffic = “app.scripts.capture_traffic:main”
create-dataset = “app.scripts.create_dataset:main”
train-model = “app.scripts.train_model:main”
retrain-model = “app.scripts.retrain_model:main”
backend-deploy = “app.main:run”

Once defined, you will be able to run each task with:
poetry run capture-traffic
poetry run create-dataset
poetry run train-model
poetry run retrain-model
poetry run backend-deploy

Purpose of each command

capture-traffic:
Starts or interfaces with Zeek to capture raw connection logs for a specified duration and stores them under the data/zeek_logs directory.

create-dataset:
Runs the ETL pipeline. It parses Zeek’s logs, performs feature engineering and normalization, and writes the resulting flow dataset into SQLite.

train-model:
Trains the autoencoder using the most recent normal data from SQLite. Saves the trained model, scaler, and threshold into the artifacts directory and records metadata in the database.

retrain-model:
Triggers the retraining process using recent “normal” flows collected during live operation. Updates artifacts and metadata so the inference service uses the new model automatically.

backend-deploy:
Launches the FastAPI application (for example using uvicorn app.main:app). This starts the REST API, background watcher, and the inference engine that processes live flows.

You can add more convenience tasks as needed, such as evaluate-model, export-dataset, or cleanup-database, following the same pattern.

Benefits

• Eliminates long shell commands — single, consistent Poetry entry point.
• Simplifies CI/CD automation and documentation.
• Keeps all operational scripts version-controlled and self-documented within the pyproject.toml.

ALGORITHMIC FOUNDATION

The model uses a semi-supervised autoencoder trained only on normal traffic.
Its goal is to reconstruct the input features representing a network flow.
Because the model has seen only normal patterns, abnormal traffic produces higher reconstruction errors.
These reconstruction errors become the anomaly scores.

MODEL ARCHITECTURE DESCRIPTION
• Input layer receives a vector of numerical features describing a single flow.
Typical features include: duration, bytes sent by origin and responder, number of packets, packet-to-byte ratios, and engineered statistics such as bytes-per-second or packets-per-second.
Protocols and services (TCP, UDP, HTTP, HTTPS, etc.) are encoded as one-hot or integer values.

• Encoder section: progressively smaller fully-connected layers (for example, 128 → 64 → 16 neurons).
Each layer applies a non-linear activation such as ReLU.
The encoder compresses the input data into a low-dimensional latent representation capturing correlations among features that describe “normal” behavior.

• Bottleneck (latent vector): this compact code represents the learned manifold of normal network activity.
The model learns to project normal flows onto this manifold; abnormal flows will not fit well and thus reconstruct poorly.

• Decoder section: mirrors the encoder structure in reverse (16 → 64 → 128 → output).
It attempts to reconstruct the original input from the latent vector.

• Training objective: mean squared error between input and reconstruction.
The optimizer (Adam or RMSProp) minimizes this loss on batches of normal traffic until convergence or early stopping.

• After training, a validation subset of normal flows is passed through the model to compute reconstruction errors.
A threshold is chosen, usually the 95th or 99th percentile of those errors.
Any new flow producing an error above this threshold is considered anomalous.
This threshold becomes part of the model metadata stored in SQLite.

WHY AUTOENCODER IS USED

It does not require labeled attack data, which is scarce and environment-specific.

It adapts to local patterns, learning statistical dependencies among ordinary traffic features.

It generalizes poorly on purpose: this sensitivity helps flag novel attacks.

It can be trained incrementally on new normal data to handle concept drift.

Alternative models such as one-class SVM or isolation forest can be added later for ensemble scoring, but the thesis centers on the deep autoencoder because it learns a continuous, interpretable latent space.

PIPELINE FOR SYSTEM USAGE (OPERATIONAL WORKFLOW)

Deploy Zeek on a machine that has visibility into the network traffic.

Allow it to capture flows for 24–72 hours of ordinary use.

Run the ETL script to parse Zeek’s logs into a structured dataset, normalize features, and insert them into SQLite.

Train the autoencoder using only the collected normal flows.

Save the trained model, scaler, and threshold into an artifacts directory.

Start the live inference service that tails new Zeek logs. Each new flow is converted into the same feature vector, normalized, passed through the model, and scored.

The backend writes each score and anomaly decision into the database.

The React dashboard polls the backend to show alerts, anomaly scores over time, and statistics.

When the network conditions change or deployment moves to another network, the retrain command triggers a new model build using recent normal data.

PIPELINE FOR DEVELOPMENT (DETAILED COOKBOOK)

PHASE 0 – Repository setup
• Create project directories for backend, frontend, sensor configuration, and documentation.
• Initialize Poetry in backend and install all required dependencies.
• Initialize Vite project in frontend and verify that both backend and frontend start successfully.

“After verifying that backend and frontend run independently, configure Poetry scripts as described in the ‘Poetry Configuration and Automation Scripts’ section so that the commands poetry run capture-traffic, poetry run create-dataset, poetry run train-model, and poetry run backend-deploy perform the main project tasks.”

PHASE 1 – Sensor integration and data schema
• Install and test Zeek on a mirrored interface to confirm that connection logs are generated.
• Define the canonical flow record structure that the backend will consume.
• Write a Python parser that converts Zeek log entries into standardized dictionaries.
• Test the parser on a sample file and ensure all expected numeric and categorical fields are extracted.

PHASE 2 – Database schema and ETL pipeline
• Create SQLite tables for flows, anomalies, and models.
• Implement feature engineering logic: compute ratios, throughput metrics, and derived statistics.
• Add normalization using scikit-learn’s StandardScaler.
• Store processed flows in the database and verify integrity of numeric data.

PHASE 3 – Model training component
• Implement the autoencoder network class with encoder and decoder layers.
• Develop a training routine that:
– Loads normal data from SQLite.
– Splits data into training and validation subsets.
– Fits the StandardScaler on training data.
– Trains the network using mean squared error loss until validation loss plateaus.
– Calculates reconstruction errors for the validation set and selects the threshold percentile.
– Saves model weights, scaler, and threshold metadata.
• Record model metadata (creation time, threshold, training size) into the models table.

PHASE 4 – Inference and live scoring service
• Create an inference engine that loads the latest saved model and scaler once at startup.
• Build a watcher service that monitors the Zeek log directory.
• Each time a new log entry appears, parse it, engineer features, normalize them, and send them to the inference engine for scoring.
• Compare each score to the stored threshold. Insert both the raw flow and the decision into the database.

PHASE 5 – FastAPI backend routes
• Implement REST endpoints:
– GET /api/status returns model metadata.
– GET /api/anomalies returns recent anomalies.
– GET /api/stats returns aggregates.
– POST /api/retrain launches the retraining routine as a background task.
– POST /api/predict (optional) scores a single JSON flow for testing.
• Ensure background tasks perform training asynchronously so the API remains responsive.
• Validate all inputs with Pydantic models.

PHASE 6 – React dashboard
• Build user interface with cards for system status, a table for recent anomalies, and graphs of anomaly score over time.
• Implement polling to update the table and chart periodically.
• Include a “Retrain Model” button that triggers the retrain endpoint and reports progress.
• Use color cues for severity levels based on anomaly scores.

PHASE 7 – Retraining and model management
• Add backend logic to collect the most recent 48 or 72 hours of flows that were classified as normal.
• Execute the same training pipeline on this subset to create an updated model.
• Replace the current artifacts atomically and refresh the inference engine without restarting the server.
• Log each retraining event in the models table for traceability.
“Adaptive behavior and false-positive handling are discussed in Phase 7.5, which describes how the retraining mechanism is used to integrate new legitimate traffic patterns into the baseline.”

PHASE 7.5 – ADAPTIVE LEARNING AND FALSE POSITIVE MITIGATION

An anomaly-based intrusion detection model learns a statistical profile of “normal” network behavior during its training period.
When the system encounters legitimate but previously unseen activity—such as introducing a new service, hosting a local Minecraft server, or adding new IoT devices—the model will initially interpret these flows as anomalous because their features differ from the learned baseline.

This is expected and forms the core behavior of anomaly detection: any deviation from the baseline is considered noteworthy until verified.

Operational response

When such benign anomalies appear:

They are logged and displayed on the dashboard with their anomaly scores.

The user or administrator reviews them and determines whether they represent legitimate new activity.

If confirmed as benign, these flows become candidates for inclusion in the next retraining cycle.

Running the retrain command (for example, poetry run retrain-model) incorporates these new patterns into the baseline, thereby reducing future false positives for the same activity.

Adaptive behavior

This feedback–retrain loop enables the system to evolve with the network.
Each retraining round expands the definition of normal traffic to reflect recent legitimate usage while still remaining sensitive to truly abnormal events.
Over time, the false-positive rate declines and detection accuracy stabilizes.

Threshold management

To prevent excessive alarms while the baseline adapts, the model uses configurable threshold bands rather than a single cutoff:

Low score: clearly normal

Medium score: uncertain, flagged for observation

High score: strong anomaly, immediate alert

These ranges allow operators to manage alert severity and decide which events warrant immediate action versus those to revisit after retraining.

Concept drift handling (optional enhancement)

Long-term networks change naturally—a phenomenon known as concept drift.
By monitoring the average reconstruction error over time, the system can detect shifts in overall behavior and trigger automatic retraining when needed.
This ensures continuous alignment of the model with real traffic patterns.

Summary

False positives caused by new but harmless traffic are not model failures but indicators of change.
The designed workflow—review, confirm, retrain—transforms this limitation into a self-learning feature, making the IDS adaptive to evolving environments without requiring predefined attack signatures.

PHASE 8 – Evaluation
• Conduct controlled evaluation periods.
• Mark time windows where known benign or test attack traffic was present.
• Use these labels to compute detection rate, false positive rate, and precision before and after retraining.
• Record results and plots for thesis documentation.


PHASE 9 – Monitoring and resilience
• Add structured logging to backend events and watcher.
• Track ingestion rate and inference latency.
• Implement error handling for malformed flows and log rotation events.

PHASE 10 – Security and privacy considerations
• Never store raw packet payloads, only metadata.
• Offer an option to hash or anonymize IP addresses for demo purposes.
• Restrict CORS and apply simple rate limiting on public endpoints.

SUMMARY OF MACHINE-LEARNING BEHAVIOR

Input data: tabular flow features.
Training data: only normal traffic from the target environment.
Learning objective: reconstruct each feature vector as accurately as possible; minimize mean squared reconstruction error.
Inference: compute reconstruction error for new flow; if above threshold, classify as anomaly.
Output: numerical anomaly score and binary decision.
Model adaptability: retraining periodically recalibrates what “normal” means for that specific network, allowing the system to follow evolving usage patterns.

EXPECTED OUTCOME

After following the cookbook, you will have:
• A running Zeek sensor feeding live flows.
• A backend that processes, scores, and stores anomalies in real time.
• A retrainable PyTorch model that adapts to each network.
• A responsive web dashboard for visualization and management.
• Documentation and evaluation results suitable for thesis submission.
