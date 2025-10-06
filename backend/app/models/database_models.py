from sqlalchemy import Column, Integer, String, Float, DateTime, JSON, Boolean, Text
from sqlalchemy.sql import func
from app.core.database import Base


class Flow(Base):
    """Network flow record from Zeek logs."""
    __tablename__ = "flows"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), index=True)
    uid = Column(String(100), unique=True, index=True)  # Zeek connection UID
    
    # Connection metadata
    orig_ip = Column(String(45), index=True)
    orig_port = Column(Integer)
    resp_ip = Column(String(45), index=True)
    resp_port = Column(Integer)
    protocol = Column(String(10))
    service = Column(String(50), nullable=True)
    
    # Flow statistics
    duration = Column(Float)
    orig_bytes = Column(Integer)
    resp_bytes = Column(Integer)
    orig_pkts = Column(Integer)
    resp_pkts = Column(Integer)
    orig_ip_bytes = Column(Integer, nullable=True)
    resp_ip_bytes = Column(Integer, nullable=True)
    
    # Connection state
    conn_state = Column(String(10))
    
    # Engineered features (JSON for flexibility)
    features = Column(JSON)
    
    # Classification
    is_normal = Column(Boolean, default=True, index=True)  # Used for training data labeling
    
    # Zeek metadata
    zeek_metadata = Column(JSON, nullable=True)


class Anomaly(Base):
    """Detected anomaly with reconstruction error."""
    __tablename__ = "anomalies"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    flow_id = Column(Integer, index=True)
    
    # Anomaly detection results
    reconstruction_error = Column(Float)
    threshold = Column(Float)
    anomaly_score = Column(Float)  # Normalized score (0-1)
    is_anomaly = Column(Boolean, index=True)
    
    # Model information
    model_id = Column(Integer, index=True)
    
    # Severity classification
    severity = Column(String(20), nullable=True)  # LOW, MEDIUM, HIGH, CRITICAL
    
    # Investigation status
    investigated = Column(Boolean, default=False, index=True)
    false_positive = Column(Boolean, default=False)
    notes = Column(Text, nullable=True)


class Model(Base):
    """Model metadata and training information."""
    __tablename__ = "models"
    
    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Model identification
    model_type = Column(String(50))  # e.g., "autoencoder"
    version = Column(String(50))
    
    # Training information
    training_size = Column(Integer)
    validation_size = Column(Integer)
    num_features = Column(Integer)
    
    # Architecture
    architecture = Column(JSON)  # Layer sizes, etc.
    
    # Performance metrics
    threshold = Column(Float)
    threshold_percentile = Column(Float)
    validation_loss = Column(Float)
    training_duration_seconds = Column(Float, nullable=True)
    
    # File paths
    model_path = Column(String(255))
    scaler_path = Column(String(255))
    
    # Deployment status
    is_active = Column(Boolean, default=False, index=True)
    
    # Additional metadata
    metadata = Column(JSON, nullable=True)
