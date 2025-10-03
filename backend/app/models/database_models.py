from sqlalchemy import Column, Integer, String, Float, DateTime, JSON, Boolean, Text
from sqlalchemy.sql import func
from app.core.database import Base


class TrafficLog(Base):
    __tablename__ = "traffic_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    source_ip = Column(String(45), index=True)
    destination_ip = Column(String(45), index=True)
    source_port = Column(Integer)
    destination_port = Column(Integer)
    protocol = Column(String(10))
    packet_length = Column(Integer)
    flags = Column(String(50))
    features = Column(JSON)
    raw_data = Column(Text, nullable=True)


class Prediction(Base):
    __tablename__ = "predictions"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    traffic_log_id = Column(Integer, index=True, nullable=True)
    model_name = Column(String(50), index=True)
    model_version = Column(String(20), nullable=True)  # v7 integration
    predicted_class = Column(String(100), index=True)
    confidence_score = Column(Float)
    is_attack = Column(Boolean, index=True)
    is_confident = Column(Boolean, default=True, nullable=True)  # v7: confidence threshold met
    severity = Column(String(20), nullable=True)  # v7: CRITICAL, HIGH, MEDIUM, BENIGN
    all_probabilities = Column(JSON)
    processing_time_ms = Column(Float)


class Alert(Base):
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    prediction_id = Column(Integer, index=True)
    severity = Column(String(20), index=True)
    attack_type = Column(String(100))
    source_ip = Column(String(45))
    destination_ip = Column(String(45))
    confidence = Column(Float)
    description = Column(Text)
    acknowledged = Column(Boolean, default=False, index=True)


class ModelMetrics(Base):
    __tablename__ = "model_metrics"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    model_name = Column(String(50), index=True)
    model_version = Column(String(20))
    dataset_name = Column(String(100))
    accuracy = Column(Float)
    precision = Column(Float)
    recall = Column(Float)
    f1_score = Column(Float)
    confusion_matrix = Column(JSON)
    class_metrics = Column(JSON)
    training_duration_seconds = Column(Float)
    parameters = Column(JSON)
