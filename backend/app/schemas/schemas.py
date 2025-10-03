from pydantic import BaseModel, Field
from datetime import datetime
from typing import Dict, List, Optional


class TrafficLogBase(BaseModel):
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    packet_length: int
    flags: Optional[str] = None
    features: Dict


class TrafficLogCreate(TrafficLogBase):
    pass


class TrafficLogResponse(TrafficLogBase):
    id: int
    timestamp: datetime
    
    class Config:
        from_attributes = True


class PredictionBase(BaseModel):
    model_name: str
    model_version: Optional[str] = None  # v7 integration
    predicted_class: str
    confidence_score: float
    is_attack: bool
    is_confident: Optional[bool] = True  # v7: confidence threshold met
    severity: Optional[str] = None  # v7: CRITICAL, HIGH, MEDIUM, BENIGN
    all_probabilities: Dict[str, float]
    processing_time_ms: float


class PredictionCreate(PredictionBase):
    traffic_log_id: Optional[int] = None


class PredictionResponse(PredictionBase):
    id: int
    timestamp: datetime
    traffic_log_id: Optional[int]
    
    class Config:
        from_attributes = True


class AlertBase(BaseModel):
    severity: str
    attack_type: str
    source_ip: str
    destination_ip: str
    confidence: float
    description: str


class AlertCreate(AlertBase):
    prediction_id: int


class AlertResponse(AlertBase):
    id: int
    timestamp: datetime
    prediction_id: int
    acknowledged: bool
    
    class Config:
        from_attributes = True


class ModelMetricsBase(BaseModel):
    model_name: str
    model_version: str
    dataset_name: str
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    confusion_matrix: List[List[int]]
    class_metrics: Dict[str, Dict[str, float]]
    training_duration_seconds: float
    parameters: Dict


class ModelMetricsCreate(ModelMetricsBase):
    pass


class ModelMetricsResponse(ModelMetricsBase):
    id: int
    timestamp: datetime
    
    class Config:
        from_attributes = True


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str


class WebSocketMessage(BaseModel):
    type: str
    data: Dict
    timestamp: datetime = Field(default_factory=datetime.utcnow)
