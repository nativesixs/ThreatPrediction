from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True)
    
    PROJECT_NAME: str = "Threat Prediction Backend"
    VERSION: str = "0.1.0"
    API_PREFIX: str = "/api/v1"
    
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000"
    ]
    
    # Database: SQLite for simplicity (supports async via aiosqlite)
    DATABASE_URL: str = "sqlite+aiosqlite:///./threat_detection.db"
    
    MODEL_PATH: str = "./models"
    LSTM_MODEL_FILE: str = "best_lstm_model.pth"
    CNN_MODEL_FILE: str = "best_cnn_model.pth"
    SCALER_FILE: str = ""  # Empty = disabled (live features have different distribution than training data)
    
    NETWORK_INTERFACE: str = "eth0"
    CAPTURE_BATCH_SIZE: int = 100
    PREDICTION_BATCH_SIZE: int = 32
    
    LOG_LEVEL: str = "INFO"


settings = Settings()
