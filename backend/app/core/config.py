from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List
from pathlib import Path


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True)
    
    PROJECT_NAME: str = "Network Intrusion Detection System"
    VERSION: str = "0.1.0"
    API_PREFIX: str = "/api"
    
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000"
    ]
    
    # Database: SQLite for simplicity (supports async via aiosqlite)
    DATABASE_URL: str = "sqlite+aiosqlite:///./nids.db"
    
    # Paths
    DATA_DIR: Path = Path("./data")
    ZEEK_LOG_DIR: Path = Path("./data/zeek_logs")
    ARTIFACTS_DIR: Path = Path("./artifacts")
    
    # Model configuration
    AUTOENCODER_MODEL_FILE: str = "autoencoder.pth"
    SCALER_FILE: str = "scaler.pkl"
    THRESHOLD_FILE: str = "threshold.json"
    
    # Zeek configuration
    ZEEK_CONN_LOG: str = "conn.log"
    
    # Training configuration
    ANOMALY_THRESHOLD_PERCENTILE: float = 95.0  # 95th percentile of reconstruction errors
    VALIDATION_SPLIT: float = 0.2
    BATCH_SIZE: int = 64
    LEARNING_RATE: float = 0.001
    MAX_EPOCHS: int = 100
    EARLY_STOPPING_PATIENCE: int = 10
    
    # Feature engineering
    NUM_FEATURES: int = 20  # Will be determined by feature extractor
    
    # Live monitoring
    NETWORK_INTERFACE: str = "eth0"
    LOG_WATCH_INTERVAL: float = 1.0  # seconds
    
    LOG_LEVEL: str = "INFO"


settings = Settings()
