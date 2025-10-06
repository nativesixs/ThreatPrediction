"""
Train autoencoder model on normal traffic.
Loads normal flows from database, trains model, saves artifacts.
"""
import asyncio
import argparse
import numpy as np
from pathlib import Path
from datetime import datetime
import logging
from sqlalchemy import select

from app.core.config import settings
from app.core.database import async_session_maker, init_db
from app.models.database_models import Flow, Model
from app.ml.autoencoder_trainer import AutoencoderTrainer

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def train_model(
    min_samples: int = 1000,
    max_samples: int = None,
    hidden_layers: list = None,
    learning_rate: float = None,
    max_epochs: int = None
):
    """
    Train autoencoder on normal traffic from database.
    
    Args:
        min_samples: Minimum number of samples required
        max_samples: Maximum number of samples to use
        hidden_layers: List of hidden layer sizes
        learning_rate: Learning rate for training
        max_epochs: Maximum number of epochs
    """
    logger.info("Starting model training pipeline")
    
    # Initialize database
    await init_db()
    
    # Load normal flows from database
    logger.info("Loading normal flows from database...")
    async with async_session_maker() as session:
        result = await session.execute(
            select(Flow).where(Flow.is_normal == True)
        )
        flows = result.scalars().all()
    
    if len(flows) < min_samples:
        logger.error(f"Insufficient training data: {len(flows)} flows (minimum: {min_samples})")
        logger.error("Please run create-dataset to collect more normal traffic")
        return
    
    logger.info(f"Loaded {len(flows)} normal flows")
    
    # Limit samples if specified
    if max_samples and len(flows) > max_samples:
        import random
        flows = random.sample(flows, max_samples)
        logger.info(f"Using {len(flows)} random samples")
    
    # Extract features
    logger.info("Extracting features...")
    features_list = []
    for flow in flows:
        if flow.features:
            features_list.append(flow.features)
    
    if len(features_list) == 0:
        logger.error("No features found in flows. Run create-dataset first.")
        return
    
    X = np.array(features_list, dtype=np.float32)
    logger.info(f"Feature matrix shape: {X.shape}")
    
    # Check for NaN/Inf values
    if np.any(np.isnan(X)) or np.any(np.isinf(X)):
        logger.warning("Detected NaN or Inf values in features, cleaning...")
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
    
    # Initialize trainer
    input_size = X.shape[1]
    trainer = AutoencoderTrainer(
        input_size=input_size,
        hidden_layers=hidden_layers,
        artifacts_dir=settings.ARTIFACTS_DIR
    )
    
    # Train model
    logger.info("Training autoencoder...")
    start_time = datetime.now()
    
    training_results = trainer.train(
        X=X,
        learning_rate=learning_rate,
        max_epochs=max_epochs
    )
    
    training_duration = (datetime.now() - start_time).total_seconds()
    logger.info(f"Training completed in {training_duration:.2f} seconds")
    
    # Save artifacts
    logger.info("Saving model artifacts...")
    artifact_paths = trainer.save_artifacts(training_results)
    
    # Save model metadata to database
    logger.info("Saving model metadata to database...")
    async with async_session_maker() as session:
        # Deactivate previous models
        result = await session.execute(
            select(Model).where(Model.is_active == True)
        )
        previous_models = result.scalars().all()
        for prev_model in previous_models:
            prev_model.is_active = False
        
        # Create new model record
        model_record = Model(
            model_type='autoencoder',
            version=f"v{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            training_size=training_results['training_samples'],
            validation_size=training_results['validation_samples'],
            num_features=input_size,
            architecture=trainer.model.get_architecture(),
            threshold=training_results['threshold'],
            threshold_percentile=training_results['threshold_percentile'],
            validation_loss=training_results['best_val_loss'],
            training_duration_seconds=training_duration,
            model_path=str(artifact_paths['model']),
            scaler_path=str(artifact_paths.get('scaler', '')),
            is_active=True,
            metadata={
                'num_epochs': training_results['num_epochs'],
                'history': trainer.history
            }
        )
        
        session.add(model_record)
        await session.commit()
        await session.refresh(model_record)
        
        logger.info(f"Model saved with ID: {model_record.id}")
        logger.info(f"  Version: {model_record.version}")
        logger.info(f"  Threshold: {model_record.threshold:.6f}")
        logger.info(f"  Validation Loss: {model_record.validation_loss:.6f}")
    
    logger.info("Training pipeline completed successfully!")
    return model_record.id


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Train autoencoder model on normal traffic'
    )
    parser.add_argument(
        '--min-samples',
        type=int,
        default=1000,
        help='Minimum number of samples required for training'
    )
    parser.add_argument(
        '--max-samples',
        type=int,
        default=None,
        help='Maximum number of samples to use'
    )
    parser.add_argument(
        '--hidden-layers',
        type=int,
        nargs='+',
        default=None,
        help='Hidden layer sizes (e.g., 128 64 32 16)'
    )
    parser.add_argument(
        '--learning-rate',
        type=float,
        default=None,
        help='Learning rate'
    )
    parser.add_argument(
        '--max-epochs',
        type=int,
        default=None,
        help='Maximum number of epochs'
    )
    
    args = parser.parse_args()
    
    # Run async function
    asyncio.run(train_model(
        min_samples=args.min_samples,
        max_samples=args.max_samples,
        hidden_layers=args.hidden_layers,
        learning_rate=args.learning_rate,
        max_epochs=args.max_epochs
    ))


if __name__ == '__main__':
    main()
