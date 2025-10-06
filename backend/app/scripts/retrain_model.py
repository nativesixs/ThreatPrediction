"""
Retrain model on recent normal traffic.
Used for adaptive learning when network conditions change.
"""
import asyncio
import argparse
import numpy as np
from datetime import datetime, timedelta
import logging
from sqlalchemy import select, and_

from app.core.config import settings
from app.core.database import async_session_maker, init_db
from app.models.database_models import Flow, Anomaly, Model
from app.ml.autoencoder_trainer import AutoencoderTrainer

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def retrain_model(
    lookback_hours: int = 72,
    min_samples: int = 1000,
    include_verified_normal: bool = True
):
    """
    Retrain model on recent traffic.
    
    Args:
        lookback_hours: Hours to look back for training data
        min_samples: Minimum samples required
        include_verified_normal: Include flows marked as false positives
    """
    logger.info("Starting model retraining")
    logger.info(f"  Lookback period: {lookback_hours} hours")
    
    # Initialize database
    await init_db()
    
    # Calculate time threshold
    time_threshold = datetime.now() - timedelta(hours=lookback_hours)
    
    # Collect recent normal flows
    logger.info("Collecting recent normal flows...")
    async with async_session_maker() as session:
        # Get flows that are either:
        # 1. Marked as normal (is_normal=True)
        # 2. Were flagged as anomalies but verified as false positives
        
        # Normal flows
        result = await session.execute(
            select(Flow).where(
                and_(
                    Flow.is_normal == True,
                    Flow.timestamp >= time_threshold
                )
            )
        )
        normal_flows = result.scalars().all()
        
        logger.info(f"Found {len(normal_flows)} recent normal flows")
        
        # False positives (if enabled)
        verified_flows = []
        if include_verified_normal:
            result = await session.execute(
                select(Flow)
                .join(Anomaly, Anomaly.flow_id == Flow.id)
                .where(
                    and_(
                        Anomaly.false_positive == True,
                        Flow.timestamp >= time_threshold
                    )
                )
            )
            verified_flows = result.scalars().all()
            logger.info(f"Found {len(verified_flows)} verified false positives")
        
        # Combine
        all_flows = normal_flows + verified_flows
        
        if len(all_flows) < min_samples:
            logger.error(
                f"Insufficient training data: {len(all_flows)} flows "
                f"(minimum: {min_samples})"
            )
            logger.error(
                f"Increase lookback period or wait for more normal traffic"
            )
            return
        
        logger.info(f"Total training samples: {len(all_flows)}")
        
        # Extract features
        logger.info("Extracting features...")
        features_list = []
        for flow in all_flows:
            if flow.features:
                features_list.append(flow.features)
        
        X = np.array(features_list, dtype=np.float32)
        logger.info(f"Feature matrix shape: {X.shape}")
        
        # Clean data
        if np.any(np.isnan(X)) or np.any(np.isinf(X)):
            logger.warning("Cleaning NaN/Inf values...")
            X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
        
        # Initialize trainer
        input_size = X.shape[1]
        trainer = AutoencoderTrainer(
            input_size=input_size,
            artifacts_dir=settings.ARTIFACTS_DIR
        )
        
        # Train model
        logger.info("Retraining autoencoder...")
        start_time = datetime.now()
        
        training_results = trainer.train(X=X)
        
        training_duration = (datetime.now() - start_time).total_seconds()
        logger.info(f"Retraining completed in {training_duration:.2f} seconds")
        
        # Save artifacts
        logger.info("Saving updated model artifacts...")
        artifact_paths = trainer.save_artifacts(training_results)
        
        # Deactivate previous models
        result = await session.execute(
            select(Model).where(Model.is_active == True)
        )
        previous_models = result.scalars().all()
        for prev_model in previous_models:
            prev_model.is_active = False
            logger.info(f"Deactivated model {prev_model.version}")
        
        # Save new model metadata
        model_record = Model(
            model_type='autoencoder',
            version=f"v{datetime.now().strftime('%Y%m%d_%H%M%S')}_retrained",
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
                'retrained': True,
                'lookback_hours': lookback_hours,
                'num_epochs': training_results['num_epochs'],
                'history': trainer.history
            }
        )
        
        session.add(model_record)
        await session.commit()
        await session.refresh(model_record)
        
        logger.info(f"Retrained model saved with ID: {model_record.id}")
        logger.info(f"  Version: {model_record.version}")
        logger.info(f"  New threshold: {model_record.threshold:.6f}")
        logger.info(f"  Validation loss: {model_record.validation_loss:.6f}")
    
    logger.info("Retraining completed successfully!")
    logger.info("The inference service will use the new model on next restart")
    
    return model_record.id


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Retrain model on recent normal traffic'
    )
    parser.add_argument(
        '--lookback-hours',
        type=int,
        default=72,
        help='Hours to look back for training data'
    )
    parser.add_argument(
        '--min-samples',
        type=int,
        default=1000,
        help='Minimum number of samples required'
    )
    parser.add_argument(
        '--no-verified',
        action='store_true',
        help='Do not include verified false positives'
    )
    
    args = parser.parse_args()
    
    # Run async function
    asyncio.run(retrain_model(
        lookback_hours=args.lookback_hours,
        min_samples=args.min_samples,
        include_verified_normal=not args.no_verified
    ))


if __name__ == '__main__':
    main()
