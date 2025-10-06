"""
ETL pipeline: Create dataset from Zeek logs.
Parses Zeek connection logs, engineers features, and stores in database.
"""
import asyncio
from pathlib import Path
import argparse
from datetime import datetime
import logging
from sqlalchemy import select

from app.core.config import settings
from app.core.database import async_session_maker, init_db
from app.models.database_models import Flow
from app.ml.zeek_parser import ZeekLogParser
from app.ml.flow_feature_extractor import FlowFeatureExtractor

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def create_dataset(
    zeek_log_dir: Path,
    is_normal: bool = True,
    batch_size: int = 1000
):
    """
    Create dataset from Zeek logs.
    
    Args:
        zeek_log_dir: Directory containing Zeek conn.log files
        is_normal: Whether this traffic is normal (for training)
        batch_size: Number of flows to insert at once
    """
    logger.info(f"Starting ETL pipeline")
    logger.info(f"  Zeek log directory: {zeek_log_dir}")
    logger.info(f"  Traffic type: {'NORMAL' if is_normal else 'UNKNOWN'}")
    
    # Initialize database
    await init_db()
    logger.info("Database initialized")
    
    # Initialize parser and feature extractor
    parser = ZeekLogParser()
    extractor = FlowFeatureExtractor()
    
    # Find all conn.log files
    log_files = list(zeek_log_dir.glob("**/conn.log")) + \
                list(zeek_log_dir.glob("**/conn.*.log"))
    
    if not log_files:
        logger.error(f"No conn.log files found in {zeek_log_dir}")
        return
    
    logger.info(f"Found {len(log_files)} log file(s)")
    
    total_flows = 0
    total_inserted = 0
    
    for log_file in log_files:
        logger.info(f"Processing {log_file}")
        
        # Parse log file
        flows = parser.parse_file(log_file)
        total_flows += len(flows)
        
        if not flows:
            logger.warning(f"No flows parsed from {log_file}")
            continue
        
        # Extract features for all flows
        features_batch = extractor.extract_batch(flows)
        
        # Insert in batches
        async with async_session_maker() as session:
            for i in range(0, len(flows), batch_size):
                batch_flows = flows[i:i + batch_size]
                batch_features = features_batch[i:i + batch_size]
                
                # Create Flow objects
                flow_objects = []
                for flow_data, features in zip(batch_flows, batch_features):
                    flow_obj = Flow(
                        timestamp=flow_data['timestamp'],
                        uid=flow_data['uid'],
                        orig_ip=flow_data['orig_ip'],
                        orig_port=flow_data['orig_port'],
                        resp_ip=flow_data['resp_ip'],
                        resp_port=flow_data['resp_port'],
                        protocol=flow_data['protocol'],
                        service=flow_data['service'],
                        duration=flow_data['duration'],
                        orig_bytes=flow_data['orig_bytes'],
                        resp_bytes=flow_data['resp_bytes'],
                        orig_pkts=flow_data['orig_pkts'],
                        resp_pkts=flow_data['resp_pkts'],
                        orig_ip_bytes=flow_data.get('orig_ip_bytes'),
                        resp_ip_bytes=flow_data.get('resp_ip_bytes'),
                        conn_state=flow_data['conn_state'],
                        features=features.tolist(),  # Store as JSON
                        is_normal=is_normal,
                        zeek_metadata=flow_data.get('zeek_metadata')
                    )
                    flow_objects.append(flow_obj)
                
                # Bulk insert
                session.add_all(flow_objects)
                await session.commit()
                
                total_inserted += len(flow_objects)
                logger.info(f"  Inserted {total_inserted}/{total_flows} flows")
    
    logger.info(f"ETL pipeline completed")
    logger.info(f"  Total flows processed: {total_flows}")
    logger.info(f"  Total flows inserted: {total_inserted}")
    
    # Print dataset statistics
    async with async_session_maker() as session:
        result = await session.execute(
            select(Flow).where(Flow.is_normal == True)
        )
        normal_count = len(result.scalars().all())
        
        logger.info(f"Dataset statistics:")
        logger.info(f"  Normal flows in database: {normal_count}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Create dataset from Zeek connection logs'
    )
    parser.add_argument(
        '--zeek-log-dir',
        type=Path,
        default=settings.ZEEK_LOG_DIR,
        help='Directory containing Zeek conn.log files'
    )
    parser.add_argument(
        '--not-normal',
        action='store_true',
        help='Mark this traffic as non-normal (for testing/evaluation)'
    )
    parser.add_argument(
        '--batch-size',
        type=int,
        default=1000,
        help='Number of flows to insert at once'
    )
    
    args = parser.parse_args()
    
    # Run async function
    asyncio.run(create_dataset(
        zeek_log_dir=args.zeek_log_dir,
        is_normal=not args.not_normal,
        batch_size=args.batch_size
    ))


if __name__ == '__main__':
    main()
