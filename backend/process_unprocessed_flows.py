#!/usr/bin/env python3
"""
Process flows that don't have anomaly records yet.
This fixes any gaps in real-time processing.
"""
import asyncio
import sys
from pathlib import Path

# Add the backend directory to path
backend_dir = Path(__file__).parent
sys.path.insert(0, str(backend_dir))

from app.core.database import async_session_maker
from app.models.database_models import Flow, Anomaly
from app.ml.anomaly_detector import load_detector
from app.ml.flow_feature_extractor import FlowFeatureExtractor
from sqlalchemy import select
from datetime import datetime

async def process_unprocessed_flows():
    """Process flows that don't have anomaly records."""
    print("Processing unprocessed flows...")
    
    # Load detector
    try:
        detector = load_detector()
        print(f"Model loaded with threshold: {detector.threshold}")
    except Exception as e:
        print(f"Failed to load model: {e}")
        return
    
    extractor = FlowFeatureExtractor()
    
    async with async_session_maker() as session:
        # Get flows without anomaly records
        subquery = select(Anomaly.flow_id)
        result = await session.execute(
            select(Flow).where(
                Flow.id.notin_(subquery)
            ).order_by(Flow.timestamp.desc()).limit(200)
        )
        unprocessed_flows = result.scalars().all()
    
    print(f"Found {len(unprocessed_flows)} unprocessed flows")
    
    if not unprocessed_flows:
        print("All flows are processed")
        return
    
    anomalies_created = 0
    
    for flow in unprocessed_flows:
        flow_dict = {
            'timestamp': flow.timestamp, 'uid': flow.uid,
            'orig_ip': flow.orig_ip, 'orig_port': flow.orig_port,
            'resp_ip': flow.resp_ip, 'resp_port': flow.resp_port,
            'protocol': flow.protocol, 'service': flow.service,
            'duration': flow.duration, 'orig_bytes': flow.orig_bytes,
            'resp_bytes': flow.resp_bytes, 'orig_pkts': flow.orig_pkts,
            'resp_pkts': flow.resp_pkts, 'orig_ip_bytes': flow.orig_ip_bytes,
            'resp_ip_bytes': flow.resp_ip_bytes, 'conn_state': flow.conn_state
        }
        
        try:
            features = extractor.extract_features(flow_dict)
            result = detector.predict_single(features)
            
            # Create anomaly record for ALL flows
            async with async_session_maker() as session:
                anomaly = Anomaly(
                    timestamp=datetime.now(),
                    flow_id=flow.id,
                    reconstruction_error=result['reconstruction_error'],
                    threshold=result['threshold'],
                    anomaly_score=result['anomaly_score'],
                    is_anomaly=result['is_anomaly'],
                    severity=result['severity'],
                    model_id=result.get('model_id')
                )
                session.add(anomaly)
                await session.commit()
                
                if result['is_anomaly']:
                    print(f"ANOMALY: Flow {flow.id} | {result['severity']} | Error: {result['reconstruction_error']:.4f}")
                    anomalies_created += 1
                    
        except Exception as e:
            print(f"Failed to process flow {flow.id}: {e}")
    
    print(f"Processing complete!")
    print(f"Anomalies detected: {anomalies_created}/{len(unprocessed_flows)}")

if __name__ == "__main__":
    asyncio.run(process_unprocessed_flows())