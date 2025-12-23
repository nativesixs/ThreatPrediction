#!/usr/bin/env python3
"""
Anomaly Gate Training Script
Train the unsupervised anomaly detector on normal traffic samples
"""
import sys
import numpy as np
from pathlib import Path

# Add the backend directory to path
backend_dir = Path(__file__).parent
sys.path.insert(0, str(backend_dir))


def train_anomaly_gate():
    """Train the anomaly detection gate on normal traffic."""
    print("🤖 TRAINING ANOMALY DETECTION GATE")
    print("=" * 50)
    
    try:
        from app.ml.anomaly_gate import create_anomaly_gate
        from app.services.live_feature_extractor import LiveFeatureExtractor
        
        # Create components
        anomaly_gate = create_anomaly_gate(contamination=0.01)  # 1% anomaly rate
        feature_extractor = LiveFeatureExtractor()
        
        print("✓ Components initialized")
        
        # Generate synthetic normal traffic for training
        print("\n📊 Generating normal traffic samples...")
        normal_packets = []
        
        # Various normal traffic patterns
        patterns = [
            # HTTPS traffic
            {'packet_length': 1500, 'source_port': 443, 'destination_port': 54321, 'protocol': 6, 'tcp_flags': 24},
            {'packet_length': 1200, 'source_port': 443, 'destination_port': 54322, 'protocol': 6, 'tcp_flags': 16},
            {'packet_length': 800, 'source_port': 443, 'destination_port': 54323, 'protocol': 6, 'tcp_flags': 16},
            
            # HTTP traffic  
            {'packet_length': 1400, 'source_port': 80, 'destination_port': 54324, 'protocol': 6, 'tcp_flags': 24},
            {'packet_length': 1100, 'source_port': 80, 'destination_port': 54325, 'protocol': 6, 'tcp_flags': 16},
            
            # DNS traffic
            {'packet_length': 64, 'source_port': 53, 'destination_port': 54326, 'protocol': 17, 'tcp_flags': 0},
            {'packet_length': 128, 'source_port': 53, 'destination_port': 54327, 'protocol': 17, 'tcp_flags': 0},
            
            # SSH traffic
            {'packet_length': 1200, 'source_port': 22, 'destination_port': 54328, 'protocol': 6, 'tcp_flags': 24},
            {'packet_length': 800, 'source_port': 22, 'destination_port': 54329, 'protocol': 6, 'tcp_flags': 16},
        ]
        
        # Generate variations of normal patterns
        import time
        base_time = time.time()
        
        for pattern_idx, pattern in enumerate(patterns):
            for i in range(100):  # 100 variations of each pattern
                packet = pattern.copy()
                
                # Generate unique timestamps without seconds overflow
                timestamp_offset = (pattern_idx * 100 + i) * 0.1  # 0.1 seconds apart
                packet_time = base_time + timestamp_offset
                timestamp_str = time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(packet_time))
                timestamp_str += f'.{int((packet_time % 1) * 1000000):06d}'
                
                packet.update({
                    'timestamp': timestamp_str,
                    'source_ip': '172.31.124.155',
                    'destination_ip': '140.82.113.21',
                    'ttl': 64,
                    'payload_length': packet['packet_length'] - 60,  # Header size
                    'transport_protocol': 'TCP' if packet['protocol'] == 6 else 'UDP',
                    'has_payload': packet['packet_length'] > 60
                })
                normal_packets.append(packet)
        
        print(f"✓ Generated {len(normal_packets)} normal traffic samples")
        
        # Extract features
        print("\n🔧 Extracting features...")
        normal_features = []
        
        # Process packets in batch to get correct 35-feature vectors  
        try:
            batch_features = feature_extractor.process_batch(normal_packets)
            if len(batch_features) > 0:
                normal_features = batch_features
                print(f"✓ Extracted features: shape {normal_features.shape}")
                print(f"   Feature range: [{normal_features.min():.3f}, {normal_features.max():.3f}]")
            else:
                print("❌ No features extracted from batch processing")
                return False
        except Exception as e:
            print(f"❌ Batch processing failed: {e}")
            return False
        
        # Train anomaly detector
        print("\n🎓 Training anomaly detector...")
        anomaly_gate.fit(normal_features)
        
        # Test on training data
        anomaly_flags, anomaly_scores = anomaly_gate.predict_anomaly(normal_features)
        training_anomaly_rate = np.sum(anomaly_flags) / len(anomaly_flags)
        
        print(f"✓ Training completed!")
        print(f"   Expected anomaly rate: {anomaly_gate.contamination:.1%}")
        print(f"   Actual anomaly rate on training: {training_anomaly_rate:.1%}")
        
        # Save the trained gate
        save_path = Path(__file__).parent / "models" / "anomaly_gate.pkl"
        save_path.parent.mkdir(exist_ok=True)
        anomaly_gate.save(save_path)
        print(f"✓ Anomaly gate saved to {save_path}")
        
        # Test with attack-like patterns
        print("\n🧪 Testing with attack-like patterns...")
        attack_packet = {
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S.%f', time.localtime(time.time())),
            'packet_length': 60,  # Small SYN packet
            'source_ip': '127.0.0.1',
            'destination_ip': '127.0.0.1',
            'source_port': 12345,
            'destination_port': 80,
            'protocol': 6,
            'tcp_flags': 2,  # SYN flag
            'ttl': 64,
            'payload_length': 0,
            'transport_protocol': 'TCP',
            'has_payload': False
        }
        
        try:
            attack_batch = feature_extractor.process_batch([attack_packet])
            if len(attack_batch) > 0:
                attack_flags, attack_scores = anomaly_gate.predict_anomaly(attack_batch)
                
                print(f"   Attack pattern anomaly score: {attack_scores[0]:.3f}")
                print(f"   Classified as anomaly: {attack_flags[0]}")
            else:
                print("   Could not extract attack features")
        except Exception as e:
            print(f"   Attack test failed: {e}")
        
        print("\n🎉 ANOMALY GATE TRAINING COMPLETE!")
        print("✅ Two-stage detection ready!")
        
        return True
        
    except Exception as e:
        print(f"❌ Training failed: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Train and test anomaly detection gate."""
    success = train_anomaly_gate()
    
    if success:
        print("\n📋 NEXT STEPS:")
        print("1. Restart backend to load anomaly gate")
        print("2. Run attack simulation")
        print("3. Check logs for two-stage detection")
        print("4. Monitor anomaly vs classification rates")
    else:
        print("\n❌ Training failed - check logs and try again")


if __name__ == "__main__":
    main()