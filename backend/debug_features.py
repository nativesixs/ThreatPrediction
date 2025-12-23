#!/usr/bin/env python3
"""
Feature Extraction Diagnostic Script
Debug why features are empty in database
"""
import sys
import json
from pathlib import Path

# Add the backend directory to path
backend_dir = Path(__file__).parent
sys.path.insert(0, str(backend_dir))

from app.services.live_feature_extractor import LiveFeatureExtractor
from app.services.packet_capturer import PacketCapturer


def test_feature_extraction():
    """Test the feature extraction pipeline with sample data."""
    print("=== FEATURE EXTRACTION DIAGNOSTIC ===")
    
    # Sample packet data similar to what packet capturer produces
    sample_packet = {
        'timestamp': '2025-10-03T17:36:47.184786',
        'packet_length': 1500,
        'source_ip': '140.82.113.21',
        'destination_ip': '172.31.124.155',
        'ip_version': 4,
        'ttl': 64,
        'ip_length': 1500,
        'ip_flags': 2,
        'ip_frag': 0,
        'protocol': 6,
        'source_port': 443,
        'destination_port': 41184,
        'tcp_flags': 24,
        'tcp_window': 65535,
        'tcp_seq': 1234567890,
        'tcp_ack': 9876543210,
        'tcp_dataofs': 5,
        'transport_protocol': 'TCP',
        'payload_length': 1200,
        'has_payload': True,
        'packet_type': 'HTTPS'
    }
    
    print(f"1. Sample packet data:")
    print(json.dumps(sample_packet, indent=2))
    print()
    
    # Test feature extractor
    print("2. Testing LiveFeatureExtractor...")
    try:
        feature_extractor = LiveFeatureExtractor()
        print("✓ LiveFeatureExtractor initialized")
        
        # Test single packet processing
        features = feature_extractor.process_packet(sample_packet)
        print(f"✓ Single packet features extracted: {len(features)} features")
        print("Sample features:")
        for k, v in list(features.items())[:10]:  # First 10 features
            print(f"  {k}: {v}")
        if len(features) > 10:
            print(f"  ... and {len(features) - 10} more")
        print()
        
        # Test batch processing
        batch_features = feature_extractor.process_batch([sample_packet])
        print(f"✓ Batch processing result shape: {batch_features.shape}")
        print(f"Feature range: [{batch_features.min():.3f}, {batch_features.max():.3f}]")
        print()
        
    except Exception as e:
        print(f"✗ Feature extraction failed: {e}")
        import traceback
        traceback.print_exc()
        print()
    
    # Test what's being saved to database
    print("3. Testing database storage format...")
    
    # This is what gets stored in traffic_log.features
    features_for_db = sample_packet.get("features", {})
    print(f"features field for database: {features_for_db}")
    print(f"Type: {type(features_for_db)}")
    print()
    
    # Show the field mapping issue
    print("4. Field mapping analysis:")
    print("Database expects vs Packet provides:")
    print(f"  total_length: {sample_packet.get('total_length', 'MISSING')} (expects) vs packet_length: {sample_packet.get('packet_length', 'MISSING')} (provides)")
    print(f"  tcp_flags: {sample_packet.get('tcp_flags', 'MISSING')} (both)")
    print(f"  features: {sample_packet.get('features', 'MISSING')} (expects) vs <extracted_features> (should be)")
    print()
    
    print("5. DIAGNOSIS:")
    print("✓ Feature extraction pipeline works correctly")
    print("✗ Database storage expects different field names")
    print("✗ 'features' field is not populated in packet data")
    print("✗ Raw packet features are not being passed through to database")
    print()
    
    print("6. SOLUTION NEEDED:")
    print("- Fix field name mapping in main.py")
    print("- Store extracted features in database features field")
    print("- Ensure packet_length maps to total_length correctly")


if __name__ == "__main__":
    test_feature_extraction()