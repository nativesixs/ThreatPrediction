#!/usr/bin/env python3
"""
Feature Analysis Tool - Debug why attacks aren't being detected
Analyzes what features are being extracted vs what the model expects
"""
import sys
import json
import numpy as np
from pathlib import Path

# Add the backend directory to path
backend_dir = Path(__file__).parent
sys.path.insert(0, str(backend_dir))


def analyze_live_vs_training_features():
    """Compare live feature extraction with training data expectations."""
    print("=== FEATURE ANALYSIS: Live vs Training ===")
    
    # Test with rapid connection pattern (like our attack simulation)
    rapid_connection_packet = {
        'timestamp': '2025-10-03T17:49:53.000000',
        'packet_length': 60,  # Small SYN packet
        'source_ip': '127.0.0.1',
        'destination_ip': '127.0.0.1', 
        'source_port': 12345,
        'destination_port': 80,
        'protocol': 6,  # TCP
        'tcp_flags': 2,  # SYN flag
        'transport_protocol': 'TCP',
        'ttl': 64,
        'payload_length': 0,  # SYN has no payload
        'packet_type': 'TCP_SYN'
    }
    
    print("1. Rapid connection packet features:")
    for k, v in rapid_connection_packet.items():
        print(f"   {k}: {v}")
    
    # Test feature extraction
    try:
        from app.services.live_feature_extractor import LiveFeatureExtractor
        extractor = LiveFeatureExtractor()
        
        print("\n2. Testing feature extraction...")
        
        # Extract features for single packet
        features = extractor.process_packet(rapid_connection_packet)
        print(f"✓ Extracted {len(features)} features")
        
        # Show key features that might indicate attack
        attack_indicators = [
            'packet_length', 'tcp_flags', 'payload_length', 
            'is_tcp', 'port_80', 'is_syn'
        ]
        
        print("\n3. Attack-relevant features:")
        for indicator in attack_indicators:
            if indicator in features:
                print(f"   {indicator}: {features[indicator]}")
        
        # Process as batch to see final model input
        batch_features = extractor.process_batch([rapid_connection_packet])
        print(f"\n4. Final model input shape: {batch_features.shape}")
        print(f"   Feature range: [{batch_features.min():.3f}, {batch_features.max():.3f}]")
        
        # Check if features look like attack patterns
        if batch_features.size > 0:
            # Look for patterns that should indicate DOS/attack
            feature_analysis = {
                'has_small_packets': np.any(batch_features < 100),  # Small packets typical in SYN flood
                'has_zero_payload': np.any(batch_features == 0),   # SYN packets have no payload
                'has_tcp_features': np.any(batch_features > 0),    # Should have TCP-related features
                'feature_variance': np.var(batch_features),        # Low variance might indicate synthetic/attack
            }
            
            print("\n5. Attack pattern analysis:")
            for pattern, detected in feature_analysis.items():
                print(f"   {pattern}: {detected}")
        
        return features, batch_features
        
    except Exception as e:
        print(f"❌ Feature extraction failed: {e}")
        import traceback
        traceback.print_exc()
        return None, None


def analyze_model_expectations():
    """Analyze what the model was trained to expect vs what we're feeding it."""
    print("\n=== MODEL EXPECTATION ANALYSIS ===")
    
    try:
        # Check model metadata
        model_path = Path(__file__).parent / "models" / "model_v10_metadata.json"
        if model_path.exists():
            with open(model_path, 'r') as f:
                metadata = json.load(f)
            
            print("1. Model training info:")
            print(f"   Dataset: {metadata.get('dataset_info', {}).get('name', 'unknown')}")
            print(f"   Training samples: {metadata.get('dataset_info', {}).get('total_samples', 'unknown')}")
            print(f"   Attack types: {metadata.get('dataset_info', {}).get('attack_types', 'unknown')}")
            
            # Check class distribution
            if 'class_distribution' in metadata.get('dataset_info', {}):
                print("\n2. Training class distribution:")
                for class_name, count in metadata['dataset_info']['class_distribution'].items():
                    print(f"   {class_name}: {count}")
            
            # Check feature expectations
            if 'feature_info' in metadata:
                print(f"\n3. Expected features: {metadata['feature_info'].get('num_features', 'unknown')}")
                if 'feature_ranges' in metadata['feature_info']:
                    ranges = metadata['feature_info']['feature_ranges']
                    print(f"   Feature range: [{ranges.get('min', '?')}, {ranges.get('max', '?')}]")
        
        else:
            print("❌ No model metadata found")
    
    except Exception as e:
        print(f"❌ Metadata analysis failed: {e}")


def check_domain_adaptation():
    """Check if CORAL domain adaptation is working properly."""
    print("\n=== DOMAIN ADAPTATION CHECK ===")
    
    try:
        # Check if CORAL transformer exists and is being used
        coral_path = Path(__file__).parent / "models" / "stage_b_coral_transformer.pkl"
        
        if coral_path.exists():
            print("✓ CORAL transformer found")
            
            # Check file size/modification time
            stat = coral_path.stat()
            print(f"   Size: {stat.st_size} bytes")
            print(f"   Modified: {stat.st_mtime}")
            
            # Try to load it
            import pickle
            with open(coral_path, 'rb') as f:
                coral_transformer = pickle.load(f)
            print(f"✓ CORAL transformer loaded successfully")
            print(f"   Type: {type(coral_transformer)}")
            
        else:
            print("❌ CORAL transformer not found - domain adaptation disabled!")
            print("   This could explain why live traffic != training data")
        
    except Exception as e:
        print(f"❌ CORAL check failed: {e}")


def suggest_fixes():
    """Suggest fixes based on analysis."""
    print("\n=== SUGGESTED FIXES ===")
    
    print("Based on analysis, the model might not detect attacks because:")
    print("1. 🎯 Feature Mismatch: Live features != training features")
    print("   • Check if TCP SYN patterns are being extracted correctly")
    print("   • Verify feature ranges match training data")
    
    print("\n2. 🌍 Domain Shift: Live network != training dataset") 
    print("   • CORAL domain adaptation might not be working")
    print("   • Training data might be from different network environment")
    
    print("\n3. 🔧 Model Sensitivity: Model not tuned for live traffic")
    print("   • Confidence thresholds might be too high")
    print("   • Model might need retraining on live data")
    
    print("\n4. 📊 Attack Pattern Mismatch: Simulation != real attacks")
    print("   • Our SYN flood might not match training attack patterns")
    print("   • Need more diverse attack types")
    
    print("\n🚀 IMMEDIATE ACTIONS:")
    print("1. Lower confidence thresholds temporarily")
    print("2. Add more aggressive attack patterns")
    print("3. Check if DOS class is being predicted at all (even low confidence)")
    print("4. Validate CORAL domain adaptation is working")


def main():
    """Run comprehensive feature analysis."""
    print("🔬 THREAT DETECTION FEATURE ANALYSIS")
    print("=" * 60)
    
    # Analyze current feature extraction
    features, batch_features = analyze_live_vs_training_features()
    
    # Check model training expectations
    analyze_model_expectations()
    
    # Check domain adaptation
    check_domain_adaptation()
    
    # Provide actionable suggestions
    suggest_fixes()
    
    print("\n" + "=" * 60)
    print("📊 ANALYSIS COMPLETE")
    
    if features and batch_features is not None:
        print("✅ Feature extraction working")
        print("🔍 Check suggestions above for why attacks aren't detected")
    else:
        print("❌ Feature extraction broken - fix this first!")


if __name__ == "__main__":
    main()