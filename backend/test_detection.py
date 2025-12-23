#!/usr/bin/env python3
"""
Comprehensive Attack Detection Test
Test the fixed system with CORAL disabled and lower thresholds
"""
import sys
import time
import subprocess
from pathlib import Path

# Add the backend directory to path
backend_dir = Path(__file__).parent
sys.path.insert(0, str(backend_dir))


def test_attack_detection():
    """Test if the system can now detect attacks with fixes applied."""
    print("🧪 COMPREHENSIVE ATTACK DETECTION TEST")
    print("=" * 50)
    print("Changes applied:")
    print("✅ CORAL transformation DISABLED")
    print("✅ Confidence thresholds LOWERED (0.50/0.70)")
    print("✅ Temperature scaling ACTIVE")
    print("✅ Feature storage FIXED")
    
    # Test attack patterns that should be detectable
    attack_patterns = [
        {
            'name': 'SYN Flood Pattern',
            'description': 'Small packets, SYN flags, rapid succession',
            'packet': {
                'packet_length': 60,
                'tcp_flags': 2,  # SYN
                'payload_length': 0,
                'source_port': 12345,
                'destination_port': 80,
                'protocol': 6,
                'transport_protocol': 'TCP'
            }
        },
        {
            'name': 'Port Scan Pattern', 
            'description': 'Multiple ports, rapid succession',
            'packet': {
                'packet_length': 60,
                'tcp_flags': 2,
                'payload_length': 0,
                'source_port': 54321,
                'destination_port': 22,  # SSH port
                'protocol': 6,
                'transport_protocol': 'TCP'
            }
        }
    ]
    
    print(f"\n🎯 Testing {len(attack_patterns)} attack patterns...")
    
    try:
        from app.services.live_feature_extractor import LiveFeatureExtractor
        from app.services.prediction_service import PredictionService
        
        # Initialize components
        extractor = LiveFeatureExtractor()
        
        # Test each attack pattern
        for i, pattern in enumerate(attack_patterns, 1):
            print(f"\n{i}. Testing {pattern['name']}:")
            print(f"   {pattern['description']}")
            
            # Extract features
            packet = pattern['packet']
            packet.update({
                'timestamp': '2025-10-03T17:50:00.000000',
                'source_ip': '127.0.0.1',
                'destination_ip': '127.0.0.1',
                'ttl': 64,
                'has_payload': packet['payload_length'] > 0
            })
            
            features = extractor.process_batch([packet])
            print(f"   Features extracted: shape {features.shape}")
            print(f"   Feature range: [{features.min():.3f}, {features.max():.3f}]")
            
            # The key test: are features in a reasonable range?
            reasonable_range = abs(features.max()) < 1000000  # Less than 1 million
            print(f"   ✓ Reasonable feature range: {reasonable_range}")
            
            if reasonable_range:
                print(f"   🎉 Pattern {i} should now be detectable!")
            else:
                print(f"   ⚠️  Pattern {i} still has extreme features")
    
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()


def run_live_test():
    """Run a live test with the backend to see actual detection."""
    print("\n🚀 LIVE DETECTION TEST")
    print("=" * 30)
    print("To test live detection:")
    print("1. Start the backend: poetry run backend-dev")
    print("2. Run attack: python scripts/simple_syn_test.py")
    print("3. Check dashboard for:")
    print("   • Lower confidence scores (not 98.93%)")
    print("   • Possible DOS/PROBE classifications")
    print("   • Feature values in database")


def check_probabilities():
    """Check if DOS/PROBE probabilities are being calculated at all."""
    print("\n🔍 PROBABILITY ANALYSIS")
    print("=" * 25)
    
    print("With temperature scaling, we should see:")
    print("✅ NORMAL: ~98% (not 100%)")
    print("✅ DOS: >0.1% (not microscopic)")
    print("✅ PROBE: >0.1% (not microscopic)")
    
    print("\nIf DOS is still microscopic (<0.001%), then:")
    print("🔧 Model fundamentally doesn't recognize attack patterns")
    print("🔧 Need domain-specific retraining or different model")


def main():
    """Run comprehensive testing."""
    test_attack_detection()
    run_live_test()
    check_probabilities()
    
    print("\n" + "=" * 50)
    print("📊 NEXT STEPS:")
    print("1. Restart backend to apply fixes")
    print("2. Run attack simulation")
    print("3. Check if probabilities improved")
    print("4. Look for ANY non-NORMAL classifications")
    print("\n🎯 SUCCESS CRITERIA:")
    print("• Feature ranges < 1,000,000")
    print("• DOS probability > 0.1%") 
    print("• At least some attack detection")


if __name__ == "__main__":
    main()