#!/usr/bin/env python3
"""
Test script for the evidence logging system.
Run this to validate that evidence collection is working properly.
"""

import sys
import os
from pathlib import Path

# Add parent directory to path to import app modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.utils.evidence_logger import get_evidence_logger, log_prediction_evidence, log_attack_evidence, log_system_evidence
from app.utils.evaluation_metrics import ThreatDetectionEvaluator
import json
from datetime import datetime

def test_evidence_logging():
    """Test evidence logging functionality"""
    print("🧪 Testing Evidence Logging System")
    print("=" * 50)
    
    # Test 1: Initialize evidence logger
    print("\n1. Initializing Evidence Logger...")
    try:
        logger = get_evidence_logger()
        print(f"✅ Evidence logger initialized")
        print(f"   Predictions file: {logger.predictions_file}")
        print(f"   Attacks file: {logger.attacks_file}")
        print(f"   System events file: {logger.system_events_file}")
    except Exception as e:
        print(f"❌ Failed to initialize evidence logger: {e}")
        return False
    
    # Test 2: Log system event
    print("\n2. Logging System Event...")
    try:
        log_system_evidence(
            event_type="SYSTEM_STARTUP",
            source="test_evidence_logging.py",
            message="Evidence logging system test started",
            data={"test_version": "1.0", "timestamp": datetime.now().isoformat()}
        )
        print("✅ System event logged successfully")
    except Exception as e:
        print(f"❌ Failed to log system event: {e}")
        return False
    
    # Test 3: Log attack evidence
    print("\n3. Logging Attack Evidence...")
    try:
        log_attack_evidence(
            attack_type="syn_flood",
            source_ip="127.0.0.1",
            target_ip="192.168.1.100",
            target_port=80,
            intensity=10,
            duration_seconds=30.0,
            packets_sent=300,
            command_used="test_evidence_logging.py --test syn_flood",
            expected_detection="DOS",
            notes="Test attack for evidence logging validation"
        )
        print("✅ Attack evidence logged successfully")
    except Exception as e:
        print(f"❌ Failed to log attack evidence: {e}")
        return False
    
    # Test 4: Log prediction evidence
    print("\n4. Logging Prediction Evidence...")
    try:
        test_probabilities = {
            "NORMAL": 0.95,
            "DOS": 0.03,
            "PROBE": 0.01,
            "EXPLOIT": 0.005,
            "MALWARE": 0.005
        }
        
        test_features = {
            "packet_length": 1500,
            "tcp_flags": "SYN",
            "inter_arrival_time": 0.001,
            "window_size": 65535
        }
        
        log_prediction_evidence(
            timestamp=datetime.now().isoformat(),
            flow_id="127.0.0.1:12345-192.168.1.100:80",
            source_ip="127.0.0.1",
            destination_ip="192.168.1.100",
            source_port=12345,
            destination_port=80,
            protocol="TCP",
            packet_length=1500,
            flags="SYN",
            model_name="lstm",
            model_version="stage_b_v1",
            predicted_class="NORMAL",
            confidence_score=0.95,
            is_attack=False,
            is_confident=True,
            severity="BENIGN",
            all_probabilities=test_probabilities,
            processing_time_ms=0.05,
            raw_features=test_features,
            session_id="test_session_001",
            attack_label=None,
            notes="Test prediction for evidence logging validation"
        )
        print("✅ Prediction evidence logged successfully")
    except Exception as e:
        print(f"❌ Failed to log prediction evidence: {e}")
        return False
    
    # Test 5: Read back evidence
    print("\n5. Reading Back Evidence...")
    try:
        recent_predictions = logger.get_recent_predictions(limit=5)
        attack_events = logger.get_attack_events()
        
        print(f"✅ Read {len(recent_predictions)} predictions and {len(attack_events)} attack events")
        
        if recent_predictions:
            print("   Latest prediction:")
            latest = recent_predictions[-1]
            print(f"     Class: {latest['predicted_class']}")
            print(f"     Confidence: {latest['confidence_score']}")
            print(f"     Source: {latest['source_ip']}:{latest['source_port']}")
            print(f"     Target: {latest['destination_ip']}:{latest['destination_port']}")
        
        if attack_events:
            print("   Latest attack event:")
            latest_attack = attack_events[-1]
            print(f"     Type: {latest_attack['attack_type']}")
            print(f"     Target: {latest_attack['target_ip']}:{latest_attack['target_port']}")
            print(f"     Expected detection: {latest_attack['expected_detection']}")
        
    except Exception as e:
        print(f"❌ Failed to read evidence: {e}")
        return False
    
    print("\n✅ All evidence logging tests passed!")
    return True

def test_evaluation_metrics():
    """Test evaluation metrics functionality"""
    print("\n\n🧪 Testing Evaluation Metrics System")
    print("=" * 50)
    
    try:
        # Create sample data for testing
        y_true = ["NORMAL", "NORMAL", "DOS", "PROBE", "NORMAL", "EXPLOIT", "NORMAL", "DOS"]
        y_pred = ["NORMAL", "NORMAL", "DOS", "NORMAL", "NORMAL", "EXPLOIT", "DOS", "NORMAL"]
        
        # Sample probability distributions
        y_proba = [
            [0.99, 0.005, 0.003, 0.001, 0.001],  # NORMAL -> NORMAL
            [0.98, 0.01, 0.005, 0.003, 0.002],   # NORMAL -> NORMAL  
            [0.1, 0.85, 0.03, 0.01, 0.01],       # DOS -> DOS
            [0.7, 0.05, 0.2, 0.03, 0.02],        # PROBE -> NORMAL (missed)
            [0.95, 0.02, 0.015, 0.01, 0.005],    # NORMAL -> NORMAL
            [0.05, 0.05, 0.05, 0.8, 0.05],       # EXPLOIT -> EXPLOIT
            [0.3, 0.6, 0.05, 0.03, 0.02],        # NORMAL -> DOS (false positive)
            [0.8, 0.15, 0.03, 0.01, 0.01]        # DOS -> NORMAL (missed)
        ]
        
        # Create evaluator
        evaluator = ThreatDetectionEvaluator()
        
        # Run evaluation
        print("1. Running evaluation...")
        results = evaluator.evaluate_predictions(y_true, y_pred, y_proba, save_plots=False)
        
        print("✅ Evaluation completed successfully")
        print(f"   Overall accuracy: {results['overall_accuracy']:.3f}")
        print(f"   Total samples: {results['total_samples']}")
        
        # Display per-class metrics
        print("\n2. Per-class Results:")
        for class_name, metrics in results['per_class_metrics'].items():
            print(f"   {class_name}:")
            print(f"     Precision: {metrics['precision']:.3f}")
            print(f"     Recall: {metrics['recall']:.3f}")
            print(f"     F1-Score: {metrics['f1_score']:.3f}")
            print(f"     Support: {metrics['support']}")
        
        # Display threshold analysis
        print("\n3. Threshold Analysis:")
        for class_name, analysis in results['threshold_analysis'].items():
            print(f"   {class_name}:")
            print(f"     Recommended threshold: {analysis['recommended_threshold']:.3f}")
            print(f"     Best F1 score: {analysis['best_f1_score']:.3f}")
            print(f"     High precision threshold: {analysis['high_precision_threshold']:.3f}")
        
        print("\n✅ Evaluation metrics test passed!")
        return True
        
    except Exception as e:
        print(f"❌ Evaluation metrics test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all tests"""
    print("🚀 Starting Evidence Collection System Tests")
    print("=" * 60)
    
    success = True
    
    # Test evidence logging
    if not test_evidence_logging():
        success = False
    
    # Test evaluation metrics
    if not test_evaluation_metrics():
        success = False
    
    print("\n" + "=" * 60)
    if success:
        print("🎉 All tests passed! Evidence collection system is ready.")
        print("\nNext steps:")
        print("1. Run attacks with evidence capture enabled")
        print("2. Analyze CSV logs for per-class performance")
        print("3. Generate evaluation reports with threshold recommendations")
    else:
        print("❌ Some tests failed. Please check the errors above.")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())