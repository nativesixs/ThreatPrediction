#!/usr/bin/env python3
"""
Collect baseline normal traffic from your home network.
This will be added to training data to teach the model what REAL normal traffic looks like.
"""

import sys
import time
import json
from pathlib import Path
from datetime import datetime
import pandas as pd

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.services.live_feature_extractor import LiveFeatureExtractor
from scapy.all import sniff, IP, TCP, UDP

print("=" * 70)
print("Collecting Normal Traffic Baseline")
print("=" * 70)
print("\nThis will capture 10 minutes of your NORMAL network traffic")
print("to teach the model what legitimate traffic looks like.\n")
print("IMPORTANT: For the next 10 minutes:")
print("  ✓ Browse normally (GitHub, Microsoft, Google, etc.)")
print("  ✓ Check email, use Slack, watch videos")
print("  ✓ Do NOT run any attack simulations")
print("  ✓ Do NOT use suspicious tools (nmap, etc.)")
print("\n" + "=" * 70)

response = input("\nReady to start collecting? (yes/no): ")
if response.lower() != 'yes':
    print("Cancelled.")
    sys.exit(0)

# Initialize feature extractor
print("\n[1/3] Initializing feature extractor...")
extractor = LiveFeatureExtractor()
print("  ✓ Feature extractor ready")

# Packet storage
packets_captured = []
features_collected = []

def packet_callback(packet):
    """Process each captured packet."""
    global packets_captured, features_collected
    
    if IP in packet:
        # Extract packet info
        packet_dict = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': packet[IP].src if IP in packet else 'unknown',
            'destination_ip': packet[IP].dst if IP in packet else 'unknown',
            'source_port': packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else 0),
            'destination_port': packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else 0),
            'transport_protocol': 'TCP' if TCP in packet else ('UDP' if UDP in packet else 'OTHER'),
            'total_length': len(packet),
            'tcp_flags': str(packet[TCP].flags) if TCP in packet else '',
        }
        
        packets_captured.append(packet_dict)
        
        # Extract features every 32 packets
        if len(packets_captured) >= 32:
            try:
                batch_features = extractor.process_batch(packets_captured)
                if batch_features.size > 0:
                    features_collected.extend(batch_features.tolist())
                    print(f"\r  Captured: {len(features_collected)} feature vectors", end='', flush=True)
            except Exception as e:
                pass
            packets_captured = []

print("\n[2/3] Capturing traffic for 10 minutes...")
print("  (You can stop early with Ctrl+C)")

start_time = time.time()
duration = 600  # 10 minutes

try:
    sniff(
        filter="ip",
        prn=packet_callback,
        timeout=duration,
        store=False
    )
except KeyboardInterrupt:
    print("\n\n  Stopped by user")

elapsed = time.time() - start_time
print(f"\n  ✓ Captured {len(features_collected)} feature vectors in {elapsed/60:.1f} minutes")

if len(features_collected) < 100:
    print("\n  ✗ Not enough data collected (need at least 100 samples)")
    print("    Try running for longer or generating more traffic")
    sys.exit(1)

# Save baseline data
print("\n[3/3] Saving baseline data...")
output_dir = Path(__file__).parent.parent / "data" / "baseline"
output_dir.mkdir(exist_ok=True)

# Convert to DataFrame
feature_cols = [f"feature_{i}" for i in range(35)]
df = pd.DataFrame(features_collected, columns=feature_cols)
df['label'] = 'NORMAL'
df['source'] = 'home_network_baseline'
df['timestamp'] = datetime.now().isoformat()

output_file = output_dir / f"baseline_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
df.to_csv(output_file, index=False)

print(f"  ✓ Saved {len(df)} samples to {output_file}")

print("\n" + "=" * 70)
print("✓ BASELINE COLLECTION COMPLETE")
print("=" * 70)
print(f"\nCollected: {len(df)} normal traffic samples")
print(f"Next steps:")
print(f"  1. Review the data: less {output_file}")
print(f"  2. Run this 2-3 more times on different days")
print(f"  3. Once you have ~3,000-5,000 samples, run:")
print(f"     python scripts/retrain_with_baseline.py")
