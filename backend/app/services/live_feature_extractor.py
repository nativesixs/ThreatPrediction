"""
Real-time feature engineering for live network traffic.
Processes captured packets and prepares features for ML prediction.

NOTE: Scaler disabled - live features have different distribution than training data.
Using simple batch normalization instead to avoid false positives.
"""
import logging
from typing import Dict, Any, List, Optional
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from collections import defaultdict, deque

logger = logging.getLogger(__name__)

class LiveFeatureExtractor:
    """Extract and engineer features from live network traffic packets."""
    
    def __init__(self, scaler_path: Optional[str] = None):
        """Initialize live feature extractor with proper StandardScaler."""
        import pickle
        from pathlib import Path
        
        # Load the SAME scaler used during training (v10 uses modern datasets only)
        if scaler_path is None:
            scaler_path = Path(__file__).parent.parent.parent / "data" / "processed" / "unified_modern_scaler.pkl"
        
        try:
            with open(scaler_path, 'rb') as f:
                self.scaler = pickle.load(f)
            logger.info(f"✓ Loaded StandardScaler from {scaler_path}")
        except Exception as e:
            logger.warning(f"Failed to load scaler: {e} - using None")
            self.scaler = None
        
        self.flows = defaultdict(lambda: deque(maxlen=100))
        self.flow_stats = {}
        self.time_window = timedelta(seconds=60)
        self.packet_times = defaultdict(lambda: deque(maxlen=1000))
    
    def _get_flow_key(self, features):
        """Generate unique flow identifier."""
        src_ip = features.get('source_ip', 'unknown')
        dst_ip = features.get('destination_ip', 'unknown')
        src_port = features.get('source_port', 0)
        dst_port = features.get('destination_port', 0)
        protocol = features.get('transport_protocol', 'unknown')
        if src_ip < dst_ip:
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        else:
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
    
    def extract_basic_features(self, packet_data):
        """Extract basic packet-level features."""
        features = {}
        features['packet_length'] = float(packet_data.get('packet_length', 0))
        features['ip_length'] = float(packet_data.get('ip_length', 0))
        features['payload_length'] = float(packet_data.get('payload_length', 0))
        features['ttl'] = float(packet_data.get('ttl', 0))
        features['ip_flags'] = float(packet_data.get('ip_flags', 0))
        features['ip_frag'] = float(packet_data.get('ip_frag', 0))
        protocol = packet_data.get('protocol', 0)
        features['protocol'] = float(protocol)
        features['is_tcp'] = 1.0 if packet_data.get('transport_protocol') == 'TCP' else 0.0
        features['is_udp'] = 1.0 if packet_data.get('transport_protocol') == 'UDP' else 0.0
        features['is_icmp'] = 1.0 if packet_data.get('transport_protocol') == 'ICMP' else 0.0
        if packet_data.get('transport_protocol') == 'TCP':
            features['tcp_flags'] = float(packet_data.get('tcp_flags', 0))
            features['tcp_window'] = float(packet_data.get('tcp_window', 0))
            features['tcp_dataofs'] = float(packet_data.get('tcp_dataofs', 0))
            tcp_flags = packet_data.get('tcp_flags', 0)
            features['tcp_flag_syn'] = 1.0 if tcp_flags & 0x02 else 0.0
            features['tcp_flag_ack'] = 1.0 if tcp_flags & 0x10 else 0.0
            features['tcp_flag_fin'] = 1.0 if tcp_flags & 0x01 else 0.0
            features['tcp_flag_rst'] = 1.0 if tcp_flags & 0x04 else 0.0
            features['tcp_flag_psh'] = 1.0 if tcp_flags & 0x08 else 0.0
            features['tcp_flag_urg'] = 1.0 if tcp_flags & 0x20 else 0.0
        else:
            for flag in ['tcp_flags', 'tcp_window', 'tcp_dataofs', 'tcp_flag_syn', 'tcp_flag_ack', 'tcp_flag_fin', 'tcp_flag_rst', 'tcp_flag_psh', 'tcp_flag_urg']:
                features[flag] = 0.0
        src_port = packet_data.get('source_port', 0)
        dst_port = packet_data.get('destination_port', 0)
        features['source_port'] = float(src_port)
        features['destination_port'] = float(dst_port)
        features['is_well_known_port'] = 1.0 if (src_port < 1024 or dst_port < 1024) else 0.0
        features['has_payload'] = 1.0 if packet_data.get('has_payload', False) else 0.0
        return features
    
    def extract_flow_features(self, packet_data):
        """Extract flow-based features."""
        flow_key = self._get_flow_key(packet_data)
        timestamp = datetime.fromisoformat(packet_data['timestamp'])
        self.flows[flow_key].append({
            'timestamp': timestamp,
            'packet_length': packet_data.get('packet_length', 0),
            'payload_length': packet_data.get('payload_length', 0)
        })
        self.packet_times[flow_key].append(timestamp)
        flow_packets = list(self.flows[flow_key])
        features = {}
        if len(flow_packets) > 0:
            lengths = [p['packet_length'] for p in flow_packets]
            payload_lengths = [p['payload_length'] for p in flow_packets]
            features['flow_packet_count'] = float(len(flow_packets))
            features['flow_mean_packet_length'] = float(np.mean(lengths))
            features['flow_std_packet_length'] = float(np.std(lengths)) if len(lengths) > 1 else 0.0
            features['flow_min_packet_length'] = float(np.min(lengths))
            features['flow_max_packet_length'] = float(np.max(lengths))
            features['flow_mean_payload_length'] = float(np.mean(payload_lengths))
            features['flow_total_bytes'] = float(np.sum(lengths))
            if len(flow_packets) > 1:
                timestamps = [p['timestamp'] for p in flow_packets]
                intervals = [(timestamps[i+1] - timestamps[i]).total_seconds() for i in range(len(timestamps)-1)]
                features['flow_mean_iat'] = float(np.mean(intervals))
                features['flow_std_iat'] = float(np.std(intervals))
                features['flow_min_iat'] = float(np.min(intervals))
                features['flow_max_iat'] = float(np.max(intervals))
                duration = (timestamps[-1] - timestamps[0]).total_seconds()
                features['flow_duration'] = float(duration)
                if duration > 0:
                    features['flow_packets_per_sec'] = float(len(flow_packets) / duration)
                    features['flow_bytes_per_sec'] = float(np.sum(lengths) / duration)
                else:
                    features['flow_packets_per_sec'] = 0.0
                    features['flow_bytes_per_sec'] = 0.0
            else:
                for key in ['flow_mean_iat', 'flow_std_iat', 'flow_min_iat', 'flow_max_iat', 'flow_duration', 'flow_packets_per_sec', 'flow_bytes_per_sec']:
                    features[key] = 0.0
        else:
            for key in ['flow_packet_count', 'flow_mean_packet_length', 'flow_std_packet_length', 'flow_min_packet_length', 'flow_max_packet_length', 'flow_mean_payload_length', 'flow_total_bytes', 'flow_mean_iat', 'flow_std_iat', 'flow_min_iat', 'flow_max_iat', 'flow_duration', 'flow_packets_per_sec', 'flow_bytes_per_sec']:
                features[key] = 0.0
        return features
    
    def extract_rate_features(self, packet_data):
        """Extract rate-based features."""
        timestamp = datetime.fromisoformat(packet_data['timestamp'])
        src_ip = packet_data.get('source_ip', 'unknown')
        dst_ip = packet_data.get('destination_ip', 'unknown')
        features = {}
        cutoff_time = timestamp - self.time_window
        src_key = f"src:{src_ip}"
        self.packet_times[src_key].append(timestamp)
        recent_packets = [t for t in self.packet_times[src_key] if t > cutoff_time]
        features['src_ip_packet_rate'] = float(len(recent_packets))
        dst_key = f"dst:{dst_ip}"
        self.packet_times[dst_key].append(timestamp)
        recent_packets = [t for t in self.packet_times[dst_key] if t > cutoff_time]
        features['dst_ip_packet_rate'] = float(len(recent_packets))
        return features
    
    def process_packet(self, packet_data):
        """Process a packet and extract all features."""
        features = {}
        features.update(self.extract_basic_features(packet_data))
        features.update(self.extract_flow_features(packet_data))
        features.update(self.extract_rate_features(packet_data))
        return features
    
    def process_batch(self, packets):
        """Process batch of packets - returns normalized 35 features."""
        from app.services.feature_mapper import FeatureMapper
        feature_list = []
        for packet in packets:
            try:
                features = self.process_packet(packet)
                feature_list.append(features)
            except Exception as e:
                logger.error(f"Error processing packet: {e}")
                continue
        if not feature_list:
            return np.array([])
        df = pd.DataFrame(feature_list)
        df = df.fillna(0)
        live_feature_names = df.columns.tolist()
        X_live = df.values.astype(np.float32)
        logger.info(f"Extracted {X_live.shape[1]} live features, mapping to 35")
        mapper = FeatureMapper()
        X = mapper.map_batch(X_live, live_feature_names)
        logger.info(f"Mapped to shape: {X.shape}")
        
        # Apply SAME standardization as training data (StandardScaler)
        if self.scaler is not None:
            try:
                X_normalized = self.scaler.transform(X)
                logger.debug(f"Applied StandardScaler - feature range: [{X_normalized.min():.3f}, {X_normalized.max():.3f}]")
            except Exception as e:
                logger.error(f"Scaler transform failed: {e} - using raw features")
                X_normalized = X
        else:
            logger.warning("No scaler available - using raw features (will cause high FP rate!)")
            X_normalized = X
        
        return X_normalized
    
    def cleanup_old_flows(self, max_age_seconds=300):
        """Remove old flow data."""
        cutoff_time = datetime.now() - timedelta(seconds=max_age_seconds)
        flows_to_remove = []
        for flow_key, packets in self.flows.items():
            if packets and packets[-1]['timestamp'] < cutoff_time:
                flows_to_remove.append(flow_key)
        for flow_key in flows_to_remove:
            del self.flows[flow_key]
            if flow_key in self.packet_times:
                del self.packet_times[flow_key]
        if flows_to_remove:
            logger.debug(f"Cleaned up {len(flows_to_remove)} old flows")
