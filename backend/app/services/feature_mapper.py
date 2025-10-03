"""
Feature mapper to convert live packet features to model-expected features.
Bridges the gap between packet capture features and training dataset features.
"""
import logging
import numpy as np
from typing import Dict, Any


logger = logging.getLogger(__name__)


class FeatureMapper:
    """Maps live packet features to the 35 features expected by the v7 model."""
    
    # Expected 35 features from training (unified dataset)
    EXPECTED_FEATURES = [
        "duration",
        "protocol",
        "total_fwd_packets",
        "total_bwd_packets",
        "total_packets",
        "total_fwd_bytes",
        "total_bwd_bytes",
        "fwd_bytes_max",
        "fwd_bytes_min",
        "fwd_bytes_mean",
        "fwd_bytes_std",
        "bwd_bytes_max",
        "bwd_bytes_min",
        "bwd_bytes_mean",
        "bwd_bytes_std",
        "flow_packets_per_sec",
        "flow_bytes_per_sec",
        "fwd_packets_per_sec",
        "bwd_packets_per_sec",
        "fwd_iat_mean",
        "fwd_iat_std",
        "bwd_iat_mean",
        "bwd_iat_std",
        "syn_flag_count",
        "ack_flag_count",
        "fin_flag_count",
        "rst_flag_count",
        "psh_flag_count",
        "urg_flag_count",
        "active_mean",
        "active_std",
        "idle_mean",
        "idle_std",
        "down_up_ratio",
        "fwd_header_length"
    ]
    
    def __init__(self):
        """Initialize feature mapper."""
        self.num_features = len(self.EXPECTED_FEATURES)
        logger.info(f"Initialized FeatureMapper with {self.num_features} expected features")
    
    def map_features(self, live_features: Dict[str, float]) -> Dict[str, float]:
        """
        Map live packet features to model-expected features.
        
        Args:
            live_features: Features extracted from live packet capture
            
        Returns:
            Dictionary with 35 expected features
        """
        mapped = {}
        
        # 1. duration - use flow_duration
        mapped["duration"] = live_features.get("flow_duration", 0.0)
        
        # 2. protocol - from protocol field
        mapped["protocol"] = live_features.get("protocol", 0.0)
        
        # 3-5. packet counts
        # Approximate forward/backward from flow stats
        total_packets = live_features.get("flow_packet_count", 1.0)
        mapped["total_packets"] = total_packets
        # Assume roughly 60/40 forward/backward split (typical)
        mapped["total_fwd_packets"] = total_packets * 0.6
        mapped["total_bwd_packets"] = total_packets * 0.4
        
        # 6-7. byte counts
        total_bytes = live_features.get("flow_total_bytes", 0.0)
        mapped["total_fwd_bytes"] = total_bytes * 0.6
        mapped["total_bwd_bytes"] = total_bytes * 0.4
        
        # 8-11. forward bytes statistics
        mean_length = live_features.get("flow_mean_packet_length", 0.0)
        std_length = live_features.get("flow_std_packet_length", 0.0)
        min_length = live_features.get("flow_min_packet_length", 0.0)
        max_length = live_features.get("flow_max_packet_length", 0.0)
        
        mapped["fwd_bytes_mean"] = mean_length
        mapped["fwd_bytes_std"] = std_length
        mapped["fwd_bytes_min"] = min_length
        mapped["fwd_bytes_max"] = max_length
        
        # 12-15. backward bytes statistics (approximate as similar to forward)
        mapped["bwd_bytes_mean"] = mean_length * 0.8  # Typically slightly smaller
        mapped["bwd_bytes_std"] = std_length * 0.8
        mapped["bwd_bytes_min"] = min_length * 0.8
        mapped["bwd_bytes_max"] = max_length * 0.8
        
        # 16-17. flow rates
        mapped["flow_packets_per_sec"] = live_features.get("flow_packets_per_sec", 0.0)
        mapped["flow_bytes_per_sec"] = live_features.get("flow_bytes_per_sec", 0.0)
        
        # 18-19. forward/backward packet rates (split total)
        total_pps = mapped["flow_packets_per_sec"]
        mapped["fwd_packets_per_sec"] = total_pps * 0.6
        mapped["bwd_packets_per_sec"] = total_pps * 0.4
        
        # 20-23. inter-arrival times
        mean_iat = live_features.get("flow_mean_iat", 0.0)
        std_iat = live_features.get("flow_std_iat", 0.0)
        
        mapped["fwd_iat_mean"] = mean_iat
        mapped["fwd_iat_std"] = std_iat
        mapped["bwd_iat_mean"] = mean_iat * 1.1  # Backward typically slightly higher
        mapped["bwd_iat_std"] = std_iat * 1.1
        
        # 24-29. TCP flag counts
        # Convert flag bits to counts (from current packet)
        packet_count = max(1.0, live_features.get("flow_packet_count", 1.0))
        
        mapped["syn_flag_count"] = live_features.get("tcp_flag_syn", 0.0) * packet_count
        mapped["ack_flag_count"] = live_features.get("tcp_flag_ack", 0.0) * packet_count
        mapped["fin_flag_count"] = live_features.get("tcp_flag_fin", 0.0) * packet_count
        mapped["rst_flag_count"] = live_features.get("tcp_flag_rst", 0.0) * packet_count
        mapped["psh_flag_count"] = live_features.get("tcp_flag_psh", 0.0) * packet_count
        mapped["urg_flag_count"] = live_features.get("tcp_flag_urg", 0.0) * packet_count
        
        # 30-33. active/idle time statistics
        # Approximate from IAT statistics
        if mean_iat > 0:
            mapped["active_mean"] = 1.0 / mean_iat  # Higher frequency = more active
            mapped["active_std"] = std_iat
        else:
            mapped["active_mean"] = 0.0
            mapped["active_std"] = 0.0
        
        # Idle times (inverse relationship)
        mapped["idle_mean"] = mean_iat * 1000  # Convert to milliseconds
        mapped["idle_std"] = std_iat * 1000
        
        # 34. down/up ratio (backward/forward bytes)
        fwd_bytes = mapped["total_fwd_bytes"]
        bwd_bytes = mapped["total_bwd_bytes"]
        if fwd_bytes > 0:
            mapped["down_up_ratio"] = bwd_bytes / fwd_bytes
        else:
            mapped["down_up_ratio"] = 0.0
        
        # 35. forward header length
        # Estimate based on protocol and packet size
        if live_features.get("is_tcp", 0.0) > 0:
            mapped["fwd_header_length"] = 40.0  # TCP/IP header
        elif live_features.get("is_udp", 0.0) > 0:
            mapped["fwd_header_length"] = 28.0  # UDP/IP header
        else:
            mapped["fwd_header_length"] = 20.0  # IP header only
        
        # Verify we have all 35 features
        if len(mapped) != self.num_features:
            logger.warning(f"Feature count mismatch: got {len(mapped)}, expected {self.num_features}")
            # Fill missing with zeros
            for feature in self.EXPECTED_FEATURES:
                if feature not in mapped:
                    mapped[feature] = 0.0
        
        return mapped
    
    def map_batch(self, live_features_batch: np.ndarray, live_feature_names: list) -> np.ndarray:
        """
        Map a batch of live features to model-expected features.
        
        Args:
            live_features_batch: Array of shape (n_samples, n_live_features)
            live_feature_names: List of feature names corresponding to columns
            
        Returns:
            Array of shape (n_samples, 35) with expected features
        """
        n_samples = live_features_batch.shape[0]
        mapped_batch = np.zeros((n_samples, self.num_features), dtype=np.float32)
        
        for i in range(n_samples):
            # Convert row to dictionary
            live_dict = {
                name: float(live_features_batch[i, j])
                for j, name in enumerate(live_feature_names)
            }
            
            # Map to expected features
            mapped_dict = self.map_features(live_dict)
            
            # Convert back to array in correct order
            for j, feature_name in enumerate(self.EXPECTED_FEATURES):
                mapped_batch[i, j] = mapped_dict.get(feature_name, 0.0)
        
        return mapped_batch
