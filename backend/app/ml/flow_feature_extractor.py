"""
Feature extraction for network flows.
Converts raw Zeek flow records into numerical feature vectors for ML.
"""
import numpy as np
from typing import Dict, List
import logging

logger = logging.getLogger(__name__)


class FlowFeatureExtractor:
    """
    Extracts and engineers features from network flow records.
    
    Features include:
    - Duration
    - Byte counts (orig, resp, total)
    - Packet counts (orig, resp, total)
    - Throughput metrics (bytes/sec, packets/sec)
    - Ratios (orig/resp bytes, packets)
    - Protocol encoding
    - Service encoding
    - Connection state encoding
    """
    
    # Common protocols
    PROTOCOLS = ['tcp', 'udp', 'icmp', 'arp', 'ipv6', 'other']
    
    # Common services
    SERVICES = [
        'http', 'https', 'ssl', 'dns', 'ssh', 'ftp', 'smtp', 'pop3',
        'imap', 'ntp', 'dhcp', 'smb', 'rdp', 'other', 'unknown'
    ]
    
    # Connection states
    CONN_STATES = [
        'S0', 'S1', 'SF', 'REJ', 'S2', 'S3', 'RSTO', 'RSTR', 
        'RSTOS0', 'RSTRH', 'SH', 'SHR', 'OTH'
    ]
    
    def __init__(self):
        """Initialize feature extractor."""
        self.feature_names = self._build_feature_names()
        self.num_features = len(self.feature_names)
        logger.info(f"Feature extractor initialized with {self.num_features} features")
    
    def _build_feature_names(self) -> List[str]:
        """Build list of all feature names."""
        names = [
            # Basic flow metrics
            'duration',
            'orig_bytes',
            'resp_bytes',
            'total_bytes',
            'orig_pkts',
            'resp_pkts',
            'total_pkts',
            
            # Derived metrics
            'bytes_per_second',
            'pkts_per_second',
            'orig_bytes_per_pkt',
            'resp_bytes_per_pkt',
            'avg_bytes_per_pkt',
            
            # Ratios
            'orig_resp_byte_ratio',
            'orig_resp_pkt_ratio',
        ]
        
        # Protocol one-hot encoding
        for proto in self.PROTOCOLS:
            names.append(f'proto_{proto}')
        
        # Service encoding (use 1 feature with numeric mapping)
        names.append('service_code')
        
        # Connection state encoding
        names.append('conn_state_code')
        
        return names
    
    def extract_features(self, flow: Dict) -> np.ndarray:
        """
        Extract feature vector from a single flow record.
        
        Args:
            flow: Parsed flow dictionary from Zeek
        
        Returns:
            Numpy array of features
        """
        features = []
        
        # Basic flow metrics
        duration = flow.get('duration') or 0.0
        orig_bytes = flow.get('orig_bytes') or 0
        resp_bytes = flow.get('resp_bytes') or 0
        orig_pkts = flow.get('orig_pkts') or 0
        resp_pkts = flow.get('resp_pkts') or 0
        
        total_bytes = orig_bytes + resp_bytes
        total_pkts = orig_pkts + resp_pkts
        
        features.extend([
            duration,
            orig_bytes,
            resp_bytes,
            total_bytes,
            orig_pkts,
            resp_pkts,
            total_pkts
        ])
        
        # Derived metrics (with safe division)
        bytes_per_sec = total_bytes / duration if duration > 0 else 0
        pkts_per_sec = total_pkts / duration if duration > 0 else 0
        orig_bytes_per_pkt = orig_bytes / orig_pkts if orig_pkts > 0 else 0
        resp_bytes_per_pkt = resp_bytes / resp_pkts if resp_pkts > 0 else 0
        avg_bytes_per_pkt = total_bytes / total_pkts if total_pkts > 0 else 0
        
        features.extend([
            bytes_per_sec,
            pkts_per_sec,
            orig_bytes_per_pkt,
            resp_bytes_per_pkt,
            avg_bytes_per_pkt
        ])
        
        # Ratios (with safe division)
        orig_resp_byte_ratio = orig_bytes / resp_bytes if resp_bytes > 0 else 0
        orig_resp_pkt_ratio = orig_pkts / resp_pkts if resp_pkts > 0 else 0
        
        features.extend([
            orig_resp_byte_ratio,
            orig_resp_pkt_ratio
        ])
        
        # Protocol one-hot encoding
        protocol = (flow.get('protocol') or 'other').lower()
        for proto in self.PROTOCOLS:
            features.append(1.0 if protocol == proto else 0.0)
        
        # Service encoding (numeric)
        service = (flow.get('service') or 'unknown').lower()
        service_code = self.SERVICES.index(service) if service in self.SERVICES else len(self.SERVICES) - 1
        features.append(float(service_code))
        
        # Connection state encoding (numeric)
        conn_state = flow.get('conn_state') or 'OTH'
        conn_state_code = self.CONN_STATES.index(conn_state) if conn_state in self.CONN_STATES else len(self.CONN_STATES) - 1
        features.append(float(conn_state_code))
        
        return np.array(features, dtype=np.float32)
    
    def extract_batch(self, flows: List[Dict]) -> np.ndarray:
        """
        Extract features from multiple flows.
        
        Args:
            flows: List of parsed flow dictionaries
        
        Returns:
            2D numpy array of shape (num_flows, num_features)
        """
        feature_vectors = []
        for flow in flows:
            try:
                features = self.extract_features(flow)
                feature_vectors.append(features)
            except Exception as e:
                logger.warning(f"Failed to extract features from flow: {e}")
                # Use zero vector as fallback
                feature_vectors.append(np.zeros(self.num_features, dtype=np.float32))
        
        return np.array(feature_vectors, dtype=np.float32)
    
    def get_feature_names(self) -> List[str]:
        """Get list of feature names."""
        return self.feature_names.copy()
    
    def get_num_features(self) -> int:
        """Get number of features."""
        return self.num_features
