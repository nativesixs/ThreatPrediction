"""
Flow aggregator for network traffic.
Aggregates packets into bidirectional flows based on 5-tuple.
"""
import logging
from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
import numpy as np

logger = logging.getLogger(__name__)


class Flow:
    """Represents a bidirectional network flow."""
    
    def __init__(self, flow_key: str):
        """Initialize flow."""
        self.flow_key = flow_key
        self.start_time: Optional[datetime] = None
        self.last_seen: Optional[datetime] = None
        
        # Forward direction (initiator -> responder)
        self.fwd_packets = []
        self.fwd_bytes = 0
        self.fwd_flags = []
        
        # Backward direction (responder -> initiator)
        self.bwd_packets = []
        self.bwd_bytes = 0
        self.bwd_flags = []
        
        # Flow metadata
        self.protocol = None
        self.src_ip = None
        self.dst_ip = None
        self.src_port = None
        self.dst_port = None
    
    def add_packet(self, packet_data: Dict[str, Any], direction: str):
        """Add packet to flow."""
        timestamp = datetime.fromisoformat(packet_data['timestamp'])
        
        if self.start_time is None:
            self.start_time = timestamp
            self.protocol = packet_data.get('transport_protocol', 'unknown')
            self.src_ip = packet_data.get('source_ip')
            self.dst_ip = packet_data.get('destination_ip')
            self.src_port = packet_data.get('source_port', 0)
            self.dst_port = packet_data.get('destination_port', 0)
        
        self.last_seen = timestamp
        
        packet_info = {
            'timestamp': timestamp,
            'length': packet_data.get('packet_length', 0),
            'payload': packet_data.get('payload_length', 0),
            'flags': packet_data.get('tcp_flags', 0)
        }
        
        if direction == 'forward':
            self.fwd_packets.append(packet_info)
            self.fwd_bytes += packet_info['length']
            if packet_info['flags']:
                self.fwd_flags.append(packet_info['flags'])
        else:
            self.bwd_packets.append(packet_info)
            self.bwd_bytes += packet_info['length']
            if packet_info['flags']:
                self.bwd_flags.append(packet_info['flags'])
    
    def get_duration(self) -> float:
        """Get flow duration in seconds."""
        if self.start_time and self.last_seen:
            return (self.last_seen - self.start_time).total_seconds()
        return 0.0
    
    def get_packet_count(self) -> int:
        """Get total packet count."""
        return len(self.fwd_packets) + len(self.bwd_packets)
    
    def get_byte_count(self) -> int:
        """Get total byte count."""
        return self.fwd_bytes + self.bwd_bytes
    
    def get_features(self) -> Dict[str, float]:
        """
        Extract flow-level features (35 features matching training data).
        These are statistical aggregations over the flow lifetime.
        """
        features = {}
        
        # Basic flow stats
        duration = self.get_duration()
        total_fwd_packets = len(self.fwd_packets)
        total_bwd_packets = len(self.bwd_packets)
        total_packets = total_fwd_packets + total_bwd_packets
        total_fwd_bytes = self.fwd_bytes
        total_bwd_bytes = self.bwd_bytes
        
        # EXACT ORDER FROM TRAINING DATA (unified_train.csv)
        features['duration'] = duration
        features['protocol'] = {'TCP': 6, 'UDP': 17, 'ICMP': 1}.get(self.protocol, 0)
        features['total_fwd_packets'] = total_fwd_packets
        features['total_bwd_packets'] = total_bwd_packets
        features['total_packets'] = total_packets
        features['total_fwd_bytes'] = total_fwd_bytes
        features['total_bwd_bytes'] = total_bwd_bytes
        
        # Packet/Byte length statistics - Forward
        if self.fwd_packets:
            fwd_lengths = [p['length'] for p in self.fwd_packets]
            features['fwd_bytes_max'] = max(fwd_lengths)
            features['fwd_bytes_min'] = min(fwd_lengths)
            features['fwd_bytes_mean'] = np.mean(fwd_lengths)
            features['fwd_bytes_std'] = np.std(fwd_lengths)
        else:
            features['fwd_bytes_max'] = 0
            features['fwd_bytes_min'] = 0
            features['fwd_bytes_mean'] = 0
            features['fwd_bytes_std'] = 0
        
        # Packet/Byte length statistics - Backward
        if self.bwd_packets:
            bwd_lengths = [p['length'] for p in self.bwd_packets]
            features['bwd_bytes_max'] = max(bwd_lengths)
            features['bwd_bytes_min'] = min(bwd_lengths)
            features['bwd_bytes_mean'] = np.mean(bwd_lengths)
            features['bwd_bytes_std'] = np.std(bwd_lengths)
        else:
            features['bwd_bytes_max'] = 0
            features['bwd_bytes_min'] = 0
            features['bwd_bytes_mean'] = 0
            features['bwd_bytes_std'] = 0
        
        # Flow/Forward/Backward packets per second
        if duration > 0:
            features['flow_packets_per_sec'] = total_packets / duration
            features['flow_bytes_per_sec'] = (total_fwd_bytes + total_bwd_bytes) / duration
            features['fwd_packets_per_sec'] = total_fwd_packets / duration
            features['bwd_packets_per_sec'] = total_bwd_packets / duration
        else:
            features['flow_packets_per_sec'] = 0
            features['flow_bytes_per_sec'] = 0
            features['fwd_packets_per_sec'] = 0
            features['bwd_packets_per_sec'] = 0
        
        # Inter-arrival time statistics
        if len(self.fwd_packets) > 1:
            fwd_iats = [(self.fwd_packets[i+1]['timestamp'] - self.fwd_packets[i]['timestamp']).total_seconds() 
                        for i in range(len(self.fwd_packets)-1)]
            features['fwd_iat_mean'] = np.mean(fwd_iats)
            features['fwd_iat_std'] = np.std(fwd_iats)
        else:
            features['fwd_iat_mean'] = 0
            features['fwd_iat_std'] = 0
        
        if len(self.bwd_packets) > 1:
            bwd_iats = [(self.bwd_packets[i+1]['timestamp'] - self.bwd_packets[i]['timestamp']).total_seconds() 
                        for i in range(len(self.bwd_packets)-1)]
            features['bwd_iat_mean'] = np.mean(bwd_iats)
            features['bwd_iat_std'] = np.std(bwd_iats)
        else:
            features['bwd_iat_mean'] = 0
            features['bwd_iat_std'] = 0
        
        # TCP flag counts (combined, not per-direction)
        if self.protocol == 'TCP':
            all_flags = self.fwd_flags + self.bwd_flags
            features['syn_flag_count'] = sum(1 for f in all_flags if f & 0x02)
            features['ack_flag_count'] = sum(1 for f in all_flags if f & 0x10)
            features['fin_flag_count'] = sum(1 for f in all_flags if f & 0x01)
            features['rst_flag_count'] = sum(1 for f in all_flags if f & 0x04)
            features['psh_flag_count'] = sum(1 for f in all_flags if f & 0x08)
            features['urg_flag_count'] = sum(1 for f in all_flags if f & 0x20)
        else:
            features['syn_flag_count'] = 0
            features['ack_flag_count'] = 0
            features['fin_flag_count'] = 0
            features['rst_flag_count'] = 0
            features['psh_flag_count'] = 0
            features['urg_flag_count'] = 0
        
        # Active/Idle time statistics (simplified - no active/idle tracking in current implementation)
        # These would require deeper state tracking; for now use placeholders
        features['active_mean'] = duration / 2 if duration > 0 else 0  # Simplified
        features['active_std'] = 0
        features['idle_mean'] = 0
        features['idle_std'] = 0
        
        # Down/Up ratio (bwd/fwd bytes ratio)
        if total_fwd_bytes > 0:
            features['down_up_ratio'] = total_bwd_bytes / total_fwd_bytes
        else:
            features['down_up_ratio'] = 0
        
        # Forward header length (TCP/IP header = 40 bytes typically, * packet count)
        features['fwd_header_length'] = total_fwd_packets * 40
        
        return features


class FlowAggregator:
    """Aggregates packets into flows for ML analysis."""
    
    def __init__(
        self,
        flow_timeout: float = 120.0,  # 2 minutes
        cleanup_interval: float = 300.0  # 5 minutes
    ):
        """
        Initialize flow aggregator.
        
        Args:
            flow_timeout: Time in seconds before flow is considered complete
            cleanup_interval: Time in seconds between cleanup operations
        """
        self.flow_timeout = timedelta(seconds=flow_timeout)
        self.cleanup_interval = timedelta(seconds=cleanup_interval)
        
        # Active flows indexed by flow key
        self.flows: Dict[str, Flow] = {}
        
        # Last cleanup time
        self.last_cleanup = datetime.now()
        
        # Statistics
        self.total_packets = 0
        self.total_flows = 0
        self.completed_flows = 0
    
    def _get_flow_key(self, packet_data: Dict[str, Any]) -> Tuple[str, str]:
        """
        Generate bidirectional flow key and direction.
        
        Returns:
            Tuple of (flow_key, direction) where direction is 'forward' or 'backward'
        """
        src_ip = packet_data.get('source_ip', 'unknown')
        dst_ip = packet_data.get('destination_ip', 'unknown')
        src_port = packet_data.get('source_port', 0)
        dst_port = packet_data.get('destination_port', 0)
        protocol = packet_data.get('transport_protocol', 'unknown')
        
        # Create bidirectional key (lexicographic order for consistency)
        if (src_ip, src_port) < (dst_ip, dst_port):
            flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
            direction = 'forward'
        else:
            flow_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
            direction = 'backward'
        
        return flow_key, direction
    
    def add_packet(self, packet_data: Dict[str, Any]) -> Optional[Flow]:
        """
        Add packet to appropriate flow.
        
        Args:
            packet_data: Packet dictionary with timestamp, IPs, ports, etc.
            
        Returns:
            Flow object if flow is complete/timed out, None otherwise
        """
        self.total_packets += 1
        
        # Get flow key and direction
        flow_key, direction = self._get_flow_key(packet_data)
        
        # Get or create flow
        if flow_key not in self.flows:
            self.flows[flow_key] = Flow(flow_key)
            self.total_flows += 1
        
        flow = self.flows[flow_key]
        flow.add_packet(packet_data, direction)
        
        # Check if flow should be completed (timeout or TCP FIN/RST)
        should_complete = False
        
        # Check timeout
        timestamp = datetime.fromisoformat(packet_data['timestamp'])
        if flow.last_seen and (timestamp - flow.last_seen) > self.flow_timeout:
            should_complete = True
        
        # Check TCP connection termination
        if packet_data.get('transport_protocol') == 'TCP':
            tcp_flags = packet_data.get('tcp_flags', 0)
            if tcp_flags & 0x01 or tcp_flags & 0x04:  # FIN or RST
                should_complete = True
        
        # Periodic cleanup
        if (datetime.now() - self.last_cleanup) > self.cleanup_interval:
            self._cleanup_old_flows()
        
        # Return completed flow
        if should_complete:
            completed_flow = self.flows.pop(flow_key)
            self.completed_flows += 1
            return completed_flow
        
        return None
    
    def _cleanup_old_flows(self):
        """Remove flows that have timed out."""
        current_time = datetime.now()
        flows_to_remove = []
        
        for flow_key, flow in self.flows.items():
            if flow.last_seen and (current_time - flow.last_seen) > self.flow_timeout:
                flows_to_remove.append(flow_key)
        
        for flow_key in flows_to_remove:
            del self.flows[flow_key]
        
        if flows_to_remove:
            logger.info(f"Cleaned up {len(flows_to_remove)} timed-out flows")
        
        self.last_cleanup = current_time
    
    def get_completed_flows(self) -> list:
        """
        Get all flows that should be completed (based on timeout).
        
        Returns:
            List of Flow objects
        """
        current_time = datetime.now()
        completed = []
        flows_to_remove = []
        
        for flow_key, flow in self.flows.items():
            if flow.last_seen and (current_time - flow.last_seen) > self.flow_timeout:
                completed.append(flow)
                flows_to_remove.append(flow_key)
        
        # Remove completed flows
        for flow_key in flows_to_remove:
            del self.flows[flow_key]
            self.completed_flows += 1
        
        return completed
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get aggregator statistics."""
        return {
            'total_packets': self.total_packets,
            'total_flows': self.total_flows,
            'completed_flows': self.completed_flows,
            'active_flows': len(self.flows)
        }
