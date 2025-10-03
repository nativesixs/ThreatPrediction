"""
Packet capture service using Scapy for live network traffic monitoring.
Captures packets, extracts features, and sends to async queue for processing.
"""
import logging
from typing import Optional, Dict, Any, Callable
from datetime import datetime
import asyncio

from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP, Raw, conf
from scapy.packet import Packet

from app.core.config import settings


logger = logging.getLogger(__name__)

# Configure Scapy to avoid L2 socket issues
conf.sniff_promisc = False


class PacketCapturer:
    """Captures network packets and extracts features for ML prediction."""
    
    def __init__(
        self,
        interface: Optional[str] = None,
        packet_callback: Optional[Callable] = None
    ):
        """
        Initialize packet capturer.
        
        Args:
            interface: Network interface to capture from (None = all interfaces)
            packet_callback: Async callback function for each packet
        """
        self.interface = interface or settings.NETWORK_INTERFACE
        self.packet_callback = packet_callback
        
        self.is_running = False
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.sniffer: Optional[AsyncSniffer] = None
        
        # Statistics
        self.packets_captured = 0
        self.packets_sent = 0
        self.errors = 0
    
    def extract_packet_features(self, packet: Packet) -> Optional[Dict[str, Any]]:
        """
        Extract features from a packet for ML prediction.
        
        Args:
            packet: Scapy packet object
            
        Returns:
            Dictionary of extracted features or None if packet is invalid
        """
        try:
            # Basic features
            features = {
                'timestamp': datetime.now().isoformat(),
                'packet_length': len(packet),
            }
            
            # IP layer features
            if IP in packet:
                ip_layer = packet[IP]
                features.update({
                    'source_ip': ip_layer.src,
                    'destination_ip': ip_layer.dst,
                    'ip_version': ip_layer.version,
                    'ttl': ip_layer.ttl,
                    'ip_length': ip_layer.len,
                    'ip_flags': int(ip_layer.flags),
                    'ip_frag': ip_layer.frag,
                    'protocol': ip_layer.proto
                })
            else:
                # Skip non-IP packets for now
                return None
            
            # TCP layer features
            if TCP in packet:
                tcp_layer = packet[TCP]
                features.update({
                    'source_port': tcp_layer.sport,
                    'destination_port': tcp_layer.dport,
                    'tcp_flags': int(tcp_layer.flags),
                    'tcp_window': tcp_layer.window,
                    'tcp_seq': tcp_layer.seq,
                    'tcp_ack': tcp_layer.ack,
                    'tcp_dataofs': tcp_layer.dataofs,
                    'transport_protocol': 'TCP'
                })
            
            # UDP layer features
            elif UDP in packet:
                udp_layer = packet[UDP]
                features.update({
                    'source_port': udp_layer.sport,
                    'destination_port': udp_layer.dport,
                    'udp_length': udp_layer.len,
                    'transport_protocol': 'UDP'
                })
            
            # ICMP layer features
            elif ICMP in packet:
                icmp_layer = packet[ICMP]
                features.update({
                    'icmp_type': icmp_layer.type,
                    'icmp_code': icmp_layer.code,
                    'transport_protocol': 'ICMP'
                })
            
            # Payload features
            if Raw in packet:
                payload = packet[Raw].load
                features.update({
                    'payload_length': len(payload),
                    'has_payload': True
                })
            else:
                features.update({
                    'payload_length': 0,
                    'has_payload': False
                })
            
            # Additional derived features
            features['packet_type'] = self._classify_packet_type(packet)
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting packet features: {e}")
            self.errors += 1
            return None
    
    def _classify_packet_type(self, packet: Packet) -> str:
        """Classify packet type based on protocol and ports."""
        if TCP in packet:
            port = packet[TCP].dport
            if port == 80 or port == 8080:
                return 'HTTP'
            elif port == 443:
                return 'HTTPS'
            elif port == 22:
                return 'SSH'
            elif port == 21:
                return 'FTP'
            elif port == 25 or port == 587:
                return 'SMTP'
            elif port == 53:
                return 'DNS'
            else:
                return 'TCP_OTHER'
        elif UDP in packet:
            port = packet[UDP].dport
            if port == 53:
                return 'DNS'
            elif port == 67 or port == 68:
                return 'DHCP'
            else:
                return 'UDP_OTHER'
        elif ICMP in packet:
            return 'ICMP'
        else:
            return 'OTHER'
    
    def packet_handler(self, packet: Packet):
        """
        Handle captured packet.
        
        Args:
            packet: Scapy packet object
        """
        try:
            if not self.is_running:
                return
            
            self.packets_captured += 1
            
            # Extract features
            features = self.extract_packet_features(packet)
            if not features:
                return
            
            # Send to callback (non-blocking)
            if self.packet_callback and self.loop:
                try:
                    asyncio.run_coroutine_threadsafe(
                        self.packet_callback(features),
                        self.loop
                    )
                    self.packets_sent += 1
                except Exception as e:
                    logger.error(f"Error in packet callback: {e}")
                    self.errors += 1
        except Exception as e:
            logger.error(f"Error in packet_handler: {e}")
            self.errors += 1
    
    async def start_capture(self, packet_count: Optional[int] = None, filter_expr: Optional[str] = None):
        """
        Start capturing packets using AsyncSniffer with auto-restart on errors.
        
        Args:
            packet_count: Number of packets to capture (None = infinite)
            filter_expr: BPF filter expression (e.g., "tcp port 80")
        """
        if self.is_running:
            logger.warning("Capture already running")
            return
        
        logger.info(f"Starting packet capture on interface: {self.interface or 'all'}")
        if filter_expr:
            logger.info(f"Using filter: {filter_expr}")
        
        self.is_running = True
        
        # Get event loop for async callbacks
        self.loop = asyncio.get_event_loop()
        
        # Auto-restart loop to handle Scapy L2 socket failures
        restart_count = 0
        max_restarts = 100  # Allow many restarts for continuous capture
        
        while self.is_running and restart_count < max_restarts:
            try:
                # Use AsyncSniffer to avoid blocking
                self.sniffer = AsyncSniffer(
                    iface=None,  # Capture on all interfaces
                    prn=self.packet_handler,
                    filter=filter_expr,
                    store=False,  # Don't store packets in memory
                    count=1000  # Capture in batches of 1000 packets
                )
                
                # Start the sniffer
                self.sniffer.start()
                if restart_count == 0:
                    logger.info("Packet capture started successfully")
                else:
                    logger.debug(f"Packet capture restarted (attempt {restart_count + 1})")
                
                # Wait for this batch to complete
                await asyncio.sleep(10)  # Check every 10 seconds
                
                # Stop and restart
                if self.sniffer:
                    try:
                        self.sniffer.stop()
                    except:
                        pass
                
                restart_count += 1
                    
            except PermissionError as e:
                logger.error(f"Permission denied for packet capture: {e}")
                logger.error("Run with: sudo -E poetry run backend-dev")
                raise
            except Exception as e:
                if restart_count == 0:
                    logger.error(f"Error during packet capture: {e}")
                else:
                    logger.debug(f"Capture error (attempt {restart_count + 1}): {e}")
                
                # Wait a bit before restarting
                await asyncio.sleep(1)
                restart_count += 1
                
        if restart_count >= max_restarts:
            logger.warning(f"Packet capture stopped after {max_restarts} restart attempts")
            
        self.stop_capture()
    
    def stop_capture(self):
        """Stop packet capture and cleanup."""
        if not self.is_running:
            return
        
        logger.info("Stopping packet capture")
        self.is_running = False
        
        # Log statistics
        logger.info(f"Capture statistics:")
        logger.info(f"  Packets captured: {self.packets_captured}")
        logger.info(f"  Packets sent: {self.packets_sent}")
        logger.info(f"  Errors: {self.errors}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get capture statistics."""
        return {
            'packets_captured': self.packets_captured,
            'packets_sent': self.packets_sent,
            'errors': self.errors,
            'is_running': self.is_running
        }
