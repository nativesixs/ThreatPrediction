"""
Ground Truth Capture Tool for attack validation.
Captures network traffic during attacks to validate detection.
"""

import subprocess
import time
import signal
import os
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
import threading
import psutil
from contextlib import contextmanager

logger = logging.getLogger(__name__)

class GroundTruthCapture:
    """Captures network traffic and system metrics during attacks"""
    
    def __init__(self, capture_dir: str = "logs/evidence/captures"):
        self.capture_dir = Path(capture_dir)
        self.capture_dir.mkdir(parents=True, exist_ok=True)
        self.tcpdump_process = None
        self.netstat_log = None
        self.capture_active = False
        
    @contextmanager
    def capture_attack(self, attack_name: str, interface: str = "any", 
                      capture_filter: str = "", duration: int = 60):
        """
        Context manager for capturing traffic during an attack
        
        Args:
            attack_name: Name/type of attack for file naming
            interface: Network interface to capture (default: any)
            capture_filter: TCPDump filter expression
            duration: Maximum capture duration in seconds
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        capture_file = self.capture_dir / f"{attack_name}_{timestamp}.pcap"
        netstat_file = self.capture_dir / f"{attack_name}_{timestamp}_netstat.log"
        
        logger.info(f"Starting ground truth capture for {attack_name}")
        logger.info(f"PCAP file: {capture_file}")
        logger.info(f"Netstat log: {netstat_file}")
        
        try:
            # Start packet capture
            self._start_tcpdump(capture_file, interface, capture_filter)
            
            # Start network statistics logging
            self._start_netstat_logging(netstat_file)
            
            # Log system state before attack
            self._log_system_state(netstat_file, "BEFORE_ATTACK")
            
            yield {
                'pcap_file': str(capture_file),
                'netstat_file': str(netstat_file),
                'start_time': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error during capture: {e}")
            raise
        finally:
            # Log system state after attack
            self._log_system_state(netstat_file, "AFTER_ATTACK")
            
            # Stop captures
            self._stop_tcpdump()
            self._stop_netstat_logging()
            
            logger.info(f"Ground truth capture completed for {attack_name}")
    
    def _start_tcpdump(self, output_file: Path, interface: str, filter_expr: str):
        """Start TCPDump packet capture"""
        try:
            cmd = [
                "sudo", "tcpdump",
                "-i", interface,
                "-w", str(output_file),
                "-s", "65535",  # Capture full packets
                "-U",  # Immediate write to file
            ]
            
            if filter_expr:
                cmd.append(filter_expr)
            
            logger.info(f"Starting tcpdump: {' '.join(cmd)}")
            self.tcpdump_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid  # Create new process group
            )
            
            # Give tcpdump a moment to start
            time.sleep(1)
            
            if self.tcpdump_process.poll() is not None:
                stdout, stderr = self.tcpdump_process.communicate()
                raise Exception(f"TCPDump failed to start: {stderr.decode()}")
            
            self.capture_active = True
            logger.info("TCPDump started successfully")
            
        except Exception as e:
            logger.error(f"Failed to start tcpdump: {e}")
            raise
    
    def _stop_tcpdump(self):
        """Stop TCPDump packet capture"""
        if self.tcpdump_process and self.capture_active:
            try:
                # Send SIGTERM to the process group
                os.killpg(os.getpgid(self.tcpdump_process.pid), signal.SIGTERM)
                
                # Wait for process to terminate
                try:
                    self.tcpdump_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    # Force kill if it doesn't terminate gracefully
                    os.killpg(os.getpgid(self.tcpdump_process.pid), signal.SIGKILL)
                    self.tcpdump_process.wait()
                
                logger.info("TCPDump stopped")
                
            except Exception as e:
                logger.error(f"Error stopping tcpdump: {e}")
            finally:
                self.tcpdump_process = None
                self.capture_active = False
    
    def _start_netstat_logging(self, log_file: Path):
        """Start continuous network statistics logging"""
        self.netstat_log = open(log_file, 'w')
        self.netstat_log.write(f"# Network statistics log started at {datetime.now().isoformat()}\n")
        self.netstat_log.flush()
        
        # Start background thread for periodic netstat
        self.netstat_thread = threading.Thread(
            target=self._netstat_logger_thread,
            args=(self.netstat_log,),
            daemon=True
        )
        self.netstat_thread.start()
        logger.info("Netstat logging started")
    
    def _stop_netstat_logging(self):
        """Stop network statistics logging"""
        if self.netstat_log:
            self.netstat_log.write(f"# Network statistics log ended at {datetime.now().isoformat()}\n")
            self.netstat_log.close()
            self.netstat_log = None
            logger.info("Netstat logging stopped")
    
    def _netstat_logger_thread(self, log_file):
        """Background thread for logging network statistics"""
        while self.capture_active:
            try:
                timestamp = datetime.now().isoformat()
                
                # Log active connections
                log_file.write(f"\n# Active connections at {timestamp}\n")
                result = subprocess.run(
                    ["netstat", "-tuln"], 
                    capture_output=True, 
                    text=True, 
                    timeout=5
                )
                if result.returncode == 0:
                    log_file.write(result.stdout)
                
                # Log connection counts by state
                log_file.write(f"\n# Connection states at {timestamp}\n")
                result = subprocess.run(
                    ["netstat", "-s"], 
                    capture_output=True, 
                    text=True, 
                    timeout=5
                )
                if result.returncode == 0:
                    log_file.write(result.stdout)
                
                log_file.flush()
                time.sleep(5)  # Log every 5 seconds
                
            except Exception as e:
                logger.error(f"Error in netstat logging: {e}")
                time.sleep(5)
    
    def _log_system_state(self, log_file, phase: str):
        """Log current system state"""
        try:
            timestamp = datetime.now().isoformat()
            log_file.write(f"\n# SYSTEM STATE {phase} at {timestamp}\n")
            
            # Network interface statistics
            log_file.write("# Network Interface Statistics\n")
            net_io = psutil.net_io_counters(pernic=True)
            for interface, stats in net_io.items():
                log_file.write(f"{interface}: bytes_sent={stats.bytes_sent}, "
                             f"bytes_recv={stats.bytes_recv}, "
                             f"packets_sent={stats.packets_sent}, "
                             f"packets_recv={stats.packets_recv}, "
                             f"errin={stats.errin}, errout={stats.errout}, "
                             f"dropin={stats.dropin}, dropout={stats.dropout}\n")
            
            # System load
            log_file.write("# System Load\n")
            load_avg = os.getloadavg()
            log_file.write(f"Load average: {load_avg[0]:.2f}, {load_avg[1]:.2f}, {load_avg[2]:.2f}\n")
            
            # Memory usage
            log_file.write("# Memory Usage\n")
            memory = psutil.virtual_memory()
            log_file.write(f"Memory: total={memory.total}, "
                         f"available={memory.available}, "
                         f"percent={memory.percent:.1f}%\n")
            
            # CPU usage
            log_file.write("# CPU Usage\n")
            cpu_percent = psutil.cpu_percent(interval=1, percpu=True)
            log_file.write(f"CPU usage per core: {cpu_percent}\n")
            
            log_file.flush()
            
        except Exception as e:
            logger.error(f"Error logging system state: {e}")

    def analyze_capture(self, pcap_file: str) -> Dict[str, Any]:
        """
        Analyze captured traffic to extract attack characteristics
        
        Args:
            pcap_file: Path to PCAP file
            
        Returns:
            Dictionary with traffic analysis results
        """
        try:
            # Basic traffic analysis using tshark
            result = subprocess.run([
                "tshark", "-r", pcap_file, "-q", "-z", "conv,ip", "-z", "plen,tree"
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                logger.error(f"tshark analysis failed: {result.stderr}")
                return {"error": "tshark analysis failed"}
            
            # Parse tshark output (basic implementation)
            analysis = {
                "file": pcap_file,
                "analysis_time": datetime.now().isoformat(),
                "tshark_output": result.stdout
            }
            
            # Extract packet counts and sizes
            lines = result.stdout.split('\n')
            for line in lines:
                if "Total frames:" in line:
                    analysis["total_packets"] = int(line.split(":")[1].strip())
                elif "Total bytes:" in line:
                    analysis["total_bytes"] = int(line.split(":")[1].strip())
            
            return analysis
            
        except subprocess.TimeoutExpired:
            logger.error(f"tshark analysis timed out for {pcap_file}")
            return {"error": "Analysis timed out"}
        except Exception as e:
            logger.error(f"Error analyzing capture {pcap_file}: {e}")
            return {"error": str(e)}

# Convenience functions for common attack types
def capture_syn_flood(target_ip: str, target_port: int, duration: int = 30) -> Dict[str, Any]:
    """Capture traffic during SYN flood attack"""
    capture = GroundTruthCapture()
    filter_expr = f"tcp and port {target_port}"
    
    with capture.capture_attack("syn_flood", capture_filter=filter_expr, duration=duration) as info:
        logger.info(f"Capturing SYN flood to {target_ip}:{target_port}")
        return info

def capture_port_scan(target_ip: str, port_range: str = "1-1000", duration: int = 60) -> Dict[str, Any]:
    """Capture traffic during port scan"""
    capture = GroundTruthCapture()
    filter_expr = f"host {target_ip}"
    
    with capture.capture_attack("port_scan", capture_filter=filter_expr, duration=duration) as info:
        logger.info(f"Capturing port scan of {target_ip} ports {port_range}")
        return info

def capture_http_flood(target_ip: str, target_port: int = 80, duration: int = 30) -> Dict[str, Any]:
    """Capture traffic during HTTP flood attack"""
    capture = GroundTruthCapture()
    filter_expr = f"tcp and host {target_ip} and port {target_port}"
    
    with capture.capture_attack("http_flood", capture_filter=filter_expr, duration=duration) as info:
        logger.info(f"Capturing HTTP flood to {target_ip}:{target_port}")
        return info