#!/usr/bin/env python3
"""
Network Attack Simulation Script
Generates real network traffic patterns that the threat detection system can capture and analyze.
This script creates traffic that Zeek can monitor on the eth0 interface.
"""
import socket
import time
import argparse
import sys
from datetime import datetime


class NetworkAttackSimulator:
    """Simulate various network attack patterns for testing threat detection."""
    
    def __init__(self):
        self.attacks_performed = []
        self.total_connections = 0
    
    def log_attack(self, attack_type, target, connections_made):
        """Log attack details."""
        self.attacks_performed.append({
            'type': attack_type,
            'target': target,
            'connections': connections_made,
            'timestamp': datetime.now().isoformat()
        })
        self.total_connections += connections_made
    
    def dns_flood_attack(self, intensity=20, delay=0.01):
        """
        Simulate DNS flood attack by rapidly connecting to multiple DNS servers.
        This generates high-frequency connection patterns that should be detected as anomalous.
        
        Args:
            intensity: Number of connections per DNS server
            delay: Delay between connections (seconds)
        """
        print(f"Starting DNS flood attack (intensity: {intensity}, delay: {delay}s)")
        
        # Target multiple DNS servers
        dns_servers = [
            ('8.8.8.8', 53),      # Google DNS
            ('1.1.1.1', 53),      # Cloudflare DNS
            ('8.8.4.4', 53),      # Google DNS Alt
            ('208.67.222.222', 53), # OpenDNS
        ]
        
        connections_made = 0
        
        for server_ip, port in dns_servers:
            print(f"  Targeting {server_ip}:{port} with {intensity} connections...")
            
            for i in range(intensity):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.01)  # Very short timeout
                    sock.connect_ex((server_ip, port))
                    sock.close()
                    connections_made += 1
                except:
                    pass
                
                time.sleep(delay)
                
                # Progress indicator
                if i % 5 == 0:
                    print(f"    Progress: {i+1}/{intensity}")
        
        self.log_attack("DNS_FLOOD", f"{len(dns_servers)} DNS servers", connections_made)
        print(f"DNS flood complete: {connections_made} connections made")
        return connections_made
    
    def port_scan_attack(self, target_ip="8.8.8.8", start_port=8080, end_port=8090, delay=0.02):
        """
        Simulate port scanning attack by probing multiple ports on a target.
        
        Args:
            target_ip: IP address to scan
            start_port: Starting port number
            end_port: Ending port number
            delay: Delay between port probes
        """
        print(f"Starting port scan attack on {target_ip} (ports {start_port}-{end_port})")
        
        connections_made = 0
        
        for port in range(start_port, end_port + 1):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.01)
                result = sock.connect_ex((target_ip, port))
                sock.close()
                connections_made += 1
                
                print(f"  Scanned {target_ip}:{port}")
                
            except:
                pass
            
            time.sleep(delay)
        
        self.log_attack("PORT_SCAN", f"{target_ip}:{start_port}-{end_port}", connections_made)
        print(f"Port scan complete: {connections_made} probes sent")
        return connections_made
    
    def connection_flood_attack(self, target_ip="1.1.1.1", target_port=80, connections=30, delay=0.005):
        """
        Simulate connection flood by rapidly connecting to the same service.
        
        Args:
            target_ip: Target server IP
            target_port: Target port
            connections: Number of connections to attempt
            delay: Delay between connections
        """
        print(f"Starting connection flood attack on {target_ip}:{target_port} ({connections} connections)")
        
        connections_made = 0
        
        for i in range(connections):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.01)
                sock.connect_ex((target_ip, target_port))
                sock.close()
                connections_made += 1
                
                if i % 10 == 0:
                    print(f"  Progress: {i+1}/{connections}")
                
            except:
                pass
            
            time.sleep(delay)
        
        self.log_attack("CONNECTION_FLOOD", f"{target_ip}:{target_port}", connections_made)
        print(f"Connection flood complete: {connections_made} connections made")
        return connections_made
    
    def mixed_attack_pattern(self):
        """
        Execute a combination of attack patterns to test comprehensive detection.
        This simulates a more realistic attack scenario.
        """
        print("Starting mixed attack pattern simulation...")
        print("This will generate multiple types of suspicious traffic")
        
        total_connections = 0
        
        # 1. Light port scan
        print("\n--- Phase 1: Port Scanning ---")
        total_connections += self.port_scan_attack(
            target_ip="8.8.8.8",
            start_port=8080,
            end_port=8085,
            delay=0.03
        )
        
        # 2. DNS flood
        print("\n--- Phase 2: DNS Flood ---")
        total_connections += self.dns_flood_attack(
            intensity=15,
            delay=0.015
        )
        
        # 3. Connection flood
        print("\n--- Phase 3: Connection Flood ---")
        total_connections += self.connection_flood_attack(
            target_ip="208.67.222.222",
            target_port=53,
            connections=20,
            delay=0.01
        )
        
        print(f"\nMixed attack pattern complete: {total_connections} total connections")
        return total_connections
    
    def print_summary(self):
        """Print summary of all attacks performed."""
        print("\n" + "="*60)
        print("ATTACK SIMULATION SUMMARY")
        print("="*60)
        print(f"Total attacks performed: {len(self.attacks_performed)}")
        print(f"Total connections made: {self.total_connections}")
        print("\nAttack details:")
        
        for attack in self.attacks_performed:
            print(f"  {attack['timestamp'][:19]} | {attack['type']:15} | {attack['target']:20} | {attack['connections']} connections")
        
        print("\n" + "="*60)
        print("THREAT DETECTION VERIFICATION")
        print("="*60)
        print("1. Check your dashboard for increased anomaly count")
        print("2. Look for CRITICAL severity anomalies")
        print("3. Verify real-time detection is working")
        print("4. Expected detection rate: 70-90% of attack traffic")
        print("\nNote: It may take 30-60 seconds for all anomalies to be processed")


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(description="Network Attack Simulation for Threat Detection Testing")
    parser.add_argument("--attack", choices=["dns", "port", "flood", "mixed"], 
                       default="mixed", help="Type of attack to simulate")
    parser.add_argument("--intensity", type=int, default=20, 
                       help="Attack intensity (connections per target)")
    parser.add_argument("--delay", type=float, default=0.01, 
                       help="Delay between connections (seconds)")
    
    args = parser.parse_args()
    
    print("NETWORK ATTACK SIMULATION")
    print("="*50)
    print("This script generates network traffic patterns that should")
    print("be detected as anomalous by the threat detection system.")
    print("Make sure the backend is running before starting.")
    print("="*50)
    
    # Give user a chance to cancel
    try:
        input("\nPress Enter to start attack simulation (Ctrl+C to cancel)...")
    except KeyboardInterrupt:
        print("\nAttack simulation cancelled")
        sys.exit(0)
    
    simulator = NetworkAttackSimulator()
    
    try:
        if args.attack == "dns":
            simulator.dns_flood_attack(intensity=args.intensity, delay=args.delay)
        elif args.attack == "port":
            simulator.port_scan_attack(delay=args.delay)
        elif args.attack == "flood":
            simulator.connection_flood_attack(connections=args.intensity, delay=args.delay)
        elif args.attack == "mixed":
            simulator.mixed_attack_pattern()
        
        simulator.print_summary()
        
    except KeyboardInterrupt:
        print("\nAttack simulation interrupted")
        simulator.print_summary()
    except Exception as e:
        print(f"\nError during attack simulation: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()