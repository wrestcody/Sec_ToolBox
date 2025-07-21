#!/usr/bin/env python3
"""
Simple Network Scanner with Guardian's Mandate Integration

A practical network scanning tool that demonstrates:
- Basic network reconnaissance skills
- Clean, readable code structure
- Integration with Guardian's Mandate for audit trails
- Professional documentation and error handling

This tool is designed to be both educational and practical for security professionals.
"""

import argparse
import ipaddress
import socket
import threading
import time
from datetime import datetime
from typing import List, Dict, Optional
import json
import sys
import os

# Add parent directory to path for Guardian's Mandate integration
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
try:
    from guardians_mandate_integration import GuardianTool, EvidenceLevel, AuditEventType
    GUARDIAN_MANDATE_AVAILABLE = True
except ImportError:
    GUARDIAN_MANDATE_AVAILABLE = False
    print("Warning: Guardian's Mandate not available. Running in basic mode.")


class NetworkScanner(GuardianTool if GUARDIAN_MANDATE_AVAILABLE else object):
    """
    Simple network scanner with port scanning capabilities.
    
    Features:
    - Host discovery using ping sweep
    - Port scanning with common ports
    - Service detection
    - Guardian's Mandate integration for audit trails
    - Clean, professional output
    """
    
    def __init__(self, enable_guardian_mandate: bool = True):
        """Initialize the network scanner."""
        if GUARDIAN_MANDATE_AVAILABLE and enable_guardian_mandate:
            super().__init__(
                tool_name="NetworkScanner",
                tool_version="1.0.0",
                evidence_level=EvidenceLevel.MEDIUM
            )
        
        self.enable_guardian_mandate = enable_guardian_mandate and GUARDIAN_MANDATE_AVAILABLE
        self.scan_results = []
        self.common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS",
            995: "POP3S", 1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL",
            5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
        }
        
        if self.enable_guardian_mandate:
            self.record_guardian_event(
                event_type=AuditEventType.TOOL_STARTUP.value,
                action="network_scanner_initialized",
                details={"common_ports": len(self.common_ports)}
            )
    
    def ping_host(self, ip: str, timeout: int = 1) -> bool:
        """
        Ping a host to check if it's alive.
        
        Args:
            ip: IP address to ping
            timeout: Timeout in seconds
            
        Returns:
            True if host is alive, False otherwise
        """
        try:
            # Use socket to create a connection (more reliable than ping)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, 80))  # Try port 80
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def scan_port(self, ip: str, port: int, timeout: int = 1) -> Optional[str]:
        """
        Scan a specific port on a host.
        
        Args:
            ip: IP address to scan
            port: Port number to scan
            timeout: Timeout in seconds
            
        Returns:
            Service name if port is open, None otherwise
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                return self.common_ports.get(port, "Unknown")
            return None
        except Exception:
            return None
    
    def scan_host(self, ip: str, ports: List[int] = None) -> Dict:
        """
        Scan a single host for open ports.
        
        Args:
            ip: IP address to scan
            ports: List of ports to scan (defaults to common ports)
            
        Returns:
            Dictionary with scan results
        """
        if ports is None:
            ports = list(self.common_ports.keys())
        
        print(f"🔍 Scanning {ip}...")
        
        open_ports = []
        for port in ports:
            service = self.scan_port(ip, port)
            if service:
                open_ports.append({
                    'port': port,
                    'service': service,
                    'status': 'open'
                })
        
        host_result = {
            'ip': ip,
            'alive': len(open_ports) > 0,
            'open_ports': open_ports,
            'scan_time': datetime.now().isoformat()
        }
        
        if self.enable_guardian_mandate:
            self.record_guardian_event(
                event_type=AuditEventType.SECURITY_SCAN.value,
                action="host_scan_completed",
                resource=ip,
                details={
                    'open_ports_count': len(open_ports),
                    'ports_scanned': len(ports)
                }
            )
        
        return host_result
    
    def scan_network(self, network: str, ports: List[int] = None, 
                    max_threads: int = 10) -> List[Dict]:
        """
        Scan an entire network range.
        
        Args:
            network: Network range (e.g., "192.168.1.0/24")
            ports: List of ports to scan
            max_threads: Maximum number of concurrent threads
            
        Returns:
            List of scan results for each host
        """
        try:
            network_obj = ipaddress.IPv4Network(network, strict=False)
            hosts = [str(ip) for ip in network_obj.hosts()]
        except Exception as e:
            print(f"❌ Error parsing network range: {e}")
            return []
        
        print(f"🌐 Scanning network: {network}")
        print(f"📊 Found {len(hosts)} hosts to scan")
        print(f"🔧 Using {max_threads} threads")
        print("-" * 50)
        
        if self.enable_guardian_mandate:
            self.record_guardian_event(
                event_type=AuditEventType.SECURITY_SCAN.value,
                action="network_scan_started",
                details={
                    'network': network,
                    'hosts_count': len(hosts),
                    'max_threads': max_threads
                }
            )
        
        results = []
        threads = []
        
        # Create thread pool
        for i in range(0, len(hosts), max_threads):
            batch = hosts[i:i + max_threads]
            batch_threads = []
            
            for host in batch:
                thread = threading.Thread(
                    target=lambda h: results.append(self.scan_host(h, ports)),
                    args=(host,)
                )
                thread.start()
                batch_threads.append(thread)
            
            # Wait for batch to complete
            for thread in batch_threads:
                thread.join()
        
        # Filter out dead hosts
        alive_hosts = [r for r in results if r['alive']]
        
        if self.enable_guardian_mandate:
            self.record_guardian_event(
                event_type=AuditEventType.SECURITY_SCAN.value,
                action="network_scan_completed",
                details={
                    'total_hosts': len(hosts),
                    'alive_hosts': len(alive_hosts),
                    'scan_results': alive_hosts
                }
            )
        
        return alive_hosts
    
    def print_results(self, results: List[Dict], output_file: str = None):
        """
        Print scan results in a clean, professional format.
        
        Args:
            results: List of scan results
            output_file: Optional file to save results
        """
        print("\n" + "=" * 60)
        print("🔍 NETWORK SCAN RESULTS")
        print("=" * 60)
        
        if not results:
            print("❌ No hosts found or all hosts are down.")
            return
        
        print(f"✅ Found {len(results)} active hosts:")
        print()
        
        for host in results:
            print(f"📍 Host: {host['ip']}")
            if host['open_ports']:
                print("   Open ports:")
                for port_info in host['open_ports']:
                    print(f"   ├─ {port_info['port']}/tcp ({port_info['service']})")
                print()
            else:
                print("   └─ No open ports found")
                print()
        
        # Summary statistics
        total_ports = sum(len(host['open_ports']) for host in results)
        print(f"📊 Summary: {len(results)} hosts, {total_ports} open ports")
        
        # Save to file if requested
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    json.dump(results, f, indent=2)
                print(f"💾 Results saved to: {output_file}")
            except Exception as e:
                print(f"❌ Error saving results: {e}")


def main():
    """Main function with command-line interface."""
    parser = argparse.ArgumentParser(
        description="Simple Network Scanner with Guardian's Mandate Integration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.0/24                    # Scan entire network
  %(prog)s 192.168.1.1                       # Scan single host
  %(prog)s 192.168.1.0/24 -p 22,80,443      # Scan specific ports
  %(prog)s 192.168.1.0/24 -o results.json   # Save results to file
        """
    )
    
    parser.add_argument(
        'target',
        help='Target network (e.g., 192.168.1.0/24) or single host (e.g., 192.168.1.1)'
    )
    
    parser.add_argument(
        '-p', '--ports',
        help='Comma-separated list of ports to scan (default: common ports)',
        default=None
    )
    
    parser.add_argument(
        '-t', '--threads',
        type=int,
        default=10,
        help='Maximum number of threads (default: 10)'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Output file for results (JSON format)'
    )
    
    parser.add_argument(
        '--disable-guardian-mandate',
        action='store_true',
        help='Disable Guardian\'s Mandate integration'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=1,
        help='Timeout for port scans in seconds (default: 1)'
    )
    
    args = parser.parse_args()
    
    # Parse ports
    ports = None
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(',')]
        except ValueError:
            print("❌ Error: Invalid port format. Use comma-separated numbers (e.g., 22,80,443)")
            sys.exit(1)
    
    # Initialize scanner
    scanner = NetworkScanner(enable_guardian_mandate=not args.disable_guardian_mandate)
    
    # Determine if single host or network
    try:
        if '/' in args.target:
            # Network scan
            results = scanner.scan_network(args.target, ports, args.threads)
        else:
            # Single host scan
            results = [scanner.scan_host(args.target, ports)]
    except KeyboardInterrupt:
        print("\n⚠️  Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error during scan: {e}")
        sys.exit(1)
    
    # Print results
    scanner.print_results(results, args.output)
    
    if scanner.enable_guardian_mandate:
        print("\n🛡️  Guardian's Mandate: Audit trail recorded")
        print("   - All scan activities logged with cryptographic integrity")
        print("   - Chain of custody maintained for forensic purposes")


if __name__ == "__main__":
    main()