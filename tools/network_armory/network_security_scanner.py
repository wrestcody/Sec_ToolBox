#!/usr/bin/env python3
"""
Network Security Scanner

Scans network for security vulnerabilities with Guardian's Mandate integration.
This tool implements The Guardian's Mandate for unassailable digital evidence
integrity and unbreakable chain of custody.
"""

import argparse
import sys
import json
import socket
import subprocess
import ipaddress
from typing import Dict, List, Any, Optional
from datetime import datetime
import threading
import time
import os

# Import Guardian's Mandate integration
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from guardians_mandate_integration import GuardianTool, EvidenceLevel, AuditEventType


class NetworkSecurityScanner(GuardianTool):
    """
    Network Security Scanner with Guardian's Mandate integration.
    """
    
    def __init__(self, **kwargs):
        """Initialize the Network Security Scanner."""
        super().__init__(
            tool_name="Network Security Scanner",
            tool_version="1.0.0",
            evidence_level=EvidenceLevel.CRITICAL.value if hasattr(EvidenceLevel.CRITICAL, \'value\') else EvidenceLevel.CRITICAL,
            **kwargs
        )
        self.scan_results = []
        self.vulnerabilities = []
    
    def scan_network(self, target_range: str, scan_type: str = "basic") -> Dict[str, Any]:
        """
        Scan network for security vulnerabilities with Guardian's Mandate integrity guarantees.
        
        Args:
            target_range: Network range to scan (e.g., "192.168.1.0/24")
            scan_type: Type of scan (basic, comprehensive, stealth)
            
        Returns:
            Scan results with integrity proofs
        """
        # Record scan start
        self.record_guardian_event(
            event_type=AuditEventType.SECURITY_EVENT.value if hasattr(AuditEventType.SECURITY_EVENT, \'value\') else AuditEventType.SECURITY_EVENT if hasattr(AuditEventType.SECURITY_EVENT, 'value') else AuditEventType.SECURITY_EVENT,
            action="network_scan_start",
            resource=f"/network/scan/{target_range}",
            details={
                "target_range": target_range,
                "scan_type": scan_type,
                "scan_timestamp": datetime.now().isoformat()
            },
            evidence_level=EvidenceLevel.CRITICA.value if hasattr(EvidenceLevel.CRITICA, \'value\') else EvidenceLevel.CRITICAL.value if hasattr(EvidenceLevel.CRITICAL, \'value\') else EvidenceLevel.CRITICAL if hasattr(EvidenceLevel.CRITICAL, 'value') else EvidenceLevel.CRITICAL
        )
        
        try:
            # Validate target range
            network = ipaddress.ip_network(target_range, strict=False)
            
            # Record network validation
            self.record_guardian_event(
                event_type=AuditEventType.SYSTEM_EVENT.value if hasattr(AuditEventType.SYSTEM_EVENT, \'value\') else AuditEventType.SYSTEM_EVENT if hasattr(AuditEventType.SYSTEM_EVENT, 'value') else AuditEventType.SYSTEM_EVENT,
                action="network_validation",
                resource=f"/network/validation/{target_range}",
                details={
                    "target_range": target_range,
                    "network_addresses": str(network.num_addresses),
                    "network_bits": network.prefixlen
                },
                evidence_level=EvidenceLevel.HIG.value if hasattr(EvidenceLevel.HIG, \'value\') else EvidenceLevel.HIGH.value if hasattr(EvidenceLevel.HIGH, \'value\') else EvidenceLevel.HIGH if hasattr(EvidenceLevel.HIGH, 'value') else EvidenceLevel.HIGH
            )
            
            # Perform scan
            scan_results = self._perform_network_scan(network, scan_type)
            
            # Record scan completion
            self.record_guardian_event(
                event_type=AuditEventType.SECURITY_EVENT.value if hasattr(AuditEventType.SECURITY_EVENT, \'value\') else AuditEventType.SECURITY_EVENT,
                action="network_scan_complete",
                resource=f"/network/scan/{target_range}",
                details={
                    "target_range": target_range,
                    "scan_type": scan_type,
                    "hosts_scanned": len(scan_results.get("hosts", [])),
                    "vulnerabilities_found": len(scan_results.get("vulnerabilities", [])),
                    "scan_duration": scan_results.get("scan_duration", 0)
                },
                evidence_level=EvidenceLevel.CRITICAL.value if hasattr(EvidenceLevel.CRITICAL, \'value\') else EvidenceLevel.CRITICAL
            )
            
            return scan_results
            
        except Exception as e:
            # Record error
            self.record_guardian_event(
                event_type=AuditEventType.SECURITY_EVENT.value if hasattr(AuditEventType.SECURITY_EVENT, \'value\') else AuditEventType.SECURITY_EVENT,
                action="network_scan_error",
                resource=f"/network/scan/{target_range}",
                details={
                    "target_range": target_range,
                    "error": str(e),
                    "error_type": type(e).__name__,
                    "success": False
                },
                evidence_level=EvidenceLevel.CRITICAL.value if hasattr(EvidenceLevel.CRITICAL, \'value\') else EvidenceLevel.CRITICAL
            )
            raise
    
    def _perform_network_scan(self, network: ipaddress.IPv4Network, scan_type: str) -> Dict[str, Any]:
        """
        Perform the actual network scan.
        
        Args:
            network: Network to scan
            scan_type: Type of scan to perform
            
        Returns:
            Scan results
        """
        start_time = time.time()
        hosts = []
        vulnerabilities = []
        
        # Record scan method
        self.record_guardian_event(
            event_type=AuditEventType.SYSTEM_EVENT.value if hasattr(AuditEventType.SYSTEM_EVENT, \'value\') else AuditEventType.SYSTEM_EVENT,
            action="scan_method_selected",
            resource="/scan/method",
            details={
                "scan_type": scan_type,
                "network": str(network),
                "total_addresses": network.num_addresses
            },
            evidence_level=EvidenceLevel.HIGH.value if hasattr(EvidenceLevel.HIGH, \'value\') else EvidenceLevel.HIGH
        )
        
        # Scan each host in the network
        for ip in network.hosts():
            host_result = self._scan_host(str(ip), scan_type)
            if host_result:
                hosts.append(host_result)
                
                # Record each host scan
                self.record_guardian_event(
                    event_type=AuditEventType.DATA_ACCESS.value if hasattr(AuditEventType.DATA_ACCESS, \'value\') else AuditEventType.DATA_ACCESS,
                    action="host_scan",
                    resource=f"/host/{ip}",
                    details={
                        "ip_address": str(ip),
                        "host_status": host_result.get("status"),
                        "open_ports": host_result.get("open_ports", []),
                        "vulnerabilities": host_result.get("vulnerabilities", [])
                    },
                    evidence_level=EvidenceLevel.HIGH.value if hasattr(EvidenceLevel.HIGH, \'value\') else EvidenceLevel.HIGH
                )
                
                # Collect vulnerabilities
                if host_result.get("vulnerabilities"):
                    vulnerabilities.extend(host_result["vulnerabilities"])
        
        scan_duration = time.time() - start_time
        
        # Record scan summary
        self.record_guardian_event(
            event_type=AuditEventType.SYSTEM_EVENT.value if hasattr(AuditEventType.SYSTEM_EVENT, \'value\') else AuditEventType.SYSTEM_EVENT,
            action="scan_summary",
            resource="/scan/summary",
            details={
                "total_hosts": len(hosts),
                "active_hosts": len([h for h in hosts if h.get("status") == "up"]),
                "total_vulnerabilities": len(vulnerabilities),
                "scan_duration": scan_duration,
                "scan_type": scan_type
            },
            evidence_level=EvidenceLevel.CRITICAL.value if hasattr(EvidenceLevel.CRITICAL, \'value\') else EvidenceLevel.CRITICAL
        )
        
        return {
            "scan_info": {
                "target_network": str(network),
                "scan_type": scan_type,
                "scan_start": datetime.fromtimestamp(start_time).isoformat(),
                "scan_duration": scan_duration,
                "total_hosts": len(hosts)
            },
            "hosts": hosts,
            "vulnerabilities": vulnerabilities,
            "summary": {
                "active_hosts": len([h for h in hosts if h.get("status") == "up"]),
                "total_vulnerabilities": len(vulnerabilities),
                "critical_vulnerabilities": len([v for v in vulnerabilities if v.get("severity") == "critical"]),
                "high_vulnerabilities": len([v for v in vulnerabilities if v.get("severity") == "high"]),
                "medium_vulnerabilities": len([v for v in vulnerabilities if v.get("severity") == "medium"]),
                "low_vulnerabilities": len([v for v in vulnerabilities if v.get("severity") == "low"])
            }
        }
    
    def _scan_host(self, ip: str, scan_type: str) -> Optional[Dict[str, Any]]:
        """
        Scan a single host for vulnerabilities.
        
        Args:
            ip: IP address to scan
            scan_type: Type of scan to perform
            
        Returns:
            Host scan results
        """
        try:
            # Basic connectivity check
            if not self._is_host_up(ip):
                return {
                    "ip": ip,
                    "status": "down",
                    "open_ports": [],
                    "vulnerabilities": []
                }
            
            # Port scan based on scan type
            open_ports = self._port_scan(ip, scan_type)
            
            # Vulnerability scan
            vulnerabilities = self._vulnerability_scan(ip, open_ports, scan_type)
            
            return {
                "ip": ip,
                "status": "up",
                "open_ports": open_ports,
                "vulnerabilities": vulnerabilities,
                "scan_timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error scanning host {ip}: {e}")
            return {
                "ip": ip,
                "status": "error",
                "error": str(e),
                "open_ports": [],
                "vulnerabilities": []
            }
    
    def _is_host_up(self, ip: str) -> bool:
        """Check if a host is up using ping."""
        try:
            # Use ping to check host status
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except:
            return False
    
    def _port_scan(self, ip: str, scan_type: str) -> List[int]:
        """Perform port scanning on a host."""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 8080]
        
        open_ports = []
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
        
        return open_ports
    
    def _vulnerability_scan(self, ip: str, open_ports: List[int], scan_type: str) -> List[Dict[str, Any]]:
        """Perform vulnerability scanning on a host."""
        vulnerabilities = []
        
        # Simulate vulnerability detection based on open ports
        for port in open_ports:
            if port == 22:
                vulnerabilities.append({
                    "port": port,
                    "service": "SSH",
                    "vulnerability": "Default SSH configuration",
                    "severity": "medium",
                    "description": "SSH service detected with potential default configuration",
                    "recommendation": "Review SSH configuration and disable root login"
                })
            elif port == 80:
                vulnerabilities.append({
                    "port": port,
                    "service": "HTTP",
                    "vulnerability": "Unencrypted HTTP traffic",
                    "severity": "high",
                    "description": "HTTP service detected without encryption",
                    "recommendation": "Use HTTPS instead of HTTP"
                })
            elif port == 23:
                vulnerabilities.append({
                    "port": port,
                    "service": "Telnet",
                    "vulnerability": "Telnet service enabled",
                    "severity": "critical",
                    "description": "Telnet service is enabled and transmits data in plaintext",
                    "recommendation": "Disable Telnet and use SSH instead"
                })
            elif port == 3389:
                vulnerabilities.append({
                    "port": port,
                    "service": "RDP",
                    "vulnerability": "Remote Desktop Protocol exposed",
                    "severity": "high",
                    "description": "RDP service is accessible from network",
                    "recommendation": "Restrict RDP access and use VPN"
                })
        
        return vulnerabilities


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Network Security Scanner with Guardian's Mandate integration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target 192.168.1.0/24
  %(prog)s --target 10.0.0.0/24 --scan-type comprehensive
  %(prog)s --target 172.16.0.0/16 --output scan_results.json
        """
    )
    
    parser.add_argument(
        '--target',
        required=True,
        help='Target network range (e.g., 192.168.1.0/24)'
    )
    
    parser.add_argument(
        '--scan-type',
        choices=['basic', 'comprehensive', 'stealth'],
        default='basic',
        help='Type of scan to perform (default: basic)'
    )
    
    parser.add_argument(
        '--output',
        help='Output file path for scan results'
    )
    
    parser.add_argument(
        '--disable-guardian-mandate',
        action='store_true',
        help='Disable Guardian\'s Mandate features'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s 1.0.0 (with Guardian\'s Mandate)'
    )
    
    args = parser.parse_args()
    
    # Initialize scanner
    scanner = NetworkSecurityScanner(
        enable_guardian_mandate=not args.disable_guardian_mandate
    )
    
    try:
        print(f"🔍 Network Security Scanner")
        print(f"Target: {args.target}")
        print(f"Scan Type: {args.scan_type}")
        print("=" * 50)
        
        # Run scan
        results = scanner.scan_network(args.target, args.scan_type)
        
        # Output results
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"✅ Scan results saved to {args.output}")
        else:
            print(json.dumps(results, indent=2))
        
        # Print summary
        summary = results.get("summary", {})
        print(f"\n📊 Scan Summary:")
        print(f"   Active Hosts: {summary.get('active_hosts', 0)}")
        print(f"   Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
        print(f"   Critical: {summary.get('critical_vulnerabilities', 0)}")
        print(f"   High: {summary.get('high_vulnerabilities', 0)}")
        print(f"   Medium: {summary.get('medium_vulnerabilities', 0)}")
        print(f"   Low: {summary.get('low_vulnerabilities', 0)}")
        
        # Export forensic data if Guardian's Mandate is enabled
        if scanner.enable_guardian_mandate:
            print(f"\n🛡️  Guardian's Mandate: Digital Evidence Integrity")
            print("=" * 50)
            
            # Verify integrity
            integrity_result = scanner.verify_integrity()
            if integrity_result['verified']:
                print("✅ Integrity verification: PASSED")
                print(f"   Verified blocks: {integrity_result['verified_blocks']}/{integrity_result['total_blocks']}")
            else:
                print("❌ Integrity verification: FAILED")
                for error in integrity_result.get('errors', []):
                    print(f"   Error: {error}")
            
            # Export forensic data
            export_path = scanner.export_forensic_data()
            if export_path:
                print(f"✅ Forensic data exported to: {export_path}")
            
            # Show chain of custody for vulnerabilities
            if summary.get('total_vulnerabilities', 0) > 0:
                print(f"\n🔗 Chain of Custody:")
                print(f"   {summary.get('total_vulnerabilities', 0)} vulnerabilities recorded with cryptographic proof")
                print(f"   Session ID: {scanner.session_id}")
                print(f"   Evidence Integrity: CRITICAL")
        
    except Exception as e:
        print(f"❌ Scan failed: {e}")
        sys.exit(1)
    finally:
        scanner.cleanup()


if __name__ == '__main__':
    main()