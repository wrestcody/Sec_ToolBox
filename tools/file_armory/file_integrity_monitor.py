#!/usr/bin/env python3
"""
File Integrity Monitor

Monitors file system changes with Guardian's Mandate integration.
This tool implements The Guardian's Mandate for unassailable digital evidence
integrity and unbreakable chain of custody.
"""

import argparse
import sys
import json
import os
import hashlib
import time
from typing import Dict, List, Any, Optional, Set
from datetime import datetime
from pathlib import Path
import threading
import signal

# Import Guardian's Mandate integration
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from guardians_mandate_integration import GuardianTool, EvidenceLevel, AuditEventType


class FileIntegrityMonitor(GuardianTool):
    """
    File Integrity Monitor with Guardian's Mandate integration.
    """
    
    def __init__(self, **kwargs):
        """Initialize the File Integrity Monitor."""
        super().__init__(
            tool_name="File Integrity Monitor",
            tool_version="1.0.0",
            evidence_level=EvidenceLevel.CRITICAL.value if hasattr(EvidenceLevel.CRITICAL, \'value\') else EvidenceLevel.CRITICAL,
            **kwargs
        )
        self.monitored_paths = set()
        self.file_hashes = {}
        self.monitoring = False
        self.monitor_thread = None
        self.changes_detected = []
    
    def add_monitoring_path(self, path: str, recursive: bool = True) -> bool:
        """
        Add a path to monitor for file integrity changes.
        
        Args:
            path: Path to monitor
            recursive: Whether to monitor subdirectories
            
        Returns:
            True if path was added successfully
        """
        try:
            path_obj = Path(path)
            if not path_obj.exists():
                self.logger.error(f"Path does not exist: {path}")
                return False
            
            # Record monitoring path addition
            self.record_guardian_event(
                event_type=AuditEventType.CONFIGURATION_CHANGE.value if hasattr(AuditEventType.CONFIGURATION_CHANGE, \'value\') else AuditEventType.CONFIGURATION_CHANGE if hasattr(AuditEventType.CONFIGURATION_CHANGE, 'value') else AuditEventType.CONFIGURATION_CHANGE,
                action="add_monitoring_path",
                resource=f"/monitor/path/{path}",
                details={
                    "path": str(path_obj.absolute()),
                    "recursive": recursive,
                    "path_type": "file" if path_obj.is_file() else "directory"
                },
                evidence_level=EvidenceLevel.HIG.value if hasattr(EvidenceLevel.HIG, \'value\') else EvidenceLevel.HIGH.value if hasattr(EvidenceLevel.HIGH, \'value\') else EvidenceLevel.HIGH if hasattr(EvidenceLevel.HIGH, 'value') else EvidenceLevel.HIGH
            )
            
            self.monitored_paths.add((str(path_obj.absolute()), recursive))
            
            # Initialize baseline for the path
            self._initialize_baseline(path_obj, recursive)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error adding monitoring path {path}: {e}")
            return False
    
    def _initialize_baseline(self, path_obj: Path, recursive: bool):
        """Initialize baseline hashes for monitored files."""
        try:
            if path_obj.is_file():
                self._hash_file(path_obj)
            elif path_obj.is_dir() and recursive:
                for file_path in path_obj.rglob("*"):
                    if file_path.is_file():
                        self._hash_file(file_path)
            elif path_obj.is_dir():
                for file_path in path_obj.iterdir():
                    if file_path.is_file():
                        self._hash_file(file_path)
            
            # Record baseline initialization
                    self.record_guardian_event(
            event_type=AuditEventType.SYSTEM_EVENT.value if hasattr(AuditEventType.SYSTEM_EVENT, \'value\') else AuditEventType.SYSTEM_EVENT if hasattr(AuditEventType.SYSTEM_EVENT, 'value') else AuditEventType.SYSTEM_EVENT,
            action="baseline_initialized",
            resource=f"/monitor/baseline/{path_obj}",
            details={
                "path": str(path_obj.absolute()),
                "files_monitored": len([f for f in self.file_hashes.keys() if str(f).startswith(str(path_obj.absolute()))]),
                "baseline_timestamp": datetime.now().isoformat()
            },
            evidence_level=EvidenceLevel.CRITICA.value if hasattr(EvidenceLevel.CRITICA, \'value\') else EvidenceLevel.CRITICAL.value if hasattr(EvidenceLevel.CRITICAL, \'value\') else EvidenceLevel.CRITICAL if hasattr(EvidenceLevel.CRITICAL, 'value') else EvidenceLevel.CRITICAL
        )
            
        except Exception as e:
            self.logger.error(f"Error initializing baseline for {path_obj}: {e}")
    
    def _hash_file(self, file_path: Path) -> Optional[str]:
        """Calculate SHA-256 hash of a file."""
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256()
                for chunk in iter(lambda: f.read(4096), b""):
                    file_hash.update(chunk)
                hash_value = file_hash.hexdigest()
                
                # Store hash with file metadata
                self.file_hashes[file_path] = {
                    "hash": hash_value,
                    "size": file_path.stat().st_size,
                    "mtime": file_path.stat().st_mtime,
                    "baseline_timestamp": datetime.now().isoformat()
                }
                
                return hash_value
        except Exception as e:
            self.logger.error(f"Error hashing file {file_path}: {e}")
            return None
    
    def start_monitoring(self, interval: int = 60) -> bool:
        """
        Start monitoring file integrity changes.
        
        Args:
            interval: Monitoring interval in seconds
            
        Returns:
            True if monitoring started successfully
        """
        if not self.monitored_paths:
            self.logger.error("No paths to monitor")
            return False
        
        # Record monitoring start
        self.record_guardian_event(
            event_type=AuditEventType.SYSTEM_EVENT.value if hasattr(AuditEventType.SYSTEM_EVENT, \'value\') else AuditEventType.SYSTEM_EVENT if hasattr(AuditEventType.SYSTEM_EVENT, 'value') else AuditEventType.SYSTEM_EVENT,
            action="monitoring_start",
            resource="/monitor/start",
            details={
                "monitored_paths": list(self.monitored_paths),
                "monitoring_interval": interval,
                "start_timestamp": datetime.now().isoformat()
            },
            evidence_level=EvidenceLevel.CRITICA.value if hasattr(EvidenceLevel.CRITICA, \'value\') else EvidenceLevel.CRITICAL.value if hasattr(EvidenceLevel.CRITICAL, \'value\') else EvidenceLevel.CRITICAL if hasattr(EvidenceLevel.CRITICAL, 'value') else EvidenceLevel.CRITICAL
        )
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(
            target=self._monitor_loop,
            args=(interval,),
            daemon=True
        )
        self.monitor_thread.start()
        
        return True
    
    def stop_monitoring(self):
        """Stop file integrity monitoring."""
        self.monitoring = False
        
        # Record monitoring stop
        self.record_guardian_event(
            event_type=AuditEventType.SYSTEM_EVENT.value if hasattr(AuditEventType.SYSTEM_EVENT, \'value\') else AuditEventType.SYSTEM_EVENT if hasattr(AuditEventType.SYSTEM_EVENT, 'value') else AuditEventType.SYSTEM_EVENT,
            action="monitoring_stop",
            resource="/monitor/stop",
            details={
                "stop_timestamp": datetime.now().isoformat(),
                "total_changes_detected": len(self.changes_detected)
            },
            evidence_level=EvidenceLevel.HIG.value if hasattr(EvidenceLevel.HIG, \'value\') else EvidenceLevel.HIGH.value if hasattr(EvidenceLevel.HIGH, \'value\') else EvidenceLevel.HIGH if hasattr(EvidenceLevel.HIGH, 'value') else EvidenceLevel.HIGH
        )
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
    
    def _monitor_loop(self, interval: int):
        """Main monitoring loop."""
        while self.monitoring:
            try:
                self._check_integrity()
                time.sleep(interval)
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(interval)
    
    def _check_integrity(self):
        """Check integrity of all monitored files."""
        changes_found = []
        
        for path_str, recursive in self.monitored_paths:
            path_obj = Path(path_str)
            
            if path_obj.is_file():
                changes = self._check_file_integrity(path_obj)
                if changes:
                    changes_found.extend(changes)
            elif path_obj.is_dir():
                if recursive:
                    files_to_check = path_obj.rglob("*")
                else:
                    files_to_check = path_obj.iterdir()
                
                for file_path in files_to_check:
                    if file_path.is_file():
                        changes = self._check_file_integrity(file_path)
                        if changes:
                            changes_found.extend(changes)
        
        # Record any changes found
        if changes_found:
            self.changes_detected.extend(changes_found)
            
            for change in changes_found:
                self.record_guardian_event(
                    event_type=AuditEventType.SECURITY_EVENT.value if hasattr(AuditEventType.SECURITY_EVENT, \'value\') else AuditEventType.SECURITY_EVENT if hasattr(AuditEventType.SECURITY_EVENT, 'value') else AuditEventType.SECURITY_EVENT,
                    action="integrity_violation",
                    resource=f"/file/{change['file_path']}",
                    details={
                        "file_path": str(change['file_path']),
                        "change_type": change['change_type'],
                        "old_hash": change.get('old_hash'),
                        "new_hash": change.get('new_hash'),
                        "detection_timestamp": datetime.now().isoformat(),
                        "severity": change.get('severity', 'high')
                    },
                    evidence_level=EvidenceLevel.CRITICA.value if hasattr(EvidenceLevel.CRITICA, \'value\') else EvidenceLevel.CRITICAL.value if hasattr(EvidenceLevel.CRITICAL, \'value\') else EvidenceLevel.CRITICAL if hasattr(EvidenceLevel.CRITICAL, 'value') else EvidenceLevel.CRITICAL
                )
    
    def _check_file_integrity(self, file_path: Path) -> List[Dict[str, Any]]:
        """Check integrity of a single file."""
        changes = []
        
        try:
            # Check if file still exists
            if not file_path.exists():
                if file_path in self.file_hashes:
                    changes.append({
                        "file_path": file_path,
                        "change_type": "file_deleted",
                        "old_hash": self.file_hashes[file_path]["hash"],
                        "severity": "critical"
                    })
                    del self.file_hashes[file_path]
                return changes
            
            # Calculate current hash
            current_hash = self._hash_file(file_path)
            if not current_hash:
                return changes
            
            # Check if file is new
            if file_path not in self.file_hashes:
                changes.append({
                    "file_path": file_path,
                    "change_type": "file_created",
                    "new_hash": current_hash,
                    "severity": "high"
                })
                return changes
            
            # Check for hash changes
            baseline_hash = self.file_hashes[file_path]["hash"]
            if current_hash != baseline_hash:
                changes.append({
                    "file_path": file_path,
                    "change_type": "file_modified",
                    "old_hash": baseline_hash,
                    "new_hash": current_hash,
                    "severity": "critical"
                })
            
            # Check for size changes
            current_size = file_path.stat().st_size
            baseline_size = self.file_hashes[file_path]["size"]
            if current_size != baseline_size:
                changes.append({
                    "file_path": file_path,
                    "change_type": "file_size_changed",
                    "old_size": baseline_size,
                    "new_size": current_size,
                    "severity": "medium"
                })
            
            # Update baseline
            self.file_hashes[file_path].update({
                "hash": current_hash,
                "size": current_size,
                "mtime": file_path.stat().st_mtime
            })
            
        except Exception as e:
            self.logger.error(f"Error checking integrity of {file_path}: {e}")
        
        return changes
    
    def get_integrity_report(self) -> Dict[str, Any]:
        """Generate integrity monitoring report."""
        report = {
            "monitoring_info": {
                "monitored_paths": list(self.monitored_paths),
                "total_files_monitored": len(self.file_hashes),
                "monitoring_active": self.monitoring,
                "report_timestamp": datetime.now().isoformat()
            },
            "changes_detected": self.changes_detected,
            "summary": {
                "total_changes": len(self.changes_detected),
                "critical_changes": len([c for c in self.changes_detected if c.get('severity') == 'critical']),
                "high_changes": len([c for c in self.changes_detected if c.get('severity') == 'high']),
                "medium_changes": len([c for c in self.changes_detected if c.get('severity') == 'medium']),
                "low_changes": len([c for c in self.changes_detected if c.get('severity') == 'low'])
            },
            "current_baseline": {
                "files": {
                    str(path): {
                        "hash": data["hash"],
                        "size": data["size"],
                        "baseline_timestamp": data["baseline_timestamp"]
                    }
                    for path, data in self.file_hashes.items()
                }
            }
        }
        
        return report
    
    def export_baseline(self, output_path: str) -> bool:
        """Export current baseline for external verification."""
        try:
            baseline_data = {
                "baseline_info": {
                    "tool_name": self.tool_name,
                    "tool_version": self.tool_version,
                    "export_timestamp": datetime.now().isoformat(),
                    "session_id": self.session_id
                },
                "monitored_paths": list(self.monitored_paths),
                "file_hashes": {
                    str(path): data
                    for path, data in self.file_hashes.items()
                }
            }
            
            with open(output_path, 'w') as f:
                json.dump(baseline_data, f, indent=2)
            
            # Record baseline export
            self.record_guardian_event(
                event_type=AuditEventType.DATA_ACCESS.value if hasattr(AuditEventType.DATA_ACCESS, \'value\') else AuditEventType.DATA_ACCESS if hasattr(AuditEventType.DATA_ACCESS, 'value') else AuditEventType.DATA_ACCESS,
                action="baseline_export",
                resource=f"/baseline/export/{output_path}",
                details={
                    "output_path": output_path,
                    "files_in_baseline": len(self.file_hashes),
                    "export_timestamp": datetime.now().isoformat()
                },
                evidence_level=EvidenceLevel.CRITICA.value if hasattr(EvidenceLevel.CRITICA, \'value\') else EvidenceLevel.CRITICAL.value if hasattr(EvidenceLevel.CRITICAL, \'value\') else EvidenceLevel.CRITICAL if hasattr(EvidenceLevel.CRITICAL, 'value') else EvidenceLevel.CRITICAL
            )
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting baseline: {e}")
            return False


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="File Integrity Monitor with Guardian's Mandate integration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --add-path /etc --recursive
  %(prog)s --add-path /var/log --start-monitoring --interval 30
  %(prog)s --add-path /home/user --export-baseline baseline.json
        """
    )
    
    parser.add_argument(
        '--add-path',
        action='append',
        help='Path to monitor for integrity changes'
    )
    
    parser.add_argument(
        '--recursive',
        action='store_true',
        help='Monitor subdirectories recursively'
    )
    
    parser.add_argument(
        '--start-monitoring',
        action='store_true',
        help='Start continuous monitoring'
    )
    
    parser.add_argument(
        '--interval',
        type=int,
        default=60,
        help='Monitoring interval in seconds (default: 60)'
    )
    
    parser.add_argument(
        '--export-baseline',
        help='Export current baseline to file'
    )
    
    parser.add_argument(
        '--report',
        action='store_true',
        help='Generate and display integrity report'
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
    
    # Initialize monitor
    monitor = FileIntegrityMonitor(
        enable_guardian_mandate=not args.disable_guardian_mandate
    )
    
    try:
        # Add monitoring paths
        if args.add_path:
            for path in args.add_path:
                if monitor.add_monitoring_path(path, args.recursive):
                    print(f"✅ Added monitoring path: {path}")
                else:
                    print(f"❌ Failed to add monitoring path: {path}")
        
        # Export baseline if requested
        if args.export_baseline:
            if monitor.export_baseline(args.export_baseline):
                print(f"✅ Baseline exported to: {args.export_baseline}")
            else:
                print(f"❌ Failed to export baseline")
        
        # Generate report if requested
        if args.report:
            report = monitor.get_integrity_report()
            print(json.dumps(report, indent=2))
        
        # Start monitoring if requested
        if args.start_monitoring:
            print(f"🔍 Starting file integrity monitoring...")
            print(f"   Interval: {args.interval} seconds")
            print(f"   Monitored paths: {len(monitor.monitored_paths)}")
            print("=" * 50)
            
            if monitor.start_monitoring(args.interval):
                print("✅ Monitoring started successfully")
                
                # Set up signal handler for graceful shutdown
                def signal_handler(signum, frame):
                    print("\n🛑 Stopping monitoring...")
                    monitor.stop_monitoring()
                    sys.exit(0)
                
                signal.signal(signal.SIGINT, signal_handler)
                signal.signal(signal.SIGTERM, signal_handler)
                
                # Keep monitoring running
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    print("\n🛑 Stopping monitoring...")
                    monitor.stop_monitoring()
        
        # Export forensic data if Guardian's Mandate is enabled
        if monitor.enable_guardian_mandate:
            print(f"\n🛡️  Guardian's Mandate: Digital Evidence Integrity")
            print("=" * 50)
            
            # Verify integrity
            integrity_result = monitor.verify_integrity()
            if integrity_result['verified']:
                print("✅ Integrity verification: PASSED")
                print(f"   Verified blocks: {integrity_result['verified_blocks']}/{integrity_result['total_blocks']}")
            else:
                print("❌ Integrity verification: FAILED")
                for error in integrity_result.get('errors', []):
                    print(f"   Error: {error}")
            
            # Export forensic data
            export_path = monitor.export_forensic_data()
            if export_path:
                print(f"✅ Forensic data exported to: {export_path}")
            
            # Show chain of custody for changes
            if monitor.changes_detected:
                print(f"\n🔗 Chain of Custody:")
                print(f"   {len(monitor.changes_detected)} changes recorded with cryptographic proof")
                print(f"   Session ID: {monitor.session_id}")
                print(f"   Evidence Integrity: CRITICAL")
        
    except Exception as e:
        print(f"❌ Monitor failed: {e}")
        sys.exit(1)
    finally:
        monitor.cleanup()


if __name__ == '__main__':
    main()