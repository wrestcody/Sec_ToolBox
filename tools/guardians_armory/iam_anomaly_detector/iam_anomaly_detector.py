#!/usr/bin/env python3
"""
Cloud IAM Behavioral Anomaly Detector with Guardian's Mandate Integration

A CLI tool that analyzes AWS CloudTrail logs for unusual IAM activity patterns
that could indicate a compromised identity or privilege escalation.

This tool implements The Guardian's Mandate for unassailable digital evidence
integrity and unbreakable chain of custody.

Core Features:
- Cryptographic tamper-evident logging of all analysis activities
- Immutable audit trails with blockchain-style verification
- Automated chain of custody for all findings and evidence
- Forensic-ready export capabilities with cryptographic proofs
- Compliance alignment with SOC2, ISO27001, NIST, and CIS frameworks
"""

import argparse
import json
import sys
import csv
import os
from datetime import datetime, timedelta
from typing import Dict, List, Set, Any, Optional
from collections import defaultdict
import ipaddress
import uuid
import hashlib
import hmac
import base64
from pathlib import Path

# Import The Guardian's Mandate framework
try:
    from guardians_mandate import (
        GuardianLedger, 
        EvidenceLevel, 
        AuditEventType,
        record_guardian_event,
        verify_guardian_integrity,
        export_guardian_forensic_data
    )
    GUARDIAN_MANDATE_AVAILABLE = True
except ImportError:
    print("Warning: Guardian's Mandate framework not available. Running in legacy mode.")
    GUARDIAN_MANDATE_AVAILABLE = False



# Import Guardian's Mandate integration
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from guardians_mandate_integration import GuardianTool, EvidenceLevel, AuditEventType


class IAMAnomalyDetector(GuardianTool):
    """Main class for detecting IAM behavioral anomalies with audit capabilities."""
    
    def __init__(self, baseline_days: int = 30, enable_guardian_mandate: bool = True):
    super().__init__(
        tool_name="IAMAnomalyDetector",
        tool_version="1.0.0",
        evidence_level=EvidenceLevel.HIGH
    )

        """
        Initialize the anomaly detector with Guardian's Mandate integration.
        
        Args:
            baseline_days: Number of days to use for building user baselines
            enable_guardian_mandate: Enable Guardian's Mandate integrity features
        """
        self.baseline_days = baseline_days
        self.user_baselines = {}
        self.anomalies = []
        self.enable_guardian_mandate = enable_guardian_mandate and GUARDIAN_MANDATE_AVAILABLE
        
        # Initialize Guardian's Mandate components
        if self.enable_guardian_mandate:
            self.guardian_ledger = GuardianLedger(ledger_path="iam_anomaly_guardian_ledger")
            self.analysis_session_id = str(uuid.uuid4())
            self.guardian_metadata = {
                'analysis_session_id': self.analysis_session_id,
                'guardian_mandate_version': '1.0.0',
                'evidence_integrity_level': EvidenceLevel.CRITICAL.value,
                'chain_of_custody_enabled': True,
                'cryptographic_verification_enabled': True
            }
        else:
            self.guardian_ledger = None
            self.analysis_session_id = None
            self.guardian_metadata = {}
        
        self.audit_metadata = {
            'analysis_start_time': datetime.now().isoformat(),
            'tool_version': '2.0.0',
            'analysis_parameters': {
                'baseline_days': baseline_days,
                'guardian_mandate_enabled': self.enable_guardian_mandate
            },
            'compliance_frameworks': {
                'SOC2': ['CC6.1', 'CC6.2', 'CC6.3', 'CC7.1', 'CC7.2', 'CC7.3'],
                'ISO27001': ['A.9.2.1', 'A.9.2.2', 'A.9.2.3', 'A.12.4.1', 'A.12.4.3'],
                'NIST': ['AC-2', 'AC-3', 'AC-6', 'AU-2', 'AU-3', 'AU-6'],
                'CIS': ['1.1', '1.2', '1.3', '1.4', '1.5', '1.6']
            },
            'audit_trail': [],
            'guardian_metadata': self.guardian_metadata
        }
        
        # Record analysis session start in Guardian Ledger
        if self.enable_guardian_mandate:
            self._record_guardian_event(
                event_type=AuditEventType.SYSTEM_EVENT.value,
                action="analysis_session_start",
                resource="iam_anomaly_detector",
                details={
                    "session_id": self.analysis_session_id,
                    "baseline_days": baseline_days,
                    "guardian_mandate_enabled": True,
                    "compliance_frameworks": list(self.audit_metadata['compliance_frameworks'].keys())
                },
                evidence_level=EvidenceLevel.CRITICAL
            )
        
    def load_cloudtrail_logs(self, log_file: str) -> List[Dict[str, Any]]:
        """
        Load CloudTrail logs from a JSON file.
        
        Args:
            log_file: Path to the JSON file containing CloudTrail logs
            
        Returns:
            List of CloudTrail log entries
        """
        try:
            with open(log_file, 'r') as f:
                logs = json.load(f)
            
            if isinstance(logs, dict) and 'Records' in logs:
                records = logs['Records']
            elif isinstance(logs, list):
                records = logs
            else:
                raise ValueError("Invalid CloudTrail log format")
            
            # Validate and clean log entries
            validated_logs = []
            invalid_logs = 0
            
            for i, log in enumerate(records):
                if self._validate_log_entry(log):
                    validated_logs.append(log)
                else:
                    invalid_logs += 1
                    print(f"Warning: Invalid log entry at index {i}, skipping")
            
            if invalid_logs > 0:
                print(f"Warning: {invalid_logs} invalid log entries were skipped")
            
            # Record log loading event in Guardian Ledger
            if self.enable_guardian_mandate:
                self._record_guardian_event(
                    event_type=AuditEventType.DATA_ACCESS.value,
                    action="load_cloudtrail_logs",
                    resource=log_file,
                    details={
                        "total_logs": len(records),
                        "validated_logs": len(validated_logs),
                        "invalid_logs": invalid_logs,
                        "file_size_bytes": os.path.getsize(log_file),
                        "file_hash": self._compute_file_hash(log_file)
                    },
                    evidence_level=EvidenceLevel.CRITICAL
                )
            
            return validated_logs
                
        except FileNotFoundError:
            print(f"Error: Log file '{log_file}' not found.")
            sys.exit(1)
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON in log file '{log_file}'.")
            sys.exit(1)
        except Exception as e:
            print(f"Error loading logs: {e}")
            sys.exit(1)
    
    def _compute_file_hash(self, file_path: str) -> str:
        """
        Compute SHA-256 hash of a file for integrity verification.
        
        Args:
            file_path: Path to the file
            
        Returns:
            SHA-256 hash of the file
        """
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256()
                for chunk in iter(lambda: f.read(4096), b""):
                    file_hash.update(chunk)
                return file_hash.hexdigest()
        except Exception as e:
            print(f"Warning: Could not compute file hash for {file_path}: {e}")
            return "unknown"
    
    def _validate_log_entry(self, log: Dict[str, Any]) -> bool:
        """
        Validate a CloudTrail log entry for required fields.
        
        Args:
            log: CloudTrail log entry
            
        Returns:
            True if valid, False otherwise
        """
        required_fields = ['eventTime', 'eventName', 'userIdentity']
        
        # Check required fields exist
        for field in required_fields:
            if field not in log:
                return False
        
        # Validate userIdentity structure
        user_identity = log.get('userIdentity', {})
        if not isinstance(user_identity, dict):
            return False
        
        # Check for valid eventTime format
        try:
            event_time = log['eventTime']
            if event_time.endswith('Z'):
                datetime.fromisoformat(event_time.replace('Z', '+00:00'))
            else:
                datetime.fromisoformat(event_time)
        except (ValueError, TypeError):
            return False
        
        return True
    
    def _add_audit_event(self, event_type: str, details: Dict[str, Any]):
        """
        Add an event to the audit trail with Guardian's Mandate integration.
        
        Args:
            event_type: Type of audit event
            details: Event details
        """
        audit_event = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'details': details,
            'guardian_session_id': self.analysis_session_id
        }
        self.audit_metadata['audit_trail'].append(audit_event)
        
        # Also record in Guardian Ledger if enabled
        if self.enable_guardian_mandate:
            self._record_guardian_event(
                event_type=event_type,
                action="audit_event",
                resource="audit_trail",
                details=details,
                evidence_level=EvidenceLevel.HIGH
            )
    
    def _record_guardian_event(self, 
                              event_type: str,
                              action: str,
                              resource: str,
                              details: Dict[str, Any],
                              evidence_level: EvidenceLevel = EvidenceLevel.HIGH,
                              parent_event_id: Optional[str] = None) -> Optional[str]:
        """
        Record an event in the Guardian Ledger with full integrity guarantees.
        
        Args:
            event_type: Type of audit event
            action: Action performed
            resource: Resource accessed/modified
            details: Event details
            evidence_level: Evidence integrity level
            parent_event_id: Parent event ID for chain of custody
            
        Returns:
            Event ID if recorded, None otherwise
        """
        if not self.enable_guardian_mandate or not self.guardian_ledger:
            return None
        
        try:
            # Extract user information from details or use defaults
            user_id = details.get('user_id', 'system')
            session_id = details.get('session_id', self.analysis_session_id)
            source_ip = details.get('source_ip', '127.0.0.1')
            user_agent = details.get('user_agent', 'IAMAnomalyDetector/2.0.0')
            
            event_id = self.guardian_ledger.record_event(
                event_type=event_type,
                user_id=user_id,
                session_id=session_id,
                source_ip=source_ip,
                user_agent=user_agent,
                action=action,
                resource=resource,
                details=details,
                evidence_level=evidence_level,
                parent_event_id=parent_event_id
            )
            
            return event_id
            
        except Exception as e:
            print(f"Warning: Failed to record Guardian event: {e}")
            return None
    
    def filter_logs_by_time_window(self, logs: List[Dict[str, Any]], 
                                  start_time: datetime, 
                                  end_time: datetime) -> List[Dict[str, Any]]:
        """
        Filter logs by time window.
        
        Args:
            logs: List of CloudTrail log entries
            start_time: Start of time window
            end_time: End of time window
            
        Returns:
            Filtered list of logs within the time window
        """
        filtered_logs = []
        
        for log in logs:
            try:
                # Handle timezone-aware datetime parsing
                event_time_str = log['eventTime']
                if event_time_str.endswith('Z'):
                    event_time = datetime.fromisoformat(event_time_str.replace('Z', '+00:00'))
                else:
                    event_time = datetime.fromisoformat(event_time_str)
                
                # Make sure all datetimes are timezone-aware for comparison
                if start_time.tzinfo is None:
                    start_time = start_time.replace(tzinfo=event_time.tzinfo)
                if end_time.tzinfo is None:
                    end_time = end_time.replace(tzinfo=event_time.tzinfo)
                
                if start_time <= event_time <= end_time:
                    filtered_logs.append(log)
            except (KeyError, ValueError) as e:
                print(f"Warning: Skipping log entry with invalid eventTime: {e}")
                continue
                
        return filtered_logs
    
    def build_user_baseline(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Build baseline profiles for each user based on historical activity.
        
        Args:
            logs: List of CloudTrail log entries for baseline period
            
        Returns:
            Dictionary mapping usernames to their baseline profiles
        """
        user_profiles = defaultdict(lambda: {
            'source_ips': set(),
            'aws_regions': set(),
            'event_names': set(),
            'assumed_roles': set(),
            'policy_changes': 0,
            'total_events': 0,
            'first_seen': None,
            'last_seen': None,
            'activity_frequency': defaultdict(int)
        })
        
        for log in logs:
            try:
                user_identity = log.get('userIdentity', {})
                username = user_identity.get('userName', 'Unknown')
                
                if username == 'Unknown':
                    continue
                
                profile = user_profiles[username]
                profile['total_events'] += 1
                
                # Track timestamps
                event_time_str = log['eventTime']
                if event_time_str.endswith('Z'):
                    event_time = datetime.fromisoformat(event_time_str.replace('Z', '+00:00'))
                else:
                    event_time = datetime.fromisoformat(event_time_str)
                
                if profile['first_seen'] is None or event_time < profile['first_seen']:
                    profile['first_seen'] = event_time
                if profile['last_seen'] is None or event_time > profile['last_seen']:
                    profile['last_seen'] = event_time
                
                # Track source IPs
                source_ip = log.get('sourceIPAddress')
                if source_ip and source_ip != '127.0.0.1':
                    profile['source_ips'].add(source_ip)
                
                # Track AWS regions
                aws_region = log.get('awsRegion')
                if aws_region:
                    profile['aws_regions'].add(aws_region)
                
                # Track event names
                event_name = log.get('eventName')
                if event_name:
                    profile['event_names'].add(event_name)
                    profile['activity_frequency'][event_name] += 1
                
                # Track assumed roles
                if event_name == 'AssumeRole':
                    role_arn = log.get('requestParameters', {}).get('roleArn')
                    if role_arn:
                        profile['assumed_roles'].add(role_arn)
                
                # Track policy changes
                if event_name in ['PutUserPolicy', 'AttachUserPolicy', 'DetachUserPolicy', 'DeleteUserPolicy']:
                    profile['policy_changes'] += 1
                    
            except Exception as e:
                print(f"Warning: Error processing log entry for baseline: {e}")
                continue
        
        # Convert sets to lists for JSON serialization
        for username, profile in user_profiles.items():
            profile['source_ips'] = list(profile['source_ips'])
            profile['aws_regions'] = list(profile['aws_regions'])
            profile['event_names'] = list(profile['event_names'])
            profile['assumed_roles'] = list(profile['assumed_roles'])
            profile['activity_frequency'] = dict(profile['activity_frequency'])
            profile['first_seen'] = profile['first_seen'].isoformat() if profile['first_seen'] else None
            profile['last_seen'] = profile['last_seen'].isoformat() if profile['last_seen'] else None
        
        return dict(user_profiles)
    
    def detect_anomalies(self, logs: List[Dict[str, Any]], 
                        user_baselines: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Detect anomalies in CloudTrail logs based on user baselines.
        
        Args:
            logs: List of CloudTrail log entries to analyze
            user_baselines: Dictionary of user baseline profiles
            
        Returns:
            List of detected anomalies
        """
        anomalies = []
        
        for log in logs:
            try:
                user_identity = log.get('userIdentity', {})
                username = user_identity.get('userName', 'Unknown')
                event_name = log.get('eventName')
                source_ip = log.get('sourceIPAddress')
                aws_region = log.get('awsRegion')
                event_time = log.get('eventTime')
                
                if username == 'Unknown' or username not in user_baselines:
                    continue
                
                baseline = user_baselines[username]
                
                # Check for new location/IP anomaly
                if event_name in ['ConsoleLogin', 'AssumeRole']:
                    if source_ip and source_ip not in baseline['source_ips']:
                        anomalies.append({
                            'event_time': event_time,
                            'username': username,
                            'event_name': event_name,
                            'source_ip': source_ip,
                            'aws_region': aws_region,
                            'anomaly_type': 'new_location_ip',
                            'description': f"User '{username}' accessed from new IP address: {source_ip}",
                            'severity': 'medium',
                            'recommendation': 'Investigate user access patterns and verify legitimate access',
                            'compliance_impact': ['SOC2:CC6.1', 'ISO27001:A.9.2.1', 'NIST:AC-2'],
                            'risk_score': 6,
                            'evidence': {
                                'baseline_ips': baseline['source_ips'],
                                'new_ip': source_ip,
                                'user_activity_history': baseline['total_events'],
                                'user_first_seen': baseline.get('first_seen'),
                                'user_last_seen': baseline.get('last_seen'),
                                'total_baseline_events': baseline['total_events'],
                                'baseline_regions': baseline['aws_regions'],
                                'analysis_timestamp': datetime.now().isoformat()
                            }
                        })
                    
                    if aws_region and aws_region not in baseline['aws_regions']:
                        anomalies.append({
                            'event_time': event_time,
                            'username': username,
                            'event_name': event_name,
                            'source_ip': source_ip,
                            'aws_region': aws_region,
                            'anomaly_type': 'new_aws_region',
                            'description': f"User '{username}' accessed from new AWS region: {aws_region}",
                            'severity': 'medium',
                            'recommendation': 'Verify if user should have access to this region',
                            'compliance_impact': ['SOC2:CC6.2', 'ISO27001:A.9.2.2', 'NIST:AC-2'],
                            'risk_score': 5,
                            'evidence': {
                                'baseline_regions': baseline['aws_regions'],
                                'new_region': aws_region,
                                'user_activity_history': baseline['total_events'],
                                'user_first_seen': baseline.get('first_seen'),
                                'user_last_seen': baseline.get('last_seen'),
                                'total_baseline_events': baseline['total_events'],
                                'baseline_ips': baseline['source_ips'],
                                'analysis_timestamp': datetime.now().isoformat()
                            }
                        })
                
                # Check for unusual policy changes
                if event_name in ['PutUserPolicy', 'AttachUserPolicy']:
                    # Flag if user rarely makes policy changes
                    if baseline['policy_changes'] < 2:  # Less than 2 policy changes in baseline
                        anomalies.append({
                            'event_time': event_time,
                            'username': username,
                            'event_name': event_name,
                            'source_ip': source_ip,
                            'aws_region': aws_region,
                            'anomaly_type': 'unusual_policy_change',
                            'description': f"User '{username}' made policy change (rare activity for this user)",
                            'severity': 'high',
                            'recommendation': 'Review policy changes and verify legitimate need',
                            'compliance_impact': ['SOC2:CC6.3', 'ISO27001:A.9.2.3', 'NIST:AC-6'],
                            'risk_score': 8,
                            'evidence': {
                                'baseline_policy_changes': baseline['policy_changes'],
                                'total_user_events': baseline['total_events'],
                                'policy_change_frequency': baseline['policy_changes'] / max(baseline['total_events'], 1),
                                'user_first_seen': baseline.get('first_seen'),
                                'user_last_seen': baseline.get('last_seen'),
                                'user_activity_frequency': baseline.get('activity_frequency', {}),
                                'analysis_timestamp': datetime.now().isoformat()
                            }
                        })
                    
                    # Check for overly permissive policies
                    request_params = log.get('requestParameters', {})
                    policy_document = request_params.get('policyDocument', '')
                    if '*' in policy_document:
                        anomalies.append({
                            'event_time': event_time,
                            'username': username,
                            'event_name': event_name,
                            'source_ip': source_ip,
                            'aws_region': aws_region,
                            'anomaly_type': 'overly_permissive_policy',
                            'description': f"User '{username}' created/attached policy with wildcard permissions (*)",
                            'severity': 'critical',
                            'recommendation': 'Immediately review and restrict overly permissive policy',
                            'compliance_impact': ['SOC2:CC6.3', 'ISO27001:A.9.2.3', 'NIST:AC-6', 'CIS:1.3'],
                            'risk_score': 10,
                            'evidence': {
                                'policy_document': policy_document,
                                'wildcard_detected': True,
                                'user_privilege_level': 'high' if baseline['policy_changes'] > 5 else 'medium',
                                'user_first_seen': baseline.get('first_seen'),
                                'user_last_seen': baseline.get('last_seen'),
                                'baseline_policy_changes': baseline['policy_changes'],
                                'total_user_events': baseline['total_events'],
                                'analysis_timestamp': datetime.now().isoformat()
                            }
                        })
                
                # Check for first-time role assumption
                if event_name == 'AssumeRole':
                    role_arn = log.get('requestParameters', {}).get('roleArn')
                    if role_arn and role_arn not in baseline['assumed_roles']:
                        anomalies.append({
                            'event_time': event_time,
                            'username': username,
                            'event_name': event_name,
                            'source_ip': source_ip,
                            'aws_region': aws_region,
                            'anomaly_type': 'first_time_role_assumption',
                            'description': f"User '{username}' assumed role for the first time: {role_arn}",
                            'severity': 'medium',
                            'recommendation': 'Verify role assumption is legitimate and review role permissions',
                            'compliance_impact': ['SOC2:CC6.2', 'ISO27001:A.9.2.2', 'NIST:AC-3'],
                            'risk_score': 7,
                            'evidence': {
                                'baseline_roles': baseline['assumed_roles'],
                                'new_role': role_arn,
                                'user_role_history': len(baseline['assumed_roles']),
                                'user_first_seen': baseline.get('first_seen'),
                                'user_last_seen': baseline.get('last_seen'),
                                'total_user_events': baseline['total_events'],
                                'user_activity_frequency': baseline.get('activity_frequency', {}),
                                'analysis_timestamp': datetime.now().isoformat()
                            }
                        })
                
                # Check for unusual event types
                if event_name and event_name not in baseline['event_names']:
                    anomalies.append({
                        'event_time': event_time,
                        'username': username,
                        'event_name': event_name,
                        'source_ip': source_ip,
                        'aws_region': aws_region,
                        'anomaly_type': 'unusual_event_type',
                        'description': f"User '{username}' performed unusual event: {event_name}",
                        'severity': 'low',
                        'recommendation': 'Review if this event type is expected for this user',
                        'compliance_impact': ['SOC2:CC6.1', 'ISO27001:A.9.2.1', 'NIST:AC-2'],
                        'risk_score': 3,
                        'evidence': {
                            'baseline_events': baseline['event_names'],
                            'new_event': event_name,
                            'user_event_history': baseline['total_events'],
                            'user_first_seen': baseline.get('first_seen'),
                            'user_last_seen': baseline.get('last_seen'),
                            'user_activity_frequency': baseline.get('activity_frequency', {}),
                            'analysis_timestamp': datetime.now().isoformat()
                        }
                    })
                    
            except Exception as e:
                print(f"Warning: Error processing log entry for anomaly detection: {e}")
                continue
        
        # Record anomaly detection summary in Guardian Ledger
        if self.enable_guardian_mandate and anomalies:
            self._record_guardian_event(
                event_type=AuditEventType.SECURITY_EVENT.value,
                action="anomaly_detection_complete",
                resource="cloudtrail_analysis",
                details={
                    "total_anomalies_detected": len(anomalies),
                    "anomaly_types": list(set(a.get('anomaly_type', 'unknown') for a in anomalies)),
                    "severity_distribution": {
                        severity: len([a for a in anomalies if a.get('severity') == severity])
                        for severity in ['critical', 'high', 'medium', 'low']
                    },
                    "users_affected": list(set(a.get('username', 'unknown') for a in anomalies)),
                    "analysis_session_id": self.analysis_session_id,
                    "detection_timestamp": datetime.now().isoformat()
                },
                evidence_level=EvidenceLevel.CRITICAL
            )
            
            # Record each individual anomaly for chain of custody
            for anomaly in anomalies:
                self._record_guardian_event(
                    event_type=AuditEventType.SECURITY_EVENT.value,
                    action="anomaly_detected",
                    resource=f"user:{anomaly.get('username', 'unknown')}",
                    details={
                        "anomaly_id": str(uuid.uuid4()),
                        "anomaly_type": anomaly.get('anomaly_type'),
                        "severity": anomaly.get('severity'),
                        "username": anomaly.get('username'),
                        "event_name": anomaly.get('event_name'),
                        "source_ip": anomaly.get('source_ip'),
                        "aws_region": anomaly.get('aws_region'),
                        "description": anomaly.get('description'),
                        "risk_score": anomaly.get('risk_score'),
                        "compliance_impact": anomaly.get('compliance_impact', []),
                        "evidence": anomaly.get('evidence', {}),
                        "analysis_session_id": self.analysis_session_id
                    },
                    evidence_level=EvidenceLevel.CRITICAL
                )
        
        return anomalies
    
    def generate_audit_report(self, anomalies: List[Dict[str, Any]], 
                            user_baselines: Dict[str, Any],
                            analysis_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a comprehensive audit report suitable for compliance purposes.
        
        Args:
            anomalies: List of detected anomalies
            user_baselines: Dictionary of user baseline profiles
            analysis_metadata: Metadata about the analysis
            
        Returns:
            Structured audit report
        """
        report = {
            'audit_metadata': {
                'report_generated': datetime.now().isoformat(),
                'tool_version': '1.0.0',
                'analysis_parameters': analysis_metadata,
                'compliance_frameworks': self.audit_metadata['compliance_frameworks'],
                'audit_trail': self.audit_metadata['audit_trail'],
                'data_quality': self._assess_data_quality(user_baselines, analysis_metadata)
            },
            'executive_summary': {
                'total_anomalies': len(anomalies),
                'critical_anomalies': len([a for a in anomalies if a['severity'] == 'critical']),
                'high_anomalies': len([a for a in anomalies if a['severity'] == 'high']),
                'medium_anomalies': len([a for a in anomalies if a['severity'] == 'medium']),
                'low_anomalies': len([a for a in anomalies if a['severity'] == 'low']),
                'total_users_analyzed': len(user_baselines),
                'overall_risk_level': self._calculate_overall_risk(anomalies)
            },
            'compliance_assessment': {
                'soc2': self._assess_soc2_compliance(anomalies),
                'iso27001': self._assess_iso27001_compliance(anomalies),
                'nist': self._assess_nist_compliance(anomalies),
                'cis': self._assess_cis_compliance(anomalies)
            },
            'detailed_findings': {
                'anomalies': anomalies,
                'user_baselines': user_baselines
            },
            'recommendations': self._generate_recommendations(anomalies),
            'risk_assessment': self._generate_risk_assessment(anomalies)
        }
        
        return report
    
    def _calculate_overall_risk(self, anomalies: List[Dict[str, Any]]) -> str:
        """Calculate overall risk level based on anomalies."""
        if not anomalies:
            return 'LOW'
        
        # Count anomalies by severity
        severity_counts = defaultdict(int)
        for anomaly in anomalies:
            severity_counts[anomaly.get('severity', 'low')] += 1
        
        # Determine overall risk based on highest severity and count
        if severity_counts.get('critical', 0) > 0:
            return 'CRITICAL'
        elif severity_counts.get('high', 0) > 0:
            return 'HIGH'
        elif severity_counts.get('medium', 0) > 0:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _assess_soc2_compliance(self, anomalies: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess SOC2 compliance based on anomalies."""
        controls = {
            'CC6.1': {'status': 'COMPLIANT', 'findings': []},
            'CC6.2': {'status': 'COMPLIANT', 'findings': []},
            'CC6.3': {'status': 'COMPLIANT', 'findings': []}
        }
        
        for anomaly in anomalies:
            for control in anomaly.get('compliance_impact', []):
                if control.startswith('SOC2:'):
                    control_id = control.split(':')[1]
                    if control_id in controls:
                        controls[control_id]['status'] = 'NON_COMPLIANT'
                        controls[control_id]['findings'].append({
                            'anomaly_type': anomaly['anomaly_type'],
                            'severity': anomaly['severity'],
                            'description': anomaly['description']
                        })
        
        return controls
    
    def _assess_iso27001_compliance(self, anomalies: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess ISO27001 compliance based on anomalies."""
        controls = {
            'A.9.2.1': {'status': 'COMPLIANT', 'findings': []},
            'A.9.2.2': {'status': 'COMPLIANT', 'findings': []},
            'A.9.2.3': {'status': 'COMPLIANT', 'findings': []}
        }
        
        for anomaly in anomalies:
            for control in anomaly.get('compliance_impact', []):
                if control.startswith('ISO27001:'):
                    control_id = control.split(':')[1]
                    if control_id in controls:
                        controls[control_id]['status'] = 'NON_COMPLIANT'
                        controls[control_id]['findings'].append({
                            'anomaly_type': anomaly['anomaly_type'],
                            'severity': anomaly['severity'],
                            'description': anomaly['description']
                        })
        
        return controls
    
    def _assess_nist_compliance(self, anomalies: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess NIST compliance based on anomalies."""
        controls = {
            'AC-2': {'status': 'COMPLIANT', 'findings': []},
            'AC-3': {'status': 'COMPLIANT', 'findings': []},
            'AC-6': {'status': 'COMPLIANT', 'findings': []}
        }
        
        for anomaly in anomalies:
            for control in anomaly.get('compliance_impact', []):
                if control.startswith('NIST:'):
                    control_id = control.split(':')[1]
                    if control_id in controls:
                        controls[control_id]['status'] = 'NON_COMPLIANT'
                        controls[control_id]['findings'].append({
                            'anomaly_type': anomaly['anomaly_type'],
                            'severity': anomaly['severity'],
                            'description': anomaly['description']
                        })
        
        return controls
    
    def _assess_cis_compliance(self, anomalies: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess CIS compliance based on anomalies."""
        controls = {
            '1.1': {'status': 'COMPLIANT', 'findings': []},
            '1.2': {'status': 'COMPLIANT', 'findings': []},
            '1.3': {'status': 'COMPLIANT', 'findings': []}
        }
        
        for anomaly in anomalies:
            for control in anomaly.get('compliance_impact', []):
                if control.startswith('CIS:'):
                    control_id = control.split(':')[1]
                    if control_id in controls:
                        controls[control_id]['status'] = 'NON_COMPLIANT'
                        controls[control_id]['findings'].append({
                            'anomaly_type': anomaly['anomaly_type'],
                            'severity': anomaly['severity'],
                            'description': anomaly['description']
                        })
        
        return controls
    
    def _generate_recommendations(self, anomalies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate prioritized recommendations based on anomalies."""
        recommendations = []
        
        # Group by anomaly type
        anomaly_groups = defaultdict(list)
        for anomaly in anomalies:
            anomaly_groups[anomaly['anomaly_type']].append(anomaly)
        
        for anomaly_type, group in anomaly_groups.items():
            severity = max(a['severity'] for a in group)
            risk_score = max(a.get('risk_score', 0) for a in group)
            
            recommendations.append({
                'priority': 'HIGH' if severity in ['critical', 'high'] else 'MEDIUM',
                'category': anomaly_type.replace('_', ' ').title(),
                'description': f"Address {len(group)} {anomaly_type.replace('_', ' ')} anomaly(ies)",
                'action_items': [a['recommendation'] for a in group],
                'affected_users': list(set(a['username'] for a in group)),
                'risk_score': risk_score
            })
        
        # Sort by priority and risk score
        recommendations.sort(key=lambda x: (x['priority'] == 'HIGH', -x['risk_score']), reverse=True)
        
        return recommendations
    
    def _generate_risk_assessment(self, anomalies: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate detailed risk assessment."""
        if not anomalies:
            return {'overall_risk': 'LOW', 'risk_factors': []}
        
        risk_factors = []
        total_risk_score = 0
        
        for anomaly in anomalies:
            risk_score = anomaly.get('risk_score', 0)
            total_risk_score += risk_score
            
            risk_factors.append({
                'factor': anomaly['anomaly_type'],
                'severity': anomaly['severity'],
                'risk_score': risk_score,
                'description': anomaly['description'],
                'affected_user': anomaly['username']
            })
        
        avg_risk_score = total_risk_score / len(anomalies)
        
        return {
            'overall_risk': self._calculate_overall_risk(anomalies),
            'average_risk_score': round(avg_risk_score, 2),
            'total_risk_score': total_risk_score,
            'risk_factors': sorted(risk_factors, key=lambda x: x['risk_score'], reverse=True)
        }
    
    def _assess_data_quality(self, user_baselines: Dict[str, Any], 
                           analysis_metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Assess the quality of data used for analysis.
        
        Args:
            user_baselines: Dictionary of user baseline profiles
            analysis_metadata: Metadata about the analysis
            
        Returns:
            Data quality assessment
        """
        if not user_baselines:
            return {
                'overall_quality': 'POOR',
                'issues': ['No user baselines available'],
                'recommendations': ['Ensure sufficient baseline data is available']
            }
        
        issues = []
        recommendations = []
        
        # Check baseline data sufficiency
        total_baseline_events = sum(baseline.get('total_events', 0) for baseline in user_baselines.values())
        if total_baseline_events < 10:
            issues.append('Limited baseline data available')
            recommendations.append('Extend baseline period or include more historical data')
        
        # Check user coverage
        users_with_minimal_data = sum(1 for baseline in user_baselines.values() if baseline.get('total_events', 0) < 3)
        if users_with_minimal_data > 0:
            issues.append(f'{users_with_minimal_data} users have minimal baseline data')
            recommendations.append('Ensure all users have sufficient activity history')
        
        # Check time coverage
        baseline_days = analysis_metadata.get('baseline_days', 30)
        if baseline_days < 14:
            issues.append('Baseline period may be too short')
            recommendations.append('Consider extending baseline period to at least 30 days')
        
        # Determine overall quality
        if len(issues) == 0:
            overall_quality = 'EXCELLENT'
        elif len(issues) <= 2:
            overall_quality = 'GOOD'
        elif len(issues) <= 4:
            overall_quality = 'FAIR'
        else:
            overall_quality = 'POOR'
        
        return {
            'overall_quality': overall_quality,
            'total_users': len(user_baselines),
            'total_baseline_events': total_baseline_events,
            'average_events_per_user': round(total_baseline_events / len(user_baselines), 2) if user_baselines else 0,
            'baseline_days': baseline_days,
            'issues': issues,
            'recommendations': recommendations
        }
    
    def export_to_csv(self, anomalies: List[Dict[str, Any]], output_file: str):
        """Export anomalies to CSV format for audit evidence."""
        if not anomalies:
            print("No anomalies to export.")
            return
        
        fieldnames = [
            'event_time', 'username', 'event_name', 'source_ip', 'aws_region',
            'anomaly_type', 'severity', 'description', 'recommendation',
            'risk_score', 'compliance_impact'
        ]
        
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for anomaly in anomalies:
                row = {
                    'event_time': anomaly['event_time'],
                    'username': anomaly['username'],
                    'event_name': anomaly['event_name'],
                    'source_ip': anomaly['source_ip'],
                    'aws_region': anomaly['aws_region'],
                    'anomaly_type': anomaly['anomaly_type'],
                    'severity': anomaly['severity'],
                    'description': anomaly['description'],
                    'recommendation': anomaly['recommendation'],
                    'risk_score': anomaly.get('risk_score', 0),
                    'compliance_impact': '; '.join(anomaly.get('compliance_impact', []))
                }
                writer.writerow(row)
        
        print(f"Anomalies exported to {output_file}")
    
    def print_anomalies(self, anomalies: List[Dict[str, Any]]):
        """
        Print detected anomalies in a formatted way.
        
        Args:
            anomalies: List of detected anomalies
        """
        if not anomalies:
            print("✅ No anomalies detected!")
            return
        
        print(f"\n🚨 {len(anomalies)} Anomaly(ies) Detected:\n")
        print("=" * 80)
        
        for i, anomaly in enumerate(anomalies, 1):
            severity_emoji = {
                'low': '🟡',
                'medium': '🟠', 
                'high': '🔴',
                'critical': '🚨'
            }.get(anomaly['severity'], '❓')
            
            print(f"{i}. {severity_emoji} {anomaly['anomaly_type'].replace('_', ' ').title()}")
            print(f"   Time: {anomaly['event_time']}")
            print(f"   User: {anomaly['username']}")
            print(f"   Event: {anomaly['event_name']}")
            print(f"   Source IP: {anomaly['source_ip']}")
            print(f"   AWS Region: {anomaly['aws_region']}")
            print(f"   Risk Score: {anomaly.get('risk_score', 'N/A')}")
            print(f"   Compliance: {', '.join(anomaly.get('compliance_impact', []))}")
            print(f"   Description: {anomaly['description']}")
            print(f"   Recommendation: {anomaly['recommendation']}")
            print("-" * 80)
    
    def run_analysis(self, log_file: str, detection_days: int = 1, 
                    output_format: str = 'console', output_file: str = None):
        """
        Run the complete anomaly detection analysis.
        
        Args:
            log_file: Path to the CloudTrail log file
            detection_days: Number of days to analyze for anomalies
            output_format: Output format ('console', 'json', 'csv', 'audit')
            output_file: Output file path (required for non-console formats)
        """
        print("🔍 Cloud IAM Behavioral Anomaly Detector")
        print("=" * 50)
        
        # Initialize audit trail
        self._add_audit_event("analysis_started", {
            "log_file": log_file,
            "detection_days": detection_days,
            "output_format": output_format,
            "baseline_days": self.baseline_days
        })
        
        # Load logs
        print(f"📁 Loading CloudTrail logs from: {log_file}")
        all_logs = self.load_cloudtrail_logs(log_file)
        print(f"   Loaded {len(all_logs)} log entries")
        
        self._add_audit_event("logs_loaded", {
            "total_logs": len(all_logs),
            "log_file": log_file
        })
        
        # Calculate time windows
        end_time = datetime.now()
        detection_start = end_time - timedelta(days=detection_days)
        baseline_start = detection_start - timedelta(days=self.baseline_days)
        
        analysis_metadata = {
            'baseline_days': self.baseline_days,
            'detection_days': detection_days,
            'baseline_start': baseline_start.isoformat(),
            'baseline_end': detection_start.isoformat(),
            'detection_start': detection_start.isoformat(),
            'detection_end': end_time.isoformat(),
            'total_logs_processed': len(all_logs)
        }
        
        print(f"\n⏰ Time Windows:")
        print(f"   Baseline period: {baseline_start.strftime('%Y-%m-%d %H:%M:%S')} to {detection_start.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"   Detection period: {detection_start.strftime('%Y-%m-%d %H:%M:%S')} to {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Filter logs for baseline and detection periods
        baseline_logs = self.filter_logs_by_time_window(all_logs, baseline_start, detection_start)
        detection_logs = self.filter_logs_by_time_window(all_logs, detection_start, end_time)
        
        print(f"\n📊 Baseline Analysis:")
        print(f"   {len(baseline_logs)} log entries in baseline period")
        
        # Build user baselines
        user_baselines = self.build_user_baseline(baseline_logs)
        print(f"   Built baselines for {len(user_baselines)} users")
        
        self._add_audit_event("baseline_built", {
            "baseline_logs": len(baseline_logs),
            "users_with_baselines": len(user_baselines),
            "baseline_start": baseline_start.isoformat(),
            "baseline_end": detection_start.isoformat()
        })
        
        print(f"\n🔍 Anomaly Detection:")
        print(f"   {len(detection_logs)} log entries in detection period")
        
        # Detect anomalies
        anomalies = self.detect_anomalies(detection_logs, user_baselines)
        
        self._add_audit_event("anomalies_detected", {
            "detection_logs": len(detection_logs),
            "anomalies_found": len(anomalies),
            "detection_start": detection_start.isoformat(),
            "detection_end": end_time.isoformat()
        })
        
        # Generate output based on format
        if output_format == 'console':
            self.print_anomalies(anomalies)
        elif output_format == 'json':
            if not output_file:
                output_file = 'anomaly_report.json'
            report = {
                'anomalies': anomalies,
                'metadata': analysis_metadata,
                'user_baselines': user_baselines
            }
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"JSON report saved to {output_file}")
        elif output_format == 'csv':
            if not output_file:
                output_file = 'anomaly_report.csv'
            self.export_to_csv(anomalies, output_file)
        elif output_format == 'audit':
            if not output_file:
                output_file = 'audit_report.json'
            audit_report = self.generate_audit_report(anomalies, user_baselines, analysis_metadata)
            with open(output_file, 'w') as f:
                json.dump(audit_report, f, indent=2)
            print(f"Audit report saved to {output_file}")
        
        print(f"\n📈 Summary:")
        print(f"   Total log entries processed: {len(all_logs)}")
        print(f"   Users with baselines: {len(user_baselines)}")
        print(f"   Anomalies detected: {len(anomalies)}")
        
        if anomalies:
            severity_counts = defaultdict(int)
            for anomaly in anomalies:
                severity_counts[anomaly['severity']] += 1
            
            print(f"   Severity breakdown:")
            for severity, count in sorted(severity_counts.items(), key=lambda x: ['critical', 'high', 'medium', 'low'].index(x[0])):
                print(f"     {severity.title()}: {count}")
        
        # Final audit event
        self._add_audit_event("analysis_completed", {
            "total_logs_processed": len(all_logs),
            "users_with_baselines": len(user_baselines),
            "anomalies_detected": len(anomalies),
            "output_format": output_format,
            "output_file": output_file,
            "severity_breakdown": dict(severity_counts) if anomalies else {}
        })
        
        # Guardian's Mandate: Integrity verification and forensic export
        if self.enable_guardian_mandate:
            print(f"\n🛡️  Guardian's Mandate: Digital Evidence Integrity")
            print("=" * 50)
            
            # Verify ledger integrity
            print("🔍 Verifying cryptographic integrity...")
            integrity_result = self.guardian_ledger.verify_integrity()
            
            if integrity_result['verified']:
                print(f"✅ Integrity verification: PASSED")
                print(f"   Verified blocks: {integrity_result['verified_blocks']}/{integrity_result['total_blocks']}")
                print(f"   Chain hashes: {len(integrity_result['chain_hashes'])}")
                print(f"   Timestamp range: {integrity_result['timestamp_range']['start']} to {integrity_result['timestamp_range']['end']}")
            else:
                print(f"❌ Integrity verification: FAILED")
                print(f"   Errors: {len(integrity_result['errors'])}")
                for error in integrity_result['errors']:
                    print(f"     - {error}")
            
            # Export forensic data
            print("\n📋 Exporting forensic data...")
            forensic_file = f"guardian_forensic_{self.analysis_session_id}.json"
            export_path = self.guardian_ledger.export_forensic_data(forensic_file)
            print(f"✅ Forensic data exported to: {export_path}")
            
            # Generate chain of custody report
            if anomalies:
                print("\n🔗 Chain of Custody Report:")
                for i, anomaly in enumerate(anomalies[:5], 1):  # Show first 5 anomalies
                    username = anomaly.get('username', 'unknown')
                    anomaly_type = anomaly.get('anomaly_type', 'unknown')
                    print(f"   {i}. User: {username} - Type: {anomaly_type}")
                    print(f"      Evidence recorded in Guardian Ledger with cryptographic proof")
                
                if len(anomalies) > 5:
                    print(f"   ... and {len(anomalies) - 5} more anomalies")
            
            print(f"\n🛡️  Guardian's Mandate Summary:")
            print(f"   Session ID: {self.analysis_session_id}")
            print(f"   Evidence Integrity: {'CRITICAL' if integrity_result['verified'] else 'COMPROMISED'}")
            print(f"   Chain of Custody: {'VERIFIED' if integrity_result['verified'] else 'BROKEN'}")
            print(f"   Forensic Export: {export_path}")
            print(f"   Compliance Ready: {'YES' if integrity_result['verified'] else 'NO'}")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Cloud IAM Behavioral Anomaly Detector - Audit & Compliance Ready",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --log-file mock_cloudtrail_logs.json
  %(prog)s --log-file mock_cloudtrail_logs.json --baseline-days 60 --detection-days 7
  %(prog)s --log-file mock_cloudtrail_logs.json --output-format json --output-file report.json
  %(prog)s --log-file mock_cloudtrail_logs.json --output-format audit --output-file audit_report.json
  %(prog)s --log-file mock_cloudtrail_logs.json --output-format csv --output-file findings.csv
        """
    )
    
    parser.add_argument(
        '--log-file',
        required=True,
        help='Path to the CloudTrail log JSON file'
    )
    
    parser.add_argument(
        '--baseline-days',
        type=int,
        default=30,
        help='Number of days to use for building user baselines (default: 30)'
    )
    
    parser.add_argument(
        '--detection-days',
        type=int,
        default=1,
        help='Number of days to analyze for anomalies (default: 1)'
    )
    
    parser.add_argument(
        '--output-format',
        choices=['console', 'json', 'csv', 'audit'],
        default='console',
        help='Output format (default: console)'
    )
    
    parser.add_argument(
        '--output-file',
        help='Output file path (required for non-console formats)'
    )
    
    parser.add_argument(
        '--disable-guardian-mandate',
        action='store_true',
        help='Disable Guardian\'s Mandate digital evidence integrity features'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s 2.0.0 (with Guardian\'s Mandate)'
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.baseline_days <= 0 or args.detection_days <= 0:
        print("Error: Baseline and detection days must be positive integers.")
        sys.exit(1)
    
    if args.output_format != 'console' and not args.output_file:
        print(f"Error: Output file is required for {args.output_format} format.")
        sys.exit(1)
    
    # Check Guardian's Mandate availability
    if not args.disable_guardian_mandate and not GUARDIAN_MANDATE_AVAILABLE:
        print("Warning: Guardian's Mandate framework not available. Running in legacy mode.")
        print("Install required dependencies: pip install -r guardians_mandate_requirements.txt")
    
    # Run analysis
    enable_guardian = not args.disable_guardian_mandate and GUARDIAN_MANDATE_AVAILABLE
    detector = IAMAnomalyDetector(
        baseline_days=args.baseline_days,
        enable_guardian_mandate=enable_guardian
    )
    detector.run_analysis(args.log_file, args.detection_days, args.output_format, args.output_file)


if __name__ == '__main__':
    main()