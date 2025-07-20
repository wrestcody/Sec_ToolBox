#!/usr/bin/env python3
"""
Cloud IAM Behavioral Anomaly Detector

A CLI tool that analyzes AWS CloudTrail logs for unusual IAM activity patterns
that could indicate a compromised identity or privilege escalation.

This is a proof-of-concept tool that uses simulated/mock data only.
"""

import argparse
import json
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Set, Any, Optional
from collections import defaultdict
import ipaddress


class IAMAnomalyDetector:
    """Main class for detecting IAM behavioral anomalies."""
    
    def __init__(self, baseline_days: int = 30):
        """
        Initialize the anomaly detector.
        
        Args:
            baseline_days: Number of days to use for building user baselines
        """
        self.baseline_days = baseline_days
        self.user_baselines = {}
        self.anomalies = []
        
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
                return logs['Records']
            elif isinstance(logs, list):
                return logs
            else:
                raise ValueError("Invalid CloudTrail log format")
                
        except FileNotFoundError:
            print(f"Error: Log file '{log_file}' not found.")
            sys.exit(1)
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON in log file '{log_file}'.")
            sys.exit(1)
        except Exception as e:
            print(f"Error loading logs: {e}")
            sys.exit(1)
    
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
                event_time = datetime.fromisoformat(log['eventTime'].replace('Z', '+00:00'))
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
            'total_events': 0
        })
        
        for log in logs:
            try:
                user_identity = log.get('userIdentity', {})
                username = user_identity.get('userName', 'Unknown')
                
                if username == 'Unknown':
                    continue
                
                profile = user_profiles[username]
                profile['total_events'] += 1
                
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
                            'recommendation': 'Investigate user access patterns and verify legitimate access'
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
                            'recommendation': 'Verify if user should have access to this region'
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
                            'recommendation': 'Review policy changes and verify legitimate need'
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
                            'recommendation': 'Immediately review and restrict overly permissive policy'
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
                            'recommendation': 'Verify role assumption is legitimate and review role permissions'
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
                        'recommendation': 'Review if this event type is expected for this user'
                    })
                    
            except Exception as e:
                print(f"Warning: Error processing log entry for anomaly detection: {e}")
                continue
        
        return anomalies
    
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
            print(f"   Description: {anomaly['description']}")
            print(f"   Recommendation: {anomaly['recommendation']}")
            print("-" * 80)
    
    def run_analysis(self, log_file: str, detection_days: int = 1):
        """
        Run the complete anomaly detection analysis.
        
        Args:
            log_file: Path to the CloudTrail log file
            detection_days: Number of days to analyze for anomalies
        """
        print("🔍 Cloud IAM Behavioral Anomaly Detector")
        print("=" * 50)
        
        # Load logs
        print(f"📁 Loading CloudTrail logs from: {log_file}")
        all_logs = self.load_cloudtrail_logs(log_file)
        print(f"   Loaded {len(all_logs)} log entries")
        
        # Calculate time windows
        end_time = datetime.now()
        detection_start = end_time - timedelta(days=detection_days)
        baseline_start = detection_start - timedelta(days=self.baseline_days)
        
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
        
        print(f"\n🔍 Anomaly Detection:")
        print(f"   {len(detection_logs)} log entries in detection period")
        
        # Detect anomalies
        anomalies = self.detect_anomalies(detection_logs, user_baselines)
        
        # Print results
        self.print_anomalies(anomalies)
        
        print(f"\n📈 Summary:")
        print(f"   Total log entries processed: {len(all_logs)}")
        print(f"   Users with baselines: {len(user_baselines)}")
        print(f"   Anomalies detected: {len(anomalies)}")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Cloud IAM Behavioral Anomaly Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --log-file mock_cloudtrail_logs.json
  %(prog)s --log-file mock_cloudtrail_logs.json --baseline-days 60 --detection-days 7
  %(prog)s --log-file mock_cloudtrail_logs.json --detection-days 24
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
        '--version',
        action='version',
        version='%(prog)s 1.0.0'
    )
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.baseline_days <= 0 or args.detection_days <= 0:
        print("Error: Baseline and detection days must be positive integers.")
        sys.exit(1)
    
    # Run analysis
    detector = IAMAnomalyDetector(baseline_days=args.baseline_days)
    detector.run_analysis(args.log_file, args.detection_days)


if __name__ == '__main__':
    main()