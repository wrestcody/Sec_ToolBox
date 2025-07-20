#!/usr/bin/env python3
"""
Cloud Compliance Evidence Scraper

A CLI tool that automates the collection of specific configuration and log data
from AWS (and conceptually other clouds) that serves as auditable evidence for
common compliance controls.

This tool performs READ-ONLY operations and should never modify cloud configurations.
"""

import argparse
import json
import logging
import os
import sys
import yaml
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError


class ComplianceEvidenceScraper:
    """Main class for collecting compliance evidence from AWS."""
    
    def __init__(self, config_path: str, region: str = 'us-east-1'):
        """
        Initialize the scraper with configuration and AWS region.
        
        Args:
            config_path: Path to the controls mapping YAML file
            region: AWS region to use for API calls
        """
        self.config_path = Path(config_path)
        self.region = region
        self.controls_mapping = self._load_controls_mapping()
        self.aws_clients = self._initialize_aws_clients()
        self.evidence_collected = []
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def _load_controls_mapping(self) -> Dict[str, Any]:
        """Load the controls mapping from YAML file."""
        try:
            # Validate file path to prevent path traversal
            config_path = Path(self.config_path).resolve()
            if not config_path.exists():
                self.logger.error(f"Controls mapping file not found: {self.config_path}")
                sys.exit(1)
            
            # Check file size to prevent DoS attacks
            if config_path.stat().st_size > 1024 * 1024:  # 1MB limit
                self.logger.error("Configuration file too large (max 1MB)")
                sys.exit(1)
            
            with open(config_path, 'r') as file:
                config = yaml.safe_load(file)
                
            # Validate required configuration structure
            if not isinstance(config, dict):
                self.logger.error("Invalid configuration format: must be a dictionary")
                sys.exit(1)
                
            required_keys = ['metadata', 'controls', 'evidence_methods']
            for key in required_keys:
                if key not in config:
                    self.logger.error(f"Missing required configuration section: {key}")
                    sys.exit(1)
                    
            return config
            
        except FileNotFoundError:
            self.logger.error(f"Controls mapping file not found: {self.config_path}")
            sys.exit(1)
        except yaml.YAMLError as e:
            self.logger.error(f"Error parsing YAML file: {e}")
            sys.exit(1)
        except Exception as e:
            self.logger.error(f"Unexpected error loading configuration: {e}")
            sys.exit(1)
    
    def _initialize_aws_clients(self) -> Dict[str, Any]:
        """Initialize AWS service clients."""
        try:
            session = boto3.Session(region_name=self.region)
            return {
                'iam': session.client('iam'),
                's3': session.client('s3'),
                'cloudtrail': session.client('cloudtrail'),
                'cloudwatch': session.client('cloudwatch'),
                'rds': session.client('rds'),
                'ec2': session.client('ec2'),
                'sts': session.client('sts')
            }
        except NoCredentialsError:
            self.logger.error("AWS credentials not found. Please configure your AWS credentials.")
            sys.exit(1)
    
    def _collect_iam_evidence(self, control: Dict[str, Any]) -> Dict[str, Any]:
        """Collect IAM-related evidence for compliance controls."""
        evidence = {
            'control_id': control['id'],
            'control_name': control['name'],
            'evidence_type': 'iam',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'data': {}
        }
        
        try:
            # Check MFA status for root account
            if 'mfa_root_check' in control.get('checks', []):
                try:
                    account_summary = self.aws_clients['iam'].get_account_summary()
                    mfa_enabled = account_summary['SummaryMap'].get('AccountMFAEnabled', 0)
                    evidence['data']['root_mfa_enabled'] = bool(mfa_enabled)
                    evidence['data']['root_mfa_status'] = 'Enabled' if mfa_enabled else 'Disabled'
                except ClientError as e:
                    evidence['data']['root_mfa_error'] = str(e)
            
            # Check IAM password policy
            if 'password_policy_check' in control.get('checks', []):
                try:
                    password_policy = self.aws_clients['iam'].get_account_password_policy()
                    evidence['data']['password_policy'] = password_policy['PasswordPolicy']
                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchEntity':
                        evidence['data']['password_policy'] = 'No password policy configured'
                    else:
                        evidence['data']['password_policy_error'] = str(e)
            
            # Check for admin users
            if 'admin_users_check' in control.get('checks', []):
                try:
                    admin_users = []
                    paginator = self.aws_clients['iam'].get_paginator('list_users')
                    for page in paginator.paginate():
                        for user in page['Users']:
                            # Check if user has admin policy attached
                            attached_policies = self.aws_clients['iam'].list_attached_user_policies(
                                UserName=user['UserName']
                            )
                            for policy in attached_policies['AttachedPolicies']:
                                if 'AdministratorAccess' in policy['PolicyName']:
                                    admin_users.append({
                                        'username': user['UserName'],
                                        'policy': policy['PolicyName']
                                    })
                    evidence['data']['admin_users'] = admin_users
                    evidence['data']['admin_users_count'] = len(admin_users)
                except ClientError as e:
                    evidence['data']['admin_users_error'] = str(e)
                    
        except Exception as e:
            evidence['error'] = str(e)
            self.logger.error(f"Error collecting IAM evidence for {control['id']}: {e}")
        
        return evidence
    
    def _collect_s3_evidence(self, control: Dict[str, Any]) -> Dict[str, Any]:
        """Collect S3-related evidence for compliance controls."""
        evidence = {
            'control_id': control['id'],
            'control_name': control['name'],
            'evidence_type': 's3',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'data': {}
        }
        
        try:
            # Check S3 bucket encryption
            if 'bucket_encryption_check' in control.get('checks', []):
                try:
                    buckets = []
                    paginator = self.aws_clients['s3'].get_paginator('list_buckets')
                    for page in paginator.paginate():
                        for bucket in page['Buckets']:
                            bucket_name = bucket['Name']
                            bucket_info = {
                                'name': bucket_name,
                                'creation_date': bucket['CreationDate'].isoformat()
                            }
                            
                            # Check encryption status
                            try:
                                encryption = self.aws_clients['s3'].get_bucket_encryption(
                                    Bucket=bucket_name
                                )
                                bucket_info['encryption_enabled'] = True
                                bucket_info['encryption_algorithm'] = encryption['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm']
                            except ClientError as e:
                                if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                                    bucket_info['encryption_enabled'] = False
                                    bucket_info['encryption_algorithm'] = 'None'
                                else:
                                    bucket_info['encryption_error'] = str(e)
                            
                            buckets.append(bucket_info)
                    
                    evidence['data']['buckets'] = buckets
                    evidence['data']['total_buckets'] = len(buckets)
                    evidence['data']['encrypted_buckets'] = len([b for b in buckets if b.get('encryption_enabled', False)])
                    
                except ClientError as e:
                    evidence['data']['buckets_error'] = str(e)
            
            # Check S3 bucket versioning
            if 'bucket_versioning_check' in control.get('checks', []):
                try:
                    versioning_status = {}
                    paginator = self.aws_clients['s3'].get_paginator('list_buckets')
                    for page in paginator.paginate():
                        for bucket in page['Buckets']:
                            bucket_name = bucket['Name']
                            try:
                                versioning = self.aws_clients['s3'].get_bucket_versioning(
                                    Bucket=bucket_name
                                )
                                versioning_status[bucket_name] = versioning.get('Status', 'NotEnabled')
                            except ClientError as e:
                                versioning_status[bucket_name] = f"Error: {str(e)}"
                    
                    evidence['data']['versioning_status'] = versioning_status
                    
                except ClientError as e:
                    evidence['data']['versioning_error'] = str(e)
                    
        except Exception as e:
            evidence['error'] = str(e)
            self.logger.error(f"Error collecting S3 evidence for {control['id']}: {e}")
        
        return evidence
    
    def _collect_cloudtrail_evidence(self, control: Dict[str, Any]) -> Dict[str, Any]:
        """Collect CloudTrail-related evidence for compliance controls."""
        evidence = {
            'control_id': control['id'],
            'control_name': control['name'],
            'evidence_type': 'cloudtrail',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'data': {}
        }
        
        try:
            # Check CloudTrail trails
            if 'trail_status_check' in control.get('checks', []):
                try:
                    trails = self.aws_clients['cloudtrail'].list_trails()
                    trail_details = []
                    
                    for trail in trails['Trails']:
                        trail_name = trail['Name']
                        try:
                            trail_info = self.aws_clients['cloudtrail'].get_trail(
                                Name=trail_name
                            )
                            trail_detail = {
                                'name': trail_name,
                                's3_bucket': trail_info['Trail']['S3BucketName'],
                                'log_file_validation_enabled': trail_info['Trail'].get('LogFileValidationEnabled', False),
                                'is_multi_region_trail': trail_info['Trail'].get('IsMultiRegionTrail', False),
                                'include_global_services': trail_info['Trail'].get('IncludeGlobalServiceEvents', False)
                            }
                            trail_details.append(trail_detail)
                        except ClientError as e:
                            trail_details.append({
                                'name': trail_name,
                                'error': str(e)
                            })
                    
                    evidence['data']['trails'] = trail_details
                    evidence['data']['total_trails'] = len(trail_details)
                    evidence['data']['multi_region_trails'] = len([t for t in trail_details if t.get('is_multi_region_trail', False)])
                    
                except ClientError as e:
                    evidence['data']['trails_error'] = str(e)
            
            # Check CloudTrail logging status
            if 'logging_status_check' in control.get('checks', []):
                try:
                    logging_status = {}
                    trails = self.aws_clients['cloudtrail'].list_trails()
                    
                    for trail in trails['Trails']:
                        trail_name = trail['Name']
                        try:
                            status = self.aws_clients['cloudtrail'].get_trail_status(
                                Name=trail_name
                            )
                            logging_status[trail_name] = {
                                'is_logging': status.get('IsLogging', False),
                                'latest_delivery_time': status.get('LatestDeliveryTime', 'Never'),
                                'latest_notification_time': status.get('LatestNotificationTime', 'Never')
                            }
                        except ClientError as e:
                            logging_status[trail_name] = {'error': str(e)}
                    
                    evidence['data']['logging_status'] = logging_status
                    
                except ClientError as e:
                    evidence['data']['logging_status_error'] = str(e)
                    
        except Exception as e:
            evidence['error'] = str(e)
            self.logger.error(f"Error collecting CloudTrail evidence for {control['id']}: {e}")
        
        return evidence
    
    def _collect_rds_evidence(self, control: Dict[str, Any]) -> Dict[str, Any]:
        """Collect RDS-related evidence for compliance controls."""
        evidence = {
            'control_id': control['id'],
            'control_name': control['name'],
            'evidence_type': 'rds',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'data': {}
        }
        
        try:
            # Check RDS encryption
            if 'rds_encryption_check' in control.get('checks', []):
                try:
                    instances = []
                    paginator = self.aws_clients['rds'].get_paginator('describe_db_instances')
                    for page in paginator.paginate():
                        for instance in page['DBInstances']:
                            instance_info = {
                                'identifier': instance['DBInstanceIdentifier'],
                                'engine': instance['Engine'],
                                'storage_encrypted': instance.get('StorageEncrypted', False),
                                'kms_key_id': instance.get('KmsKeyId', 'None'),
                                'status': instance['DBInstanceStatus']
                            }
                            instances.append(instance_info)
                    
                    evidence['data']['instances'] = instances
                    evidence['data']['total_instances'] = len(instances)
                    evidence['data']['encrypted_instances'] = len([i for i in instances if i.get('storage_encrypted', False)])
                    
                except ClientError as e:
                    evidence['data']['instances_error'] = str(e)
                    
        except Exception as e:
            evidence['error'] = str(e)
            self.logger.error(f"Error collecting RDS evidence for {control['id']}: {e}")
        
        return evidence
    
    def collect_evidence(self, framework: Optional[str] = None, control_ids: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Collect evidence for specified controls or frameworks.
        
        Args:
            framework: Specific compliance framework to collect evidence for
            control_ids: List of specific control IDs to collect evidence for
            
        Returns:
            List of collected evidence dictionaries
        """
        self.logger.info(f"Starting evidence collection for region: {self.region}")
        
        # Filter controls based on parameters
        controls_to_check = []
        for control in self.controls_mapping['controls']:
            if framework and control.get('framework') != framework:
                continue
            if control_ids and control['id'] not in control_ids:
                continue
            controls_to_check.append(control)
        
        if not controls_to_check:
            self.logger.warning("No controls found matching the specified criteria")
            return []
        
        self.logger.info(f"Collecting evidence for {len(controls_to_check)} controls")
        
        for control in controls_to_check:
            self.logger.info(f"Collecting evidence for control: {control['id']} - {control['name']}")
            
            evidence = None
            if control['type'] == 'iam':
                evidence = self._collect_iam_evidence(control)
            elif control['type'] == 's3':
                evidence = self._collect_s3_evidence(control)
            elif control['type'] == 'cloudtrail':
                evidence = self._collect_cloudtrail_evidence(control)
            elif control['type'] == 'rds':
                evidence = self._collect_rds_evidence(control)
            else:
                self.logger.warning(f"Unknown control type: {control['type']}")
                continue
            
            if evidence:
                self.evidence_collected.append(evidence)
        
        return self.evidence_collected
    
    def generate_report(self, output_format: str = 'json', output_file: Optional[str] = None) -> str:
        """
        Generate a compliance evidence report.
        
        Args:
            output_format: Format for the report ('json', 'markdown', 'csv')
            output_file: Optional file path to save the report
            
        Returns:
            Generated report content
        """
        if not self.evidence_collected:
            return "No evidence collected."
        
        if output_format == 'json':
            report = {
                'metadata': {
                    'generated_at': datetime.now(timezone.utc).isoformat(),
                    'region': self.region,
                    'total_controls_checked': len(self.evidence_collected)
                },
                'evidence': self.evidence_collected
            }
            report_content = json.dumps(report, indent=2, default=str)
            
        elif output_format == 'markdown':
            report_content = self._generate_markdown_report()
            
        elif output_format == 'csv':
            report_content = self._generate_csv_report()
            
        else:
            raise ValueError(f"Unsupported output format: {output_format}")
        
        if output_file:
            # Validate output file path to prevent path traversal
            output_path = Path(output_file).resolve()
            
            # Ensure output directory exists and is writable
            output_dir = output_path.parent
            if not output_dir.exists():
                try:
                    output_dir.mkdir(parents=True, exist_ok=True)
                except Exception as e:
                    self.logger.error(f"Cannot create output directory: {e}")
                    raise
            
            # Check if directory is writable
            if not os.access(output_dir, os.W_OK):
                self.logger.error(f"Output directory not writable: {output_dir}")
                raise PermissionError(f"Cannot write to directory: {output_dir}")
            
            try:
                with open(output_path, 'w') as f:
                    f.write(report_content)
                self.logger.info(f"Report saved to: {output_path}")
            except Exception as e:
                self.logger.error(f"Error writing report file: {e}")
                raise
        
        return report_content
    
    def _generate_markdown_report(self) -> str:
        """Generate a markdown formatted report."""
        report_lines = [
            "# Cloud Compliance Evidence Report",
            "",
            f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"**AWS Region:** {self.region}",
            f"**Controls Checked:** {len(self.evidence_collected)}",
            "",
            "## Summary",
            ""
        ]
        
        # Summary statistics
        frameworks = {}
        evidence_types = {}
        for evidence in self.evidence_collected:
            framework = evidence.get('framework', 'Unknown')
            frameworks[framework] = frameworks.get(framework, 0) + 1
            evidence_type = evidence.get('evidence_type', 'Unknown')
            evidence_types[evidence_type] = evidence_types.get(evidence_type, 0) + 1
        
        report_lines.extend([
            "### Frameworks Covered",
            ""
        ])
        for framework, count in frameworks.items():
            report_lines.append(f"- **{framework}:** {count} controls")
        
        report_lines.extend([
            "",
            "### Evidence Types Collected",
            ""
        ])
        for evidence_type, count in evidence_types.items():
            report_lines.append(f"- **{evidence_type}:** {count} controls")
        
        report_lines.extend([
            "",
            "## Detailed Evidence",
            ""
        ])
        
        # Detailed evidence for each control
        for evidence in self.evidence_collected:
            report_lines.extend([
                f"### {evidence['control_id']} - {evidence['control_name']}",
                "",
                f"**Type:** {evidence['evidence_type']}",
                f"**Timestamp:** {evidence['timestamp']}",
                ""
            ])
            
            if 'error' in evidence:
                report_lines.extend([
                    "**Status:** ❌ Error",
                    f"**Error:** {evidence['error']}",
                    ""
                ])
            else:
                report_lines.extend([
                    "**Status:** ✅ Collected",
                    ""
                ])
                
                # Add key findings
                data = evidence.get('data', {})
                if data:
                    report_lines.append("**Key Findings:**")
                    for key, value in data.items():
                        if isinstance(value, (dict, list)):
                            report_lines.append(f"- **{key}:** {len(value)} items")
                        else:
                            report_lines.append(f"- **{key}:** {value}")
                    report_lines.append("")
            
            report_lines.append("---")
            report_lines.append("")
        
        return "\n".join(report_lines)
    
    def _generate_csv_report(self) -> str:
        """Generate a CSV formatted report."""
        import csv
        from io import StringIO
        
        output = StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow([
            'Control ID', 'Control Name', 'Framework', 'Evidence Type', 
            'Timestamp', 'Status', 'Key Findings'
        ])
        
        # Data rows
        for evidence in self.evidence_collected:
            status = "Error" if 'error' in evidence else "Collected"
            
            # Extract key findings
            findings = []
            data = evidence.get('data', {})
            for key, value in data.items():
                if isinstance(value, (dict, list)):
                    findings.append(f"{key}: {len(value)} items")
                else:
                    findings.append(f"{key}: {value}")
            
            writer.writerow([
                evidence['control_id'],
                evidence['control_name'],
                evidence.get('framework', ''),
                evidence['evidence_type'],
                evidence['timestamp'],
                status,
                '; '.join(findings)
            ])
        
        return output.getvalue()


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Cloud Compliance Evidence Scraper - Collect audit evidence from AWS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Collect evidence for all controls
  python compliance_scraper.py --config controls_mapping.yaml

  # Collect evidence for specific framework
  python compliance_scraper.py --config controls_mapping.yaml --framework "SOC 2"

  # Collect evidence for specific controls
  python compliance_scraper.py --config controls_mapping.yaml --control-ids CC6.1 CC6.2

  # Generate markdown report
  python compliance_scraper.py --config controls_mapping.yaml --output-format markdown --output-file report.md
        """
    )
    
    parser.add_argument(
        '--config', '-c',
        required=True,
        help='Path to the controls mapping YAML file'
    )
    
    parser.add_argument(
        '--region', '-r',
        default='us-east-1',
        help='AWS region to use (default: us-east-1)'
    )
    
    parser.add_argument(
        '--framework', '-f',
        help='Specific compliance framework to collect evidence for'
    )
    
    parser.add_argument(
        '--control-ids',
        nargs='+',
        help='Specific control IDs to collect evidence for'
    )
    
    parser.add_argument(
        '--output-format',
        choices=['json', 'markdown', 'csv'],
        default='json',
        help='Output format for the report (default: json)'
    )
    
    parser.add_argument(
        '--output-file', '-o',
        help='Output file path (if not specified, prints to stdout)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        # Initialize scraper
        scraper = ComplianceEvidenceScraper(args.config, args.region)
        
        # Collect evidence
        evidence = scraper.collect_evidence(args.framework, args.control_ids)
        
        if not evidence:
            print("No evidence collected. Check your configuration and AWS credentials.")
            sys.exit(1)
        
        # Generate and output report
        report = scraper.generate_report(args.output_format, args.output_file)
        
        if not args.output_file:
            print(report)
        
        print(f"\nEvidence collection completed. {len(evidence)} controls checked.")
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()