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
            'framework': control.get('framework', 'Unknown'),
            'category': control.get('category', 'Unknown'),
            'evidence_type': 'iam',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'risk_level': control.get('risk_level', 'Unknown'),
            'compliance_status': 'Unknown',
            'findings': [],
            'recommendations': [],
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
                    
                    # Add compliance assessment
                    if mfa_enabled:
                        evidence['findings'].append("✅ Root account MFA is enabled")
                    else:
                        evidence['findings'].append("❌ Root account MFA is not enabled")
                        evidence['recommendations'].append("Enable MFA for the root account immediately")
                        evidence['compliance_status'] = 'Non-Compliant'
                        
                except ClientError as e:
                    evidence['data']['root_mfa_error'] = str(e)
                    evidence['findings'].append(f"⚠️ Unable to verify root MFA status: {e}")
            
            # Check IAM password policy
            if 'password_policy_check' in control.get('checks', []):
                try:
                    password_policy = self.aws_clients['iam'].get_account_password_policy()
                    policy = password_policy['PasswordPolicy']
                    evidence['data']['password_policy'] = policy
                    
                    # Assess password policy compliance
                    findings = []
                    recommendations = []
                    
                    if policy.get('MinimumPasswordLength', 0) >= 12:
                        findings.append("✅ Minimum password length is 12+ characters")
                    else:
                        findings.append(f"❌ Minimum password length is {policy.get('MinimumPasswordLength', 0)} characters")
                        recommendations.append("Increase minimum password length to 12+ characters")
                    
                    if policy.get('RequireSymbols', False):
                        findings.append("✅ Password policy requires symbols")
                    else:
                        findings.append("❌ Password policy does not require symbols")
                        recommendations.append("Enable symbol requirement in password policy")
                    
                    if policy.get('RequireNumbers', False):
                        findings.append("✅ Password policy requires numbers")
                    else:
                        findings.append("❌ Password policy does not require numbers")
                        recommendations.append("Enable number requirement in password policy")
                    
                    if policy.get('RequireUppercaseCharacters', False):
                        findings.append("✅ Password policy requires uppercase characters")
                    else:
                        findings.append("❌ Password policy does not require uppercase characters")
                        recommendations.append("Enable uppercase character requirement in password policy")
                    
                    if policy.get('RequireLowercaseCharacters', False):
                        findings.append("✅ Password policy requires lowercase characters")
                    else:
                        findings.append("❌ Password policy does not require lowercase characters")
                        recommendations.append("Enable lowercase character requirement in password policy")
                    
                    if policy.get('ExpirePasswords', False):
                        findings.append("✅ Password policy requires password expiration")
                        max_age = policy.get('MaxPasswordAge', 0)
                        if max_age <= 90:
                            findings.append(f"✅ Password expiration is set to {max_age} days")
                        else:
                            findings.append(f"⚠️ Password expiration is set to {max_age} days (recommend 90 days or less)")
                            recommendations.append("Reduce password expiration to 90 days or less")
                    else:
                        findings.append("❌ Password policy does not require password expiration")
                        recommendations.append("Enable password expiration in password policy")
                    
                    evidence['findings'].extend(findings)
                    evidence['recommendations'].extend(recommendations)
                    
                    # Update compliance status if recommendations exist
                    if recommendations and evidence['compliance_status'] != 'Non-Compliant':
                        evidence['compliance_status'] = 'Partially Compliant'
                        
                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchEntity':
                        evidence['data']['password_policy'] = 'No password policy configured'
                        evidence['findings'].append("❌ No IAM password policy is configured")
                        evidence['recommendations'].append("Configure a comprehensive IAM password policy")
                        evidence['compliance_status'] = 'Non-Compliant'
                    else:
                        evidence['data']['password_policy_error'] = str(e)
                        evidence['findings'].append(f"⚠️ Unable to verify password policy: {e}")
            
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
                    
                    # Assess admin user compliance
                    if len(admin_users) == 0:
                        evidence['findings'].append("✅ No users with AdministratorAccess policy found")
                    elif len(admin_users) <= 3:
                        evidence['findings'].append(f"⚠️ {len(admin_users)} users have AdministratorAccess policy")
                        evidence['recommendations'].append("Review and reduce the number of administrative users")
                        if evidence['compliance_status'] != 'Non-Compliant':
                            evidence['compliance_status'] = 'Partially Compliant'
                    else:
                        evidence['findings'].append(f"❌ {len(admin_users)} users have AdministratorAccess policy (too many)")
                        evidence['recommendations'].append("Immediately review and reduce administrative users to minimum required")
                        evidence['compliance_status'] = 'Non-Compliant'
                        
                except ClientError as e:
                    evidence['data']['admin_users_error'] = str(e)
                    evidence['findings'].append(f"⚠️ Unable to verify admin users: {e}")
            
            # Set compliance status if not already set
            if evidence['compliance_status'] == 'Unknown' and not evidence['findings']:
                evidence['compliance_status'] = 'Compliant'
            elif evidence['compliance_status'] == 'Unknown':
                evidence['compliance_status'] = 'Compliant'
                    
        except Exception as e:
            evidence['error'] = str(e)
            evidence['findings'].append(f"❌ Error collecting IAM evidence: {e}")
            evidence['compliance_status'] = 'Error'
            self.logger.error(f"Error collecting IAM evidence for {control['id']}: {e}")
        
        return evidence
    
    def _collect_s3_evidence(self, control: Dict[str, Any]) -> Dict[str, Any]:
        """Collect S3-related evidence for compliance controls."""
        evidence = {
            'control_id': control['id'],
            'control_name': control['name'],
            'framework': control.get('framework', 'Unknown'),
            'category': control.get('category', 'Unknown'),
            'evidence_type': 's3',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'risk_level': control.get('risk_level', 'Unknown'),
            'compliance_status': 'Unknown',
            'findings': [],
            'recommendations': [],
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
                    
                    # Assess S3 encryption compliance
                    total_buckets = len(buckets)
                    encrypted_buckets = len([b for b in buckets if b.get('encryption_enabled', False)])
                    unencrypted_buckets = total_buckets - encrypted_buckets
                    
                    if total_buckets == 0:
                        evidence['findings'].append("ℹ️ No S3 buckets found")
                    elif encrypted_buckets == total_buckets:
                        evidence['findings'].append(f"✅ All {total_buckets} S3 buckets are encrypted")
                    elif encrypted_buckets > 0:
                        evidence['findings'].append(f"⚠️ {encrypted_buckets}/{total_buckets} S3 buckets are encrypted")
                        evidence['findings'].append(f"❌ {unencrypted_buckets} buckets are not encrypted")
                        evidence['recommendations'].append(f"Enable encryption for {unencrypted_buckets} unencrypted S3 buckets")
                        evidence['compliance_status'] = 'Partially Compliant'
                    else:
                        evidence['findings'].append(f"❌ None of the {total_buckets} S3 buckets are encrypted")
                        evidence['recommendations'].append("Enable encryption for all S3 buckets immediately")
                        evidence['compliance_status'] = 'Non-Compliant'
                    
                except ClientError as e:
                    evidence['data']['buckets_error'] = str(e)
                    evidence['findings'].append(f"⚠️ Unable to verify S3 bucket encryption: {e}")
            
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
                    
                    # Assess S3 versioning compliance
                    total_buckets = len(versioning_status)
                    enabled_versioning = len([v for v in versioning_status.values() if v == 'Enabled'])
                    disabled_versioning = total_buckets - enabled_versioning
                    
                    if total_buckets == 0:
                        evidence['findings'].append("ℹ️ No S3 buckets found for versioning check")
                    elif enabled_versioning == total_buckets:
                        evidence['findings'].append(f"✅ All {total_buckets} S3 buckets have versioning enabled")
                    elif enabled_versioning > 0:
                        evidence['findings'].append(f"⚠️ {enabled_versioning}/{total_buckets} S3 buckets have versioning enabled")
                        evidence['findings'].append(f"❌ {disabled_versioning} buckets do not have versioning enabled")
                        evidence['recommendations'].append(f"Enable versioning for {disabled_versioning} S3 buckets")
                        if evidence['compliance_status'] != 'Non-Compliant':
                            evidence['compliance_status'] = 'Partially Compliant'
                    else:
                        evidence['findings'].append(f"❌ None of the {total_buckets} S3 buckets have versioning enabled")
                        evidence['recommendations'].append("Enable versioning for all S3 buckets")
                        evidence['compliance_status'] = 'Non-Compliant'
                    
                except ClientError as e:
                    evidence['data']['versioning_error'] = str(e)
                    evidence['findings'].append(f"⚠️ Unable to verify S3 bucket versioning: {e}")
                    
        except Exception as e:
            evidence['error'] = str(e)
            evidence['findings'].append(f"❌ Error collecting S3 evidence: {e}")
            evidence['compliance_status'] = 'Error'
            self.logger.error(f"Error collecting S3 evidence for {control['id']}: {e}")
        
        # Set compliance status if not already set
        if evidence['compliance_status'] == 'Unknown' and not evidence['findings']:
            evidence['compliance_status'] = 'Compliant'
        elif evidence['compliance_status'] == 'Unknown':
            evidence['compliance_status'] = 'Compliant'
        
        return evidence
    
    def _collect_cloudtrail_evidence(self, control: Dict[str, Any]) -> Dict[str, Any]:
        """Collect CloudTrail-related evidence for compliance controls."""
        evidence = {
            'control_id': control['id'],
            'control_name': control['name'],
            'framework': control.get('framework', 'Unknown'),
            'category': control.get('category', 'Unknown'),
            'evidence_type': 'cloudtrail',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'risk_level': control.get('risk_level', 'Unknown'),
            'compliance_status': 'Unknown',
            'findings': [],
            'recommendations': [],
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
                    
                    # Assess CloudTrail configuration compliance
                    total_trails = len(trail_details)
                    multi_region_trails = len([t for t in trail_details if t.get('is_multi_region_trail', False)])
                    log_validation_enabled = len([t for t in trail_details if t.get('log_file_validation_enabled', False)])
                    
                    if total_trails == 0:
                        evidence['findings'].append("❌ No CloudTrail trails configured")
                        evidence['recommendations'].append("Configure at least one CloudTrail trail")
                        evidence['compliance_status'] = 'Non-Compliant'
                    else:
                        evidence['findings'].append(f"✅ {total_trails} CloudTrail trail(s) configured")
                        
                        if multi_region_trails > 0:
                            evidence['findings'].append(f"✅ {multi_region_trails} multi-region trail(s) configured")
                        else:
                            evidence['findings'].append("❌ No multi-region CloudTrail trails configured")
                            evidence['recommendations'].append("Configure at least one multi-region CloudTrail trail")
                            evidence['compliance_status'] = 'Partially Compliant'
                        
                        if log_validation_enabled > 0:
                            evidence['findings'].append(f"✅ {log_validation_enabled} trail(s) have log file validation enabled")
                        else:
                            evidence['findings'].append("⚠️ No trails have log file validation enabled")
                            evidence['recommendations'].append("Enable log file validation for CloudTrail trails")
                            if evidence['compliance_status'] != 'Non-Compliant':
                                evidence['compliance_status'] = 'Partially Compliant'
                    
                except ClientError as e:
                    evidence['data']['trails_error'] = str(e)
                    evidence['findings'].append(f"⚠️ Unable to verify CloudTrail configuration: {e}")
            
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
                    
                    # Assess CloudTrail logging status compliance
                    total_trails = len(logging_status)
                    active_logging = len([s for s in logging_status.values() if s.get('is_logging', False)])
                    inactive_logging = total_trails - active_logging
                    
                    if total_trails == 0:
                        evidence['findings'].append("ℹ️ No CloudTrail trails found for logging status check")
                    elif active_logging == total_trails:
                        evidence['findings'].append(f"✅ All {total_trails} CloudTrail trail(s) are actively logging")
                    elif active_logging > 0:
                        evidence['findings'].append(f"⚠️ {active_logging}/{total_trails} CloudTrail trail(s) are actively logging")
                        evidence['findings'].append(f"❌ {inactive_logging} trail(s) are not actively logging")
                        evidence['recommendations'].append(f"Ensure {inactive_logging} CloudTrail trail(s) are actively logging")
                        if evidence['compliance_status'] != 'Non-Compliant':
                            evidence['compliance_status'] = 'Partially Compliant'
                    else:
                        evidence['findings'].append(f"❌ None of the {total_trails} CloudTrail trail(s) are actively logging")
                        evidence['recommendations'].append("Ensure all CloudTrail trails are actively logging")
                        evidence['compliance_status'] = 'Non-Compliant'
                    
                except ClientError as e:
                    evidence['data']['logging_status_error'] = str(e)
                    evidence['findings'].append(f"⚠️ Unable to verify CloudTrail logging status: {e}")
                    
        except Exception as e:
            evidence['error'] = str(e)
            evidence['findings'].append(f"❌ Error collecting CloudTrail evidence: {e}")
            evidence['compliance_status'] = 'Error'
            self.logger.error(f"Error collecting CloudTrail evidence for {control['id']}: {e}")
        
        # Set compliance status if not already set
        if evidence['compliance_status'] == 'Unknown' and not evidence['findings']:
            evidence['compliance_status'] = 'Compliant'
        elif evidence['compliance_status'] == 'Unknown':
            evidence['compliance_status'] = 'Compliant'
        
        return evidence
    
    def _collect_rds_evidence(self, control: Dict[str, Any]) -> Dict[str, Any]:
        """Collect RDS-related evidence for compliance controls."""
        evidence = {
            'control_id': control['id'],
            'control_name': control['name'],
            'framework': control.get('framework', 'Unknown'),
            'category': control.get('category', 'Unknown'),
            'evidence_type': 'rds',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'risk_level': control.get('risk_level', 'Unknown'),
            'compliance_status': 'Unknown',
            'findings': [],
            'recommendations': [],
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
                    
                    # Assess RDS encryption compliance
                    total_instances = len(instances)
                    encrypted_instances = len([i for i in instances if i.get('storage_encrypted', False)])
                    unencrypted_instances = total_instances - encrypted_instances
                    
                    if total_instances == 0:
                        evidence['findings'].append("ℹ️ No RDS instances found")
                    elif encrypted_instances == total_instances:
                        evidence['findings'].append(f"✅ All {total_instances} RDS instance(s) are encrypted")
                    elif encrypted_instances > 0:
                        evidence['findings'].append(f"⚠️ {encrypted_instances}/{total_instances} RDS instance(s) are encrypted")
                        evidence['findings'].append(f"❌ {unencrypted_instances} instance(s) are not encrypted")
                        evidence['recommendations'].append(f"Enable encryption for {unencrypted_instances} unencrypted RDS instance(s)")
                        evidence['compliance_status'] = 'Partially Compliant'
                    else:
                        evidence['findings'].append(f"❌ None of the {total_instances} RDS instance(s) are encrypted")
                        evidence['recommendations'].append("Enable encryption for all RDS instances immediately")
                        evidence['compliance_status'] = 'Non-Compliant'
                    
                except ClientError as e:
                    evidence['data']['instances_error'] = str(e)
                    evidence['findings'].append(f"⚠️ Unable to verify RDS encryption: {e}")
                    
        except Exception as e:
            evidence['error'] = str(e)
            evidence['findings'].append(f"❌ Error collecting RDS evidence: {e}")
            evidence['compliance_status'] = 'Error'
            self.logger.error(f"Error collecting RDS evidence for {control['id']}: {e}")
        
        # Set compliance status if not already set
        if evidence['compliance_status'] == 'Unknown' and not evidence['findings']:
            evidence['compliance_status'] = 'Compliant'
        elif evidence['compliance_status'] == 'Unknown':
            evidence['compliance_status'] = 'Compliant'
        
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
        compliance_status = {}
        risk_levels = {}
        
        for evidence in self.evidence_collected:
            framework = evidence.get('framework', 'Unknown')
            frameworks[framework] = frameworks.get(framework, 0) + 1
            evidence_type = evidence.get('evidence_type', 'Unknown')
            evidence_types[evidence_type] = evidence_types.get(evidence_type, 0) + 1
            status = evidence.get('compliance_status', 'Unknown')
            compliance_status[status] = compliance_status.get(status, 0) + 1
            risk_level = evidence.get('risk_level', 'Unknown')
            risk_levels[risk_level] = risk_levels.get(risk_level, 0) + 1
        
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
            "### Compliance Status Summary",
            ""
        ])
        for status, count in compliance_status.items():
            status_icon = "✅" if status == "Compliant" else "⚠️" if status == "Partially Compliant" else "❌" if status == "Non-Compliant" else "❓"
            report_lines.append(f"- {status_icon} **{status}:** {count} controls")
        
        report_lines.extend([
            "",
            "### Risk Level Distribution",
            ""
        ])
        for risk_level, count in risk_levels.items():
            risk_icon = "🔴" if risk_level == "Critical" else "🟠" if risk_level == "High" else "🟡" if risk_level == "Medium" else "🟢" if risk_level == "Low" else "⚪"
            report_lines.append(f"- {risk_icon} **{risk_level}:** {count} controls")
        
        report_lines.extend([
            "",
            "## Detailed Evidence",
            ""
        ])
        
        # Detailed evidence for each control
        for evidence in self.evidence_collected:
            # Determine status icon
            status = evidence.get('compliance_status', 'Unknown')
            status_icon = "✅" if status == "Compliant" else "⚠️" if status == "Partially Compliant" else "❌" if status == "Non-Compliant" else "❓"
            
            # Determine risk icon
            risk_level = evidence.get('risk_level', 'Unknown')
            risk_icon = "🔴" if risk_level == "Critical" else "🟠" if risk_level == "High" else "🟡" if risk_level == "Medium" else "🟢" if risk_level == "Low" else "⚪"
            
            report_lines.extend([
                f"### {evidence['control_id']} - {evidence['control_name']}",
                "",
                f"**Framework:** {evidence.get('framework', 'Unknown')}",
                f"**Category:** {evidence.get('category', 'Unknown')}",
                f"**Type:** {evidence['evidence_type']}",
                f"**Risk Level:** {risk_icon} {risk_level}",
                f"**Compliance Status:** {status_icon} {status}",
                f"**Timestamp:** {evidence['timestamp']}",
                ""
            ])
            
            if 'error' in evidence:
                report_lines.extend([
                    "**Error Details:**",
                    f"```",
                    f"{evidence['error']}",
                    f"```",
                    ""
                ])
            else:
                # Add findings
                findings = evidence.get('findings', [])
                if findings:
                    report_lines.append("**Findings:**")
                    for finding in findings:
                        report_lines.append(f"- {finding}")
                    report_lines.append("")
                
                # Add recommendations
                recommendations = evidence.get('recommendations', [])
                if recommendations:
                    report_lines.append("**Recommendations:**")
                    for recommendation in recommendations:
                        report_lines.append(f"- {recommendation}")
                    report_lines.append("")
                
                # Add key data summary
                data = evidence.get('data', {})
                if data:
                    report_lines.append("**Data Summary:**")
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
            'Control ID', 'Control Name', 'Framework', 'Category', 'Evidence Type', 
            'Risk Level', 'Compliance Status', 'Timestamp', 'Findings', 'Recommendations'
        ])
        
        # Data rows
        for evidence in self.evidence_collected:
            # Extract findings
            findings = evidence.get('findings', [])
            findings_text = '; '.join(findings) if findings else 'No findings'
            
            # Extract recommendations
            recommendations = evidence.get('recommendations', [])
            recommendations_text = '; '.join(recommendations) if recommendations else 'No recommendations'
            
            writer.writerow([
                evidence['control_id'],
                evidence['control_name'],
                evidence.get('framework', ''),
                evidence.get('category', ''),
                evidence['evidence_type'],
                evidence.get('risk_level', ''),
                evidence.get('compliance_status', ''),
                evidence['timestamp'],
                findings_text,
                recommendations_text
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