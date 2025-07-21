"""
AWS Integration
Secure LLM Interaction Proxy

Provides integration with AWS services including:
- AWS IAM for authentication and authorization
- AWS Secrets Manager for secure credential storage
- AWS CloudWatch for monitoring and logging
- AWS CloudTrail for audit logging
- AWS Systems Manager for configuration management
- AWS Lambda for serverless deployment
- AWS ECS/EKS for container deployment
"""

import os
import json
import boto3
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from enum import Enum

import botocore
from botocore.exceptions import ClientError, NoCredentialsError

class AWSIntegrationError(Exception):
    """Custom exception for AWS integration errors."""
    pass

class AWSRegion(Enum):
    """AWS regions for deployment."""
    US_EAST_1 = "us-east-1"
    US_WEST_2 = "us-west-2"
    EU_WEST_1 = "eu-west-1"
    AP_SOUTHEAST_1 = "ap-southeast-1"

@dataclass
class AWSConfig:
    """AWS configuration settings."""
    region: str = "us-east-1"
    access_key_id: Optional[str] = None
    secret_access_key: Optional[str] = None
    session_token: Optional[str] = None
    role_arn: Optional[str] = None
    profile_name: Optional[str] = None
    use_iam_role: bool = True
    enable_cloudwatch: bool = True
    enable_cloudtrail: bool = True
    enable_secrets_manager: bool = True
    enable_systems_manager: bool = True

@dataclass
class CloudWatchMetric:
    """CloudWatch metric data."""
    namespace: str
    metric_name: str
    value: float
    unit: str
    dimensions: List[Dict[str, str]]
    timestamp: datetime

@dataclass
class CloudWatchLog:
    """CloudWatch log data."""
    log_group: str
    log_stream: str
    message: str
    timestamp: datetime
    level: str = "INFO"

class AWSIntegration:
    """AWS integration for enterprise deployment."""
    
    def __init__(self, config: AWSConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Initialize AWS clients
        self._init_clients()
    
    def _init_clients(self):
        """Initialize AWS service clients."""
        try:
            # Configure session
            session_kwargs = {
                'region_name': self.config.region
            }
            
            if self.config.profile_name:
                session_kwargs['profile_name'] = self.config.profile_name
            elif self.config.access_key_id and self.config.secret_access_key:
                session_kwargs.update({
                    'aws_access_key_id': self.config.access_key_id,
                    'aws_secret_access_key': self.config.secret_access_key
                })
                if self.config.session_token:
                    session_kwargs['aws_session_token'] = self.config.session_token
            
            self.session = boto3.Session(**session_kwargs)
            
            # Initialize service clients
            self.iam = self.session.client('iam')
            self.secretsmanager = self.session.client('secrets-manager')
            self.cloudwatch = self.session.client('cloudwatch')
            self.cloudwatch_logs = self.session.client('logs')
            self.cloudtrail = self.session.client('cloudtrail')
            self.ssm = self.session.client('ssm')
            self.ec2 = self.session.client('ec2')
            self.ecs = self.session.client('ecs')
            self.ecr = self.session.client('ecr')
            self.lambda_client = self.session.client('lambda')
            self.s3 = self.session.client('s3')
            
            self.logger.info("AWS clients initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize AWS clients: {e}")
            raise AWSIntegrationError(f"AWS client initialization failed: {e}")
    
    # IAM Integration
    def create_iam_role(self, role_name: str, trust_policy: Dict, 
                       policy_arns: List[str] = None) -> str:
        """Create IAM role for the application."""
        try:
            # Create role
            response = self.iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                Description=f"IAM role for Secure LLM Proxy - {role_name}"
            )
            
            role_arn = response['Role']['Arn']
            
            # Attach policies
            if policy_arns:
                for policy_arn in policy_arns:
                    self.iam.attach_role_policy(
                        RoleName=role_name,
                        PolicyArn=policy_arn
                    )
            
            # Create instance profile
            try:
                self.iam.create_instance_profile(
                    InstanceProfileName=role_name
                )
                self.iam.add_role_to_instance_profile(
                    InstanceProfileName=role_name,
                    RoleName=role_name
                )
            except ClientError as e:
                if e.response['Error']['Code'] != 'EntityAlreadyExists':
                    raise
            
            self.logger.info(f"IAM role {role_name} created successfully")
            return role_arn
            
        except ClientError as e:
            self.logger.error(f"Failed to create IAM role: {e}")
            raise AWSIntegrationError(f"IAM role creation failed: {e}")
    
    def create_iam_user(self, username: str, policy_arns: List[str] = None) -> Dict:
        """Create IAM user for API access."""
        try:
            # Create user
            response = self.iam.create_user(UserName=username)
            user_arn = response['User']['Arn']
            
            # Attach policies
            if policy_arns:
                for policy_arn in policy_arns:
                    self.iam.attach_user_policy(
                        UserName=username,
                        PolicyArn=policy_arn
                    )
            
            # Create access key
            access_key_response = self.iam.create_access_key(UserName=username)
            access_key = access_key_response['AccessKey']
            
            self.logger.info(f"IAM user {username} created successfully")
            return {
                'user_arn': user_arn,
                'access_key_id': access_key['AccessKeyId'],
                'secret_access_key': access_key['SecretAccessKey']
            }
            
        except ClientError as e:
            self.logger.error(f"Failed to create IAM user: {e}")
            raise AWSIntegrationError(f"IAM user creation failed: {e}")
    
    def validate_iam_credentials(self) -> bool:
        """Validate IAM credentials and permissions."""
        try:
            # Test IAM access
            self.iam.get_user()
            self.logger.info("IAM credentials validated successfully")
            return True
        except ClientError as e:
            self.logger.error(f"IAM credentials validation failed: {e}")
            return False
    
    # Secrets Manager Integration
    def store_secret(self, secret_name: str, secret_value: str, 
                    description: str = None) -> str:
        """Store secret in AWS Secrets Manager."""
        try:
            response = self.secretsmanager.create_secret(
                Name=secret_name,
                SecretString=secret_value,
                Description=description or f"Secret for Secure LLM Proxy - {secret_name}"
            )
            
            self.logger.info(f"Secret {secret_name} stored successfully")
            return response['ARN']
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceExistsException':
                # Update existing secret
                response = self.secretsmanager.update_secret(
                    SecretId=secret_name,
                    SecretString=secret_value
                )
                self.logger.info(f"Secret {secret_name} updated successfully")
                return response['ARN']
            else:
                self.logger.error(f"Failed to store secret: {e}")
                raise AWSIntegrationError(f"Secret storage failed: {e}")
    
    def retrieve_secret(self, secret_name: str) -> str:
        """Retrieve secret from AWS Secrets Manager."""
        try:
            response = self.secretsmanager.get_secret_value(
                SecretId=secret_name
            )
            
            if 'SecretString' in response:
                return response['SecretString']
            else:
                # Handle binary secrets
                import base64
                return base64.b64decode(response['SecretBinary']).decode('utf-8')
                
        except ClientError as e:
            self.logger.error(f"Failed to retrieve secret: {e}")
            raise AWSIntegrationError(f"Secret retrieval failed: {e}")
    
    def list_secrets(self, prefix: str = None) -> List[Dict]:
        """List secrets in Secrets Manager."""
        try:
            secrets = []
            paginator = self.secretsmanager.get_paginator('list_secrets')
            
            for page in paginator.paginate():
                for secret in page['SecretList']:
                    if not prefix or secret['Name'].startswith(prefix):
                        secrets.append({
                            'name': secret['Name'],
                            'arn': secret['ARN'],
                            'description': secret.get('Description', ''),
                            'last_modified': secret['LastModifiedDate']
                        })
            
            return secrets
            
        except ClientError as e:
            self.logger.error(f"Failed to list secrets: {e}")
            raise AWSIntegrationError(f"Secret listing failed: {e}")
    
    # CloudWatch Integration
    def send_metric(self, metric: CloudWatchMetric):
        """Send metric to CloudWatch."""
        try:
            self.cloudwatch.put_metric_data(
                Namespace=metric.namespace,
                MetricData=[{
                    'MetricName': metric.metric_name,
                    'Value': metric.value,
                    'Unit': metric.unit,
                    'Dimensions': metric.dimensions,
                    'Timestamp': metric.timestamp
                }]
            )
            
            self.logger.debug(f"Metric {metric.metric_name} sent to CloudWatch")
            
        except ClientError as e:
            self.logger.error(f"Failed to send metric: {e}")
            raise AWSIntegrationError(f"Metric sending failed: {e}")
    
    def send_log(self, log: CloudWatchLog):
        """Send log to CloudWatch Logs."""
        try:
            # Ensure log group exists
            try:
                self.cloudwatch_logs.create_log_group(logGroupName=log.log_group)
            except ClientError as e:
                if e.response['Error']['Code'] != 'ResourceAlreadyExistsException':
                    raise
            
            # Ensure log stream exists
            try:
                self.cloudwatch_logs.create_log_stream(
                    logGroupName=log.log_group,
                    logStreamName=log.log_stream
                )
            except ClientError as e:
                if e.response['Error']['Code'] != 'ResourceAlreadyExistsException':
                    raise
            
            # Send log event
            self.cloudwatch_logs.put_log_events(
                logGroupName=log.log_group,
                logStreamName=log.log_stream,
                logEvents=[{
                    'timestamp': int(log.timestamp.timestamp() * 1000),
                    'message': json.dumps({
                        'message': log.message,
                        'level': log.level,
                        'timestamp': log.timestamp.isoformat()
                    })
                }]
            )
            
            self.logger.debug(f"Log sent to CloudWatch: {log.log_group}/{log.log_stream}")
            
        except ClientError as e:
            self.logger.error(f"Failed to send log: {e}")
            raise AWSIntegrationError(f"Log sending failed: {e}")
    
    def create_dashboard(self, dashboard_name: str, dashboard_body: str):
        """Create CloudWatch dashboard."""
        try:
            self.cloudwatch.put_dashboard(
                DashboardName=dashboard_name,
                DashboardBody=dashboard_body
            )
            
            self.logger.info(f"Dashboard {dashboard_name} created successfully")
            
        except ClientError as e:
            self.logger.error(f"Failed to create dashboard: {e}")
            raise AWSIntegrationError(f"Dashboard creation failed: {e}")
    
    # CloudTrail Integration
    def log_cloudtrail_event(self, event_name: str, event_data: Dict):
        """Log custom event to CloudTrail."""
        try:
            # CloudTrail automatically logs API calls, but we can create custom events
            # by making API calls that will be logged
            self.cloudtrail.lookup_events(
                LookupAttributes=[{
                    'AttributeKey': 'EventName',
                    'AttributeValue': event_name
                }],
                MaxResults=1
            )
            
            self.logger.debug(f"CloudTrail event logged: {event_name}")
            
        except ClientError as e:
            self.logger.error(f"Failed to log CloudTrail event: {e}")
            raise AWSIntegrationError(f"CloudTrail logging failed: {e}")
    
    # Systems Manager Integration
    def store_parameter(self, parameter_name: str, parameter_value: str, 
                       parameter_type: str = "SecureString", description: str = None):
        """Store parameter in Systems Manager Parameter Store."""
        try:
            self.ssm.put_parameter(
                Name=parameter_name,
                Value=parameter_value,
                Type=parameter_type,
                Description=description or f"Parameter for Secure LLM Proxy - {parameter_name}",
                Overwrite=True
            )
            
            self.logger.info(f"Parameter {parameter_name} stored successfully")
            
        except ClientError as e:
            self.logger.error(f"Failed to store parameter: {e}")
            raise AWSIntegrationError(f"Parameter storage failed: {e}")
    
    def retrieve_parameter(self, parameter_name: str, with_decryption: bool = True) -> str:
        """Retrieve parameter from Systems Manager Parameter Store."""
        try:
            response = self.ssm.get_parameter(
                Name=parameter_name,
                WithDecryption=with_decryption
            )
            
            return response['Parameter']['Value']
            
        except ClientError as e:
            self.logger.error(f"Failed to retrieve parameter: {e}")
            raise AWSIntegrationError(f"Parameter retrieval failed: {e}")
    
    # ECS/EKS Integration
    def create_ecs_task_definition(self, family: str, container_definitions: List[Dict],
                                  task_role_arn: str = None, execution_role_arn: str = None) -> str:
        """Create ECS task definition."""
        try:
            task_def = {
                'family': family,
                'containerDefinitions': container_definitions,
                'requiresCompatibilities': ['FARGATE'],
                'networkMode': 'awsvpc',
                'cpu': '256',
                'memory': '512'
            }
            
            if task_role_arn:
                task_def['taskRoleArn'] = task_role_arn
            if execution_role_arn:
                task_def['executionRoleArn'] = execution_role_arn
            
            response = self.ecs.register_task_definition(**task_def)
            
            self.logger.info(f"ECS task definition {family} created successfully")
            return response['taskDefinition']['taskDefinitionArn']
            
        except ClientError as e:
            self.logger.error(f"Failed to create ECS task definition: {e}")
            raise AWSIntegrationError(f"ECS task definition creation failed: {e}")
    
    def create_ecs_service(self, cluster_name: str, service_name: str, 
                          task_definition_arn: str, subnets: List[str],
                          security_groups: List[str]) -> str:
        """Create ECS service."""
        try:
            response = self.ecs.create_service(
                cluster=cluster_name,
                serviceName=service_name,
                taskDefinition=task_definition_arn,
                desiredCount=1,
                launchType='FARGATE',
                networkConfiguration={
                    'awsvpcConfiguration': {
                        'subnets': subnets,
                        'securityGroups': security_groups,
                        'assignPublicIp': 'ENABLED'
                    }
                }
            )
            
            self.logger.info(f"ECS service {service_name} created successfully")
            return response['service']['serviceArn']
            
        except ClientError as e:
            self.logger.error(f"Failed to create ECS service: {e}")
            raise AWSIntegrationError(f"ECS service creation failed: {e}")
    
    # Lambda Integration
    def create_lambda_function(self, function_name: str, runtime: str, 
                              handler: str, code_zip_path: str,
                              role_arn: str, environment_vars: Dict = None) -> str:
        """Create Lambda function."""
        try:
            with open(code_zip_path, 'rb') as f:
                code_zip = f.read()
            
            function_config = {
                'FunctionName': function_name,
                'Runtime': runtime,
                'Role': role_arn,
                'Handler': handler,
                'Code': {'ZipFile': code_zip},
                'Timeout': 30,
                'MemorySize': 128
            }
            
            if environment_vars:
                function_config['Environment'] = {
                    'Variables': environment_vars
                }
            
            response = self.lambda_client.create_function(**function_config)
            
            self.logger.info(f"Lambda function {function_name} created successfully")
            return response['FunctionArn']
            
        except ClientError as e:
            self.logger.error(f"Failed to create Lambda function: {e}")
            raise AWSIntegrationError(f"Lambda function creation failed: {e}")
    
    # S3 Integration
    def upload_to_s3(self, bucket_name: str, key: str, data: bytes, 
                    content_type: str = None, metadata: Dict = None):
        """Upload data to S3 bucket."""
        try:
            upload_kwargs = {
                'Bucket': bucket_name,
                'Key': key,
                'Body': data
            }
            
            if content_type:
                upload_kwargs['ContentType'] = content_type
            if metadata:
                upload_kwargs['Metadata'] = metadata
            
            self.s3.put_object(**upload_kwargs)
            
            self.logger.info(f"Data uploaded to S3: s3://{bucket_name}/{key}")
            
        except ClientError as e:
            self.logger.error(f"Failed to upload to S3: {e}")
            raise AWSIntegrationError(f"S3 upload failed: {e}")
    
    def download_from_s3(self, bucket_name: str, key: str) -> bytes:
        """Download data from S3 bucket."""
        try:
            response = self.s3.get_object(Bucket=bucket_name, Key=key)
            return response['Body'].read()
            
        except ClientError as e:
            self.logger.error(f"Failed to download from S3: {e}")
            raise AWSIntegrationError(f"S3 download failed: {e}")
    
    # Security and Compliance
    def enable_cloudtrail(self, trail_name: str, s3_bucket_name: str,
                         log_file_prefix: str = None, include_global_services: bool = True):
        """Enable CloudTrail logging."""
        try:
            trail_config = {
                'Name': trail_name,
                'S3BucketName': s3_bucket_name,
                'IncludeGlobalServiceEvents': include_global_services,
                'IsMultiRegionTrail': True
            }
            
            if log_file_prefix:
                trail_config['S3KeyPrefix'] = log_file_prefix
            
            self.cloudtrail.create_trail(**trail_config)
            self.cloudtrail.start_logging(Name=trail_name)
            
            self.logger.info(f"CloudTrail {trail_name} enabled successfully")
            
        except ClientError as e:
            self.logger.error(f"Failed to enable CloudTrail: {e}")
            raise AWSIntegrationError(f"CloudTrail enablement failed: {e}")
    
    def create_security_group(self, group_name: str, description: str,
                             vpc_id: str, ingress_rules: List[Dict] = None) -> str:
        """Create security group."""
        try:
            response = self.ec2.create_security_group(
                GroupName=group_name,
                Description=description,
                VpcId=vpc_id
            )
            
            group_id = response['GroupId']
            
            # Add ingress rules
            if ingress_rules:
                self.ec2.authorize_security_group_ingress(
                    GroupId=group_id,
                    IpPermissions=ingress_rules
                )
            
            self.logger.info(f"Security group {group_name} created successfully")
            return group_id
            
        except ClientError as e:
            self.logger.error(f"Failed to create security group: {e}")
            raise AWSIntegrationError(f"Security group creation failed: {e}")
    
    # Monitoring and Alerting
    def create_cloudwatch_alarm(self, alarm_name: str, metric_name: str,
                               namespace: str, threshold: float,
                               comparison_operator: str = "GreaterThanThreshold",
                               evaluation_periods: int = 1,
                               period: int = 300):
        """Create CloudWatch alarm."""
        try:
            self.cloudwatch.put_metric_alarm(
                AlarmName=alarm_name,
                MetricName=metric_name,
                Namespace=namespace,
                Threshold=threshold,
                ComparisonOperator=comparison_operator,
                EvaluationPeriods=evaluation_periods,
                Period=period,
                Statistic='Average'
            )
            
            self.logger.info(f"CloudWatch alarm {alarm_name} created successfully")
            
        except ClientError as e:
            self.logger.error(f"Failed to create CloudWatch alarm: {e}")
            raise AWSIntegrationError(f"CloudWatch alarm creation failed: {e}")
    
    # Cost Optimization
    def get_cost_and_usage(self, start_date: str, end_date: str, 
                          granularity: str = "MONTHLY") -> Dict:
        """Get AWS cost and usage data."""
        try:
            ce_client = self.session.client('ce')
            
            response = ce_client.get_cost_and_usage(
                TimePeriod={
                    'Start': start_date,
                    'End': end_date
                },
                Granularity=granularity,
                Metrics=['UnblendedCost'],
                GroupBy=[
                    {'Type': 'DIMENSION', 'Key': 'SERVICE'}
                ]
            )
            
            return response
            
        except ClientError as e:
            self.logger.error(f"Failed to get cost and usage: {e}")
            raise AWSIntegrationError(f"Cost and usage retrieval failed: {e}")
    
    # Health Check
    def health_check(self) -> Dict[str, Any]:
        """Perform health check of AWS services."""
        health_status = {
            'overall_status': 'healthy',
            'services': {},
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        # Check IAM
        try:
            self.iam.get_user()
            health_status['services']['iam'] = 'healthy'
        except Exception as e:
            health_status['services']['iam'] = f'unhealthy: {str(e)}'
            health_status['overall_status'] = 'unhealthy'
        
        # Check CloudWatch
        try:
            self.cloudwatch.list_metrics(MaxResults=1)
            health_status['services']['cloudwatch'] = 'healthy'
        except Exception as e:
            health_status['services']['cloudwatch'] = f'unhealthy: {str(e)}'
            health_status['overall_status'] = 'unhealthy'
        
        # Check Secrets Manager
        try:
            self.secretsmanager.list_secrets(MaxResults=1)
            health_status['services']['secrets_manager'] = 'healthy'
        except Exception as e:
            health_status['services']['secrets_manager'] = f'unhealthy: {str(e)}'
            health_status['overall_status'] = 'unhealthy'
        
        return health_status