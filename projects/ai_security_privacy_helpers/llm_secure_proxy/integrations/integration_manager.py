"""
Integration Manager
Secure LLM Interaction Proxy

Provides a unified interface for managing multiple enterprise integrations
including AWS, Okta, Snyk, Sumo Logic, and other enterprise tools.
"""

import os
import json
import logging
from typing import Dict, List, Any, Optional, Type
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from enum import Enum

class IntegrationType(Enum):
    """Integration types."""
    AWS = "aws"
    OKTA = "okta"
    SNYK = "snyk"
    SUMOLOGIC = "sumologic"
    SPLUNK = "splunk"
    CROWDSTRIKE = "crowdstrike"
    TENABLE = "tenable"
    QUALYS = "qualys"
    AZURE = "azure"
    GCP = "gcp"
    JIRA = "jira"
    SLACK = "slack"
    PAGERDUTY = "pagerduty"
    DATADOG = "datadog"
    NEWRELIC = "newrelic"
    ELASTIC = "elastic"
    GRAFANA = "grafana"
    PROMETHEUS = "prometheus"
    VAULT = "vault"
    LDAP = "ldap"

@dataclass
class IntegrationStatus:
    """Integration status information."""
    name: str
    type: IntegrationType
    status: str
    last_check: datetime
    error_message: Optional[str] = None
    config_valid: bool = True

@dataclass
class IntegrationConfig:
    """Integration configuration."""
    type: IntegrationType
    enabled: bool = True
    config_data: Dict[str, Any] = None
    priority: int = 1

class IntegrationManager:
    """Manager for multiple enterprise integrations."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.integrations: Dict[str, Any] = {}
        self.configs: Dict[str, IntegrationConfig] = {}
        self.status: Dict[str, IntegrationStatus] = {}
        
        # Load configurations from environment
        self._load_configurations()
    
    def _load_configurations(self):
        """Load integration configurations from environment variables."""
        # AWS Configuration
        if os.getenv('AWS_ACCESS_KEY_ID') and os.getenv('AWS_SECRET_ACCESS_KEY'):
            self.configs['aws'] = IntegrationConfig(
                type=IntegrationType.AWS,
                enabled=True,
                config_data={
                    'region': os.getenv('AWS_REGION', 'us-east-1'),
                    'access_key_id': os.getenv('AWS_ACCESS_KEY_ID'),
                    'secret_access_key': os.getenv('AWS_SECRET_ACCESS_KEY'),
                    'enable_cloudwatch': True,
                    'enable_cloudtrail': True,
                    'enable_secrets_manager': True
                }
            )
        
        # Okta Configuration
        if os.getenv('OKTA_API_TOKEN') and os.getenv('OKTA_ORG_URL'):
            self.configs['okta'] = IntegrationConfig(
                type=IntegrationType.OKTA,
                enabled=True,
                config_data={
                    'org_url': os.getenv('OKTA_ORG_URL'),
                    'api_token': os.getenv('OKTA_API_TOKEN'),
                    'client_id': os.getenv('OKTA_CLIENT_ID'),
                    'client_secret': os.getenv('OKTA_CLIENT_SECRET'),
                    'enable_sso': True,
                    'enable_mfa': True
                }
            )
        
        # Snyk Configuration
        if os.getenv('SNYK_API_TOKEN') and os.getenv('SNYK_ORG_ID'):
            self.configs['snyk'] = IntegrationConfig(
                type=IntegrationType.SNYK,
                enabled=True,
                config_data={
                    'api_token': os.getenv('SNYK_API_TOKEN'),
                    'org_id': os.getenv('SNYK_ORG_ID'),
                    'enable_monitoring': True,
                    'enable_scanning': True
                }
            )
        
        # Sumo Logic Configuration
        if os.getenv('SUMO_ACCESS_ID') and os.getenv('SUMO_ACCESS_KEY'):
            self.configs['sumologic'] = IntegrationConfig(
                type=IntegrationType.SUMOLOGIC,
                enabled=True,
                config_data={
                    'access_id': os.getenv('SUMO_ACCESS_ID'),
                    'access_key': os.getenv('SUMO_ACCESS_KEY'),
                    'enable_logging': True,
                    'enable_search': True
                }
            )
        
        # Splunk Configuration
        if os.getenv('SPLUNK_HOST') and os.getenv('SPLUNK_USERNAME'):
            self.configs['splunk'] = IntegrationConfig(
                type=IntegrationType.SPLUNK,
                enabled=True,
                config_data={
                    'host': os.getenv('SPLUNK_HOST'),
                    'port': int(os.getenv('SPLUNK_PORT', '8089')),
                    'username': os.getenv('SPLUNK_USERNAME'),
                    'password': os.getenv('SPLUNK_PASSWORD')
                }
            )
        
        # DataDog Configuration
        if os.getenv('DATADOG_API_KEY'):
            self.configs['datadog'] = IntegrationConfig(
                type=IntegrationType.DATADOG,
                enabled=True,
                config_data={
                    'api_key': os.getenv('DATADOG_API_KEY'),
                    'app_key': os.getenv('DATADOG_APP_KEY'),
                    'site': os.getenv('DATADOG_SITE', 'datadoghq.com')
                }
            )
        
        # Slack Configuration
        if os.getenv('SLACK_BOT_TOKEN'):
            self.configs['slack'] = IntegrationConfig(
                type=IntegrationType.SLACK,
                enabled=True,
                config_data={
                    'bot_token': os.getenv('SLACK_BOT_TOKEN'),
                    'app_token': os.getenv('SLACK_APP_TOKEN')
                }
            )
        
        # PagerDuty Configuration
        if os.getenv('PAGERDUTY_API_KEY'):
            self.configs['pagerduty'] = IntegrationConfig(
                type=IntegrationType.PAGERDUTY,
                enabled=True,
                config_data={
                    'api_key': os.getenv('PAGERDUTY_API_KEY'),
                    'service_id': os.getenv('PAGERDUTY_SERVICE_ID')
                }
            )
        
        # Vault Configuration
        if os.getenv('VAULT_URL') and os.getenv('VAULT_TOKEN'):
            self.configs['vault'] = IntegrationConfig(
                type=IntegrationType.VAULT,
                enabled=True,
                config_data={
                    'url': os.getenv('VAULT_URL'),
                    'token': os.getenv('VAULT_TOKEN')
                }
            )
    
    def register_integration(self, name: str, integration_instance: Any) -> bool:
        """Register an integration instance."""
        try:
            self.integrations[name] = integration_instance
            
            # Initialize status
            self.status[name] = IntegrationStatus(
                name=name,
                type=self.configs.get(name, IntegrationConfig(IntegrationType.AWS)).type,
                status='registered',
                last_check=datetime.now(timezone.utc)
            )
            
            self.logger.info(f"Integration '{name}' registered successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to register integration '{name}': {e}")
            return False
    
    def get_integration(self, name: str) -> Optional[Any]:
        """Get an integration instance by name."""
        return self.integrations.get(name)
    
    def initialize_integration(self, name: str) -> bool:
        """Initialize an integration based on configuration."""
        try:
            if name not in self.configs:
                self.logger.warning(f"No configuration found for integration '{name}'")
                return False
            
            config = self.configs[name]
            if not config.enabled:
                self.logger.info(f"Integration '{name}' is disabled")
                return False
            
            # Initialize based on type
            if config.type == IntegrationType.AWS:
                from .aws_integration import AWSIntegration, AWSConfig
                aws_config = AWSConfig(**config.config_data)
                integration = AWSIntegration(aws_config)
                
            elif config.type == IntegrationType.OKTA:
                from .okta_integration import OktaIntegration, OktaConfig
                okta_config = OktaConfig(**config.config_data)
                integration = OktaIntegration(okta_config)
                
            elif config.type == IntegrationType.SNYK:
                from .snyk_integration import SnykIntegration, SnykConfig
                snyk_config = SnykConfig(**config.config_data)
                integration = SnykIntegration(snyk_config)
                
            elif config.type == IntegrationType.SUMOLOGIC:
                from .sumologic_integration import SumoLogicIntegration, SumoLogicConfig
                sumo_config = SumoLogicConfig(**config.config_data)
                integration = SumoLogicIntegration(sumo_config)
                
            else:
                self.logger.warning(f"Unsupported integration type: {config.type}")
                return False
            
            # Register the integration
            return self.register_integration(name, integration)
            
        except Exception as e:
            self.logger.error(f"Failed to initialize integration '{name}': {e}")
            return False
    
    def initialize_all(self) -> Dict[str, bool]:
        """Initialize all configured integrations."""
        results = {}
        
        for name in self.configs.keys():
            results[name] = self.initialize_integration(name)
        
        return results
    
    def health_check(self, name: str) -> Optional[Dict[str, Any]]:
        """Perform health check for a specific integration."""
        try:
            integration = self.get_integration(name)
            if not integration:
                self.logger.warning(f"Integration '{name}' not found")
                return None
            
            # Perform health check
            health_result = integration.health_check()
            
            # Update status
            if name in self.status:
                self.status[name].status = health_result.get('overall_status', 'unknown')
                self.status[name].last_check = datetime.now(timezone.utc)
                
                if health_result.get('overall_status') == 'unhealthy':
                    self.status[name].error_message = str(health_result.get('services', {}))
            
            return health_result
            
        except Exception as e:
            self.logger.error(f"Health check failed for integration '{name}': {e}")
            
            # Update status with error
            if name in self.status:
                self.status[name].status = 'error'
                self.status[name].error_message = str(e)
                self.status[name].last_check = datetime.now(timezone.utc)
            
            return None
    
    def health_check_all(self) -> Dict[str, Dict[str, Any]]:
        """Perform health check for all integrations."""
        results = {}
        
        for name in self.integrations.keys():
            results[name] = self.health_check(name) or {}
        
        return results
    
    def get_status(self) -> Dict[str, IntegrationStatus]:
        """Get status of all integrations."""
        return self.status.copy()
    
    def get_status_summary(self) -> Dict[str, Any]:
        """Get a summary of integration statuses."""
        total = len(self.status)
        healthy = sum(1 for status in self.status.values() if status.status == 'healthy')
        unhealthy = sum(1 for status in self.status.values() if status.status == 'unhealthy')
        error = sum(1 for status in self.status.values() if status.status == 'error')
        
        return {
            'total_integrations': total,
            'healthy': healthy,
            'unhealthy': unhealthy,
            'error': error,
            'overall_status': 'healthy' if unhealthy == 0 and error == 0 else 'unhealthy',
            'last_check': datetime.now(timezone.utc).isoformat()
        }
    
    def send_log_to_all(self, message: str, level: str = "INFO", 
                       fields: Dict[str, Any] = None) -> Dict[str, bool]:
        """Send a log message to all logging integrations."""
        results = {}
        
        # Send to Sumo Logic
        if 'sumologic' in self.integrations:
            try:
                from .sumologic_integration import SumoLogicLogLevel
                level_enum = SumoLogicLogLevel(level.lower())
                
                log = self.integrations['sumologic'].send_log_simple(
                    "secure-llm-proxy",
                    message,
                    level_enum,
                    fields
                )
                results['sumologic'] = log
            except Exception as e:
                self.logger.error(f"Failed to send log to Sumo Logic: {e}")
                results['sumologic'] = False
        
        # Send to Splunk
        if 'splunk' in self.integrations:
            try:
                log = self.integrations['splunk'].send_event(
                    "secure_llm_proxy",
                    {
                        "message": message,
                        "level": level,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        **(fields or {})
                    }
                )
                results['splunk'] = True
            except Exception as e:
                self.logger.error(f"Failed to send log to Splunk: {e}")
                results['splunk'] = False
        
        # Send to DataDog
        if 'datadog' in self.integrations:
            try:
                self.integrations['datadog'].send_metric(
                    "secure_llm_proxy.logs",
                    1,
                    tags=[f"level:{level}", "service:secure-llm-proxy"]
                )
                results['datadog'] = True
            except Exception as e:
                self.logger.error(f"Failed to send log to DataDog: {e}")
                results['datadog'] = False
        
        return results
    
    def send_alert_to_all(self, title: str, message: str, severity: str = "info") -> Dict[str, bool]:
        """Send an alert to all alerting integrations."""
        results = {}
        
        # Send to Slack
        if 'slack' in self.integrations:
            try:
                color_map = {
                    'info': 'good',
                    'warning': 'warning',
                    'error': 'danger',
                    'critical': 'danger'
                }
                
                self.integrations['slack'].send_message(
                    "security-alerts",
                    f"🚨 {title}",
                    attachments=[{
                        "color": color_map.get(severity, 'good'),
                        "text": message,
                        "fields": [
                            {"title": "Severity", "value": severity.upper(), "short": True},
                            {"title": "Time", "value": datetime.now(timezone.utc).isoformat(), "short": True}
                        ]
                    }]
                )
                results['slack'] = True
            except Exception as e:
                self.logger.error(f"Failed to send alert to Slack: {e}")
                results['slack'] = False
        
        # Send to PagerDuty
        if 'pagerduty' in self.integrations:
            try:
                urgency_map = {
                    'info': 'low',
                    'warning': 'low',
                    'error': 'high',
                    'critical': 'high'
                }
                
                self.integrations['pagerduty'].create_incident(
                    title,
                    message,
                    urgency=urgency_map.get(severity, 'low')
                )
                results['pagerduty'] = True
            except Exception as e:
                self.logger.error(f"Failed to send alert to PagerDuty: {e}")
                results['pagerduty'] = False
        
        return results
    
    def get_secret(self, secret_name: str, integration_name: str = None) -> Optional[str]:
        """Get a secret from the configured secret management integration."""
        # Try specified integration first
        if integration_name and integration_name in self.integrations:
            try:
                if integration_name == 'aws':
                    return self.integrations['aws'].retrieve_secret(secret_name)
                elif integration_name == 'vault':
                    secret = self.integrations['vault'].get_secret(secret_name)
                    return secret['data'].get('value') if secret else None
            except Exception as e:
                self.logger.error(f"Failed to get secret from {integration_name}: {e}")
        
        # Try AWS Secrets Manager (default)
        if 'aws' in self.integrations:
            try:
                return self.integrations['aws'].retrieve_secret(secret_name)
            except Exception as e:
                self.logger.error(f"Failed to get secret from AWS: {e}")
        
        # Try Vault
        if 'vault' in self.integrations:
            try:
                secret = self.integrations['vault'].get_secret(secret_name)
                return secret['data'].get('value') if secret else None
            except Exception as e:
                self.logger.error(f"Failed to get secret from Vault: {e}")
        
        return None
    
    def store_secret(self, secret_name: str, secret_value: str, 
                    integration_name: str = None) -> bool:
        """Store a secret in the configured secret management integration."""
        # Try specified integration first
        if integration_name and integration_name in self.integrations:
            try:
                if integration_name == 'aws':
                    self.integrations['aws'].store_secret(secret_name, secret_value)
                    return True
                elif integration_name == 'vault':
                    self.integrations['vault'].store_secret(secret_name, {"value": secret_value})
                    return True
            except Exception as e:
                self.logger.error(f"Failed to store secret in {integration_name}: {e}")
                return False
        
        # Try AWS Secrets Manager (default)
        if 'aws' in self.integrations:
            try:
                self.integrations['aws'].store_secret(secret_name, secret_value)
                return True
            except Exception as e:
                self.logger.error(f"Failed to store secret in AWS: {e}")
        
        # Try Vault
        if 'vault' in self.integrations:
            try:
                self.integrations['vault'].store_secret(secret_name, {"value": secret_value})
                return True
            except Exception as e:
                self.logger.error(f"Failed to store secret in Vault: {e}")
        
        return False
    
    def authenticate_user(self, username: str, password: str, 
                         integration_name: str = None) -> Optional[Dict]:
        """Authenticate a user using the configured identity integration."""
        # Try specified integration first
        if integration_name and integration_name in self.integrations:
            try:
                if integration_name == 'okta':
                    return self.integrations['okta'].authenticate_user(username, password)
            except Exception as e:
                self.logger.error(f"Failed to authenticate with {integration_name}: {e}")
        
        # Try Okta (default)
        if 'okta' in self.integrations:
            try:
                return self.integrations['okta'].authenticate_user(username, password)
            except Exception as e:
                self.logger.error(f"Failed to authenticate with Okta: {e}")
        
        return None
    
    def scan_vulnerabilities(self, target: str, scan_type: str = "project") -> Optional[Dict]:
        """Scan for vulnerabilities using the configured security integration."""
        if 'snyk' in self.integrations:
            try:
                if scan_type == "project":
                    return self.integrations['snyk'].scan_project(target)
                elif scan_type == "container":
                    return self.integrations['snyk'].scan_container_image(target)
                elif scan_type == "infrastructure":
                    return self.integrations['snyk'].scan_infrastructure(target)
            except Exception as e:
                self.logger.error(f"Failed to scan vulnerabilities: {e}")
        
        return None
    
    def list_integrations(self) -> List[str]:
        """List all registered integrations."""
        return list(self.integrations.keys())
    
    def list_configured_integrations(self) -> List[str]:
        """List all configured integrations."""
        return list(self.configs.keys())
    
    def enable_integration(self, name: str) -> bool:
        """Enable an integration."""
        if name in self.configs:
            self.configs[name].enabled = True
            self.logger.info(f"Integration '{name}' enabled")
            return True
        return False
    
    def disable_integration(self, name: str) -> bool:
        """Disable an integration."""
        if name in self.configs:
            self.configs[name].enabled = False
            self.logger.info(f"Integration '{name}' disabled")
            return True
        return False
    
    def remove_integration(self, name: str) -> bool:
        """Remove an integration."""
        if name in self.integrations:
            del self.integrations[name]
        
        if name in self.status:
            del self.status[name]
        
        if name in self.configs:
            del self.configs[name]
        
        self.logger.info(f"Integration '{name}' removed")
        return True
    
    def get_integration_info(self) -> Dict[str, Dict[str, Any]]:
        """Get detailed information about all integrations."""
        info = {}
        
        for name, integration in self.integrations.items():
            info[name] = {
                'type': self.configs.get(name, IntegrationConfig(IntegrationType.AWS)).type.value,
                'enabled': self.configs.get(name, IntegrationConfig(IntegrationType.AWS)).enabled,
                'status': self.status.get(name, IntegrationStatus(name, IntegrationType.AWS, 'unknown', datetime.now(timezone.utc))).status,
                'last_check': self.status.get(name, IntegrationStatus(name, IntegrationType.AWS, 'unknown', datetime.now(timezone.utc))).last_check.isoformat(),
                'class': integration.__class__.__name__
            }
        
        return info