"""
Sumo Logic Integration
Secure LLM Interaction Proxy

Provides integration with Sumo Logic for:
- Log analytics and monitoring
- Real-time log ingestion
- Log search and querying
- Dashboard creation
- Alert management
- Metrics collection
"""

import os
import json
import requests
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib
import hmac

class SumoLogicIntegrationError(Exception):
    """Custom exception for Sumo Logic integration errors."""
    pass

class SumoLogicLogLevel(Enum):
    """Sumo Logic log levels."""
    DEBUG = "debug"
    INFO = "info"
    WARN = "warn"
    ERROR = "error"
    FATAL = "fatal"

@dataclass
class SumoLogicConfig:
    """Sumo Logic configuration settings."""
    access_id: str
    access_key: str
    endpoint: str = "https://api.sumologic.com"
    api_version: str = "v1"
    enable_logging: bool = True
    enable_search: bool = True
    enable_alerts: bool = True
    log_retention_days: int = 90
    batch_size: int = 100
    verify_ssl: bool = True

@dataclass
class SumoLogicLog:
    """Sumo Logic log entry."""
    message: str
    timestamp: datetime
    level: SumoLogicLogLevel
    source_name: str
    source_category: str
    source_host: str
    fields: Dict[str, Any]

@dataclass
class SumoLogicSearchResult:
    """Sumo Logic search result."""
    query: str
    results: List[Dict]
    total_count: int
    search_time: datetime
    execution_time_ms: int

@dataclass
class SumoLogicAlert:
    """Sumo Logic alert configuration."""
    id: str
    name: str
    description: str
    query: str
    threshold: float
    time_range: str
    severity: str
    status: str

class SumoLogicIntegration:
    """Sumo Logic integration for log analytics and monitoring."""
    
    def __init__(self, config: SumoLogicConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Initialize session
        self.session = requests.Session()
        self.session.auth = (config.access_id, config.access_key)
        self.session.headers.update({
            'Content-Type': 'application/json'
        })
        
        # Verify SSL
        if not config.verify_ssl:
            self.session.verify = False
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # Base URL
        self.base_url = f"{config.endpoint}/api/{config.api_version}"
    
    def _make_request(self, method: str, endpoint: str, data: Dict = None, 
                     params: Dict = None) -> Dict:
        """Make HTTP request to Sumo Logic API."""
        url = f"{self.base_url}{endpoint}"
        
        try:
            response = self.session.request(
                method=method,
                url=url,
                json=data,
                params=params
            )
            response.raise_for_status()
            
            if response.content:
                return response.json()
            return {}
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Sumo Logic API request failed: {e}")
            raise SumoLogicIntegrationError(f"Sumo Logic API request failed: {e}")
    
    def _get_headers(self, method: str, url: str, timestamp: str, body: str = "") -> Dict:
        """Generate authentication headers for Sumo Logic API."""
        # Create signature
        signature_string = f"{method}\n\n\n{timestamp}\n{url}"
        if body:
            signature_string = f"{method}\n\n\n{timestamp}\n{url}\n{body}"
        
        signature = hmac.new(
            self.config.access_key.encode('utf-8'),
            signature_string.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        return {
            'Authorization': f'Bearer {self.config.access_id}:{signature}',
            'X-Sumo-Date': timestamp,
            'Content-Type': 'application/json'
        }
    
    # Log Management
    def send_log(self, log: SumoLogicLog) -> bool:
        """Send a single log entry to Sumo Logic."""
        try:
            # Prepare log data
            log_data = {
                'message': log.message,
                'timestamp': log.timestamp.isoformat(),
                'level': log.level.value,
                'sourceName': log.source_name,
                'sourceCategory': log.source_category,
                'sourceHost': log.source_host,
                'fields': log.fields
            }
            
            # Generate headers
            timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
            url = f"{self.config.endpoint}/receiver/v1/http/{self.config.access_id}"
            
            headers = self._get_headers('POST', url, timestamp, json.dumps(log_data))
            
            # Send log
            response = requests.post(
                url,
                json=log_data,
                headers=headers
            )
            response.raise_for_status()
            
            self.logger.debug(f"Log sent to Sumo Logic: {log.message[:50]}...")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send log: {e}")
            return False
    
    def send_logs_batch(self, logs: List[SumoLogicLog]) -> Dict[str, int]:
        """Send multiple logs in a batch."""
        success_count = 0
        failure_count = 0
        
        for log in logs:
            if self.send_log(log):
                success_count += 1
            else:
                failure_count += 1
        
        return {
            'success_count': success_count,
            'failure_count': failure_count,
            'total_count': len(logs)
        }
    
    def send_log_simple(self, source_category: str, message: str, 
                       level: SumoLogicLogLevel = SumoLogicLogLevel.INFO,
                       fields: Dict[str, Any] = None) -> bool:
        """Send a simple log message."""
        log = SumoLogicLog(
            message=message,
            timestamp=datetime.now(timezone.utc),
            level=level,
            source_name="secure-llm-proxy",
            source_category=source_category,
            source_host=os.getenv('HOSTNAME', 'unknown'),
            fields=fields or {}
        )
        
        return self.send_log(log)
    
    # Search and Query
    def search_logs(self, query: str, start_time: str = None, end_time: str = None,
                   limit: int = 100) -> Optional[SumoLogicSearchResult]:
        """Search logs using Sumo Logic query language."""
        try:
            # Prepare search request
            search_data = {
                'query': query,
                'from': start_time or (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
                'to': end_time or datetime.now(timezone.utc).isoformat(),
                'timeZone': 'UTC'
            }
            
            # Start search job
            response = self._make_request('POST', '/search/jobs', data=search_data)
            job_id = response['id']
            
            # Wait for completion
            while True:
                status_response = self._make_request('GET', f'/search/jobs/{job_id}')
                
                if status_response['state'] == 'DONE GATHERING RESULTS':
                    break
                elif status_response['state'] == 'CANCELLED':
                    raise SumoLogicIntegrationError("Search job was cancelled")
                
                import time
                time.sleep(1)
            
            # Get results
            results_response = self._make_request(
                'GET', 
                f'/search/jobs/{job_id}/messages',
                params={'limit': limit}
            )
            
            return SumoLogicSearchResult(
                query=query,
                results=results_response.get('messages', []),
                total_count=status_response.get('messageCount', 0),
                search_time=datetime.now(timezone.utc),
                execution_time_ms=status_response.get('executionTime', 0)
            )
            
        except SumoLogicIntegrationError as e:
            self.logger.error(f"Failed to search logs: {e}")
            return None
    
    def search_logs_simple(self, source_category: str, message_pattern: str = None,
                          level: SumoLogicLogLevel = None, hours: int = 24) -> List[Dict]:
        """Simple log search with common filters."""
        query_parts = [f'_sourceCategory={source_category}']
        
        if message_pattern:
            query_parts.append(f'"{message_pattern}"')
        
        if level:
            query_parts.append(f'level={level.value}')
        
        query = ' AND '.join(query_parts)
        
        search_result = self.search_logs(
            query,
            start_time=(datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(),
            end_time=datetime.now(timezone.utc).isoformat()
        )
        
        return search_result.results if search_result else []
    
    # Dashboard Management
    def create_dashboard(self, name: str, description: str, 
                        panels: List[Dict]) -> Optional[Dict]:
        """Create a Sumo Logic dashboard."""
        try:
            dashboard_data = {
                'title': name,
                'description': description,
                'panels': panels,
                'layout': {
                    'gridLayout': {
                        'layoutType': 'grid'
                    }
                }
            }
            
            response = self._make_request('POST', '/dashboards', data=dashboard_data)
            
            self.logger.info(f"Dashboard '{name}' created successfully")
            return response
            
        except SumoLogicIntegrationError as e:
            self.logger.error(f"Failed to create dashboard: {e}")
            return None
    
    def get_dashboard(self, dashboard_id: str) -> Optional[Dict]:
        """Get dashboard by ID."""
        try:
            response = self._make_request('GET', f'/dashboards/{dashboard_id}')
            return response
            
        except SumoLogicIntegrationError as e:
            self.logger.error(f"Failed to get dashboard: {e}")
            return None
    
    def list_dashboards(self) -> List[Dict]:
        """List all dashboards."""
        try:
            response = self._make_request('GET', '/dashboards')
            return response.get('dashboards', [])
            
        except SumoLogicIntegrationError as e:
            self.logger.error(f"Failed to list dashboards: {e}")
            return []
    
    def update_dashboard(self, dashboard_id: str, updates: Dict) -> bool:
        """Update dashboard."""
        try:
            self._make_request('PUT', f'/dashboards/{dashboard_id}', data=updates)
            
            self.logger.info(f"Dashboard {dashboard_id} updated successfully")
            return True
            
        except SumoLogicIntegrationError as e:
            self.logger.error(f"Failed to update dashboard: {e}")
            return False
    
    def delete_dashboard(self, dashboard_id: str) -> bool:
        """Delete dashboard."""
        try:
            self._make_request('DELETE', f'/dashboards/{dashboard_id}')
            
            self.logger.info(f"Dashboard {dashboard_id} deleted successfully")
            return True
            
        except SumoLogicIntegrationError as e:
            self.logger.error(f"Failed to delete dashboard: {e}")
            return False
    
    # Alert Management
    def create_alert(self, alert: SumoLogicAlert) -> Optional[Dict]:
        """Create a Sumo Logic alert."""
        try:
            alert_data = {
                'name': alert.name,
                'description': alert.description,
                'query': alert.query,
                'threshold': alert.threshold,
                'timeRange': alert.time_range,
                'severity': alert.severity,
                'type': 'metric'
            }
            
            response = self._make_request('POST', '/monitors', data=alert_data)
            
            self.logger.info(f"Alert '{alert.name}' created successfully")
            return response
            
        except SumoLogicIntegrationError as e:
            self.logger.error(f"Failed to create alert: {e}")
            return None
    
    def get_alert(self, alert_id: str) -> Optional[Dict]:
        """Get alert by ID."""
        try:
            response = self._make_request('GET', f'/monitors/{alert_id}')
            return response
            
        except SumoLogicIntegrationError as e:
            self.logger.error(f"Failed to get alert: {e}")
            return None
    
    def list_alerts(self) -> List[Dict]:
        """List all alerts."""
        try:
            response = self._make_request('GET', '/monitors')
            return response.get('monitors', [])
            
        except SumoLogicIntegrationError as e:
            self.logger.error(f"Failed to list alerts: {e}")
            return []
    
    def update_alert(self, alert_id: str, updates: Dict) -> bool:
        """Update alert."""
        try:
            self._make_request('PUT', f'/monitors/{alert_id}', data=updates)
            
            self.logger.info(f"Alert {alert_id} updated successfully")
            return True
            
        except SumoLogicIntegrationError as e:
            self.logger.error(f"Failed to update alert: {e}")
            return False
    
    def delete_alert(self, alert_id: str) -> bool:
        """Delete alert."""
        try:
            self._make_request('DELETE', f'/monitors/{alert_id}')
            
            self.logger.info(f"Alert {alert_id} deleted successfully")
            return True
            
        except SumoLogicIntegrationError as e:
            self.logger.error(f"Failed to delete alert: {e}")
            return False
    
    # Metrics Collection
    def send_metric(self, metric_name: str, value: float, 
                   dimensions: Dict[str, str] = None, timestamp: datetime = None) -> bool:
        """Send a metric to Sumo Logic."""
        try:
            if timestamp is None:
                timestamp = datetime.now(timezone.utc)
            
            metric_data = {
                'metric': metric_name,
                'value': value,
                'timestamp': timestamp.isoformat(),
                'dimensions': dimensions or {}
            }
            
            # Generate headers
            timestamp_str = timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')
            url = f"{self.config.endpoint}/receiver/v1/http/{self.config.access_id}"
            
            headers = self._get_headers('POST', url, timestamp_str, json.dumps(metric_data))
            
            # Send metric
            response = requests.post(
                url,
                json=metric_data,
                headers=headers
            )
            response.raise_for_status()
            
            self.logger.debug(f"Metric sent to Sumo Logic: {metric_name}={value}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send metric: {e}")
            return False
    
    def send_metrics_batch(self, metrics: List[Dict]) -> Dict[str, int]:
        """Send multiple metrics in a batch."""
        success_count = 0
        failure_count = 0
        
        for metric in metrics:
            if self.send_metric(
                metric['name'],
                metric['value'],
                metric.get('dimensions'),
                metric.get('timestamp')
            ):
                success_count += 1
            else:
                failure_count += 1
        
        return {
            'success_count': success_count,
            'failure_count': failure_count,
            'total_count': len(metrics)
        }
    
    # Content Management
    def create_content(self, name: str, content_type: str, content: str,
                      description: str = None) -> Optional[Dict]:
        """Create content (saved searches, dashboards, etc.)."""
        try:
            content_data = {
                'name': name,
                'type': content_type,
                'content': content
            }
            
            if description:
                content_data['description'] = description
            
            response = self._make_request('POST', '/content', data=content_data)
            
            self.logger.info(f"Content '{name}' created successfully")
            return response
            
        except SumoLogicIntegrationError as e:
            self.logger.error(f"Failed to create content: {e}")
            return None
    
    def get_content(self, content_id: str) -> Optional[Dict]:
        """Get content by ID."""
        try:
            response = self._make_request('GET', f'/content/{content_id}')
            return response
            
        except SumoLogicIntegrationError as e:
            self.logger.error(f"Failed to get content: {e}")
            return None
    
    def list_content(self, content_type: str = None) -> List[Dict]:
        """List content with optional type filter."""
        try:
            params = {}
            if content_type:
                params['type'] = content_type
            
            response = self._make_request('GET', '/content', params=params)
            return response.get('data', [])
            
        except SumoLogicIntegrationError as e:
            self.logger.error(f"Failed to list content: {e}")
            return []
    
    # User and Role Management
    def get_users(self) -> List[Dict]:
        """Get all users."""
        try:
            response = self._make_request('GET', '/users')
            return response.get('data', [])
            
        except SumoLogicIntegrationError as e:
            self.logger.error(f"Failed to get users: {e}")
            return []
    
    def get_roles(self) -> List[Dict]:
        """Get all roles."""
        try:
            response = self._make_request('GET', '/roles')
            return response.get('data', [])
            
        except SumoLogicIntegrationError as e:
            self.logger.error(f"Failed to get roles: {e}")
            return []
    
    # Health Check
    def health_check(self) -> Dict[str, Any]:
        """Perform health check of Sumo Logic integration."""
        health_status = {
            'overall_status': 'healthy',
            'services': {},
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        # Check API connectivity
        try:
            self._make_request('GET', '/users')
            health_status['services']['api'] = 'healthy'
        except Exception as e:
            health_status['services']['api'] = f'unhealthy: {str(e)}'
            health_status['overall_status'] = 'unhealthy'
        
        # Check log ingestion
        try:
            test_log = SumoLogicLog(
                message="Health check test log",
                timestamp=datetime.now(timezone.utc),
                level=SumoLogicLogLevel.INFO,
                source_name="secure-llm-proxy",
                source_category="health-check",
                source_host="health-check",
                fields={"test": True}
            )
            
            if self.send_log(test_log):
                health_status['services']['log_ingestion'] = 'healthy'
            else:
                health_status['services']['log_ingestion'] = 'unhealthy'
                health_status['overall_status'] = 'unhealthy'
                
        except Exception as e:
            health_status['services']['log_ingestion'] = f'unhealthy: {str(e)}'
            health_status['overall_status'] = 'unhealthy'
        
        return health_status