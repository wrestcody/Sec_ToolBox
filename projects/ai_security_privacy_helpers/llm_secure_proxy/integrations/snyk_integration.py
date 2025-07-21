"""
Snyk Integration
Secure LLM Interaction Proxy

Provides integration with Snyk for:
- Vulnerability scanning and monitoring
- Dependency analysis
- Security compliance reporting
- Container image scanning
- Infrastructure as Code (IaC) scanning
- License compliance
- Security policy enforcement
"""

import os
import json
import requests
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import base64

class SnykIntegrationError(Exception):
    """Custom exception for Snyk integration errors."""
    pass

class SnykScanType(Enum):
    """Snyk scan types."""
    OPEN_SOURCE = "open_source"
    CONTAINER = "container"
    INFRASTRUCTURE = "infrastructure"
    CODE = "code"
    LICENSE = "license"

class SnykSeverity(Enum):
    """Snyk vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

@dataclass
class SnykConfig:
    """Snyk configuration settings."""
    api_token: str
    org_id: str
    base_url: str = "https://api.snyk.io"
    api_version: str = "v1"
    enable_monitoring: bool = True
    enable_scanning: bool = True
    enable_reporting: bool = True
    auto_fix: bool = False
    fail_on_critical: bool = True
    fail_on_high: bool = False
    scan_timeout_minutes: int = 30
    verify_ssl: bool = True

@dataclass
class SnykVulnerability:
    """Snyk vulnerability information."""
    id: str
    title: str
    description: str
    severity: SnykSeverity
    cvss_score: float
    cvss_vector: str
    cve_id: Optional[str]
    cwe_id: Optional[str]
    package_name: str
    package_version: str
    fixed_in: Optional[str]
    disclosure_time: str
    publish_time: str
    references: List[str]
    credit: List[str]

@dataclass
class SnykProject:
    """Snyk project information."""
    id: str
    name: str
    type: str
    owner: str
    created: str
    last_tested: Optional[str]
    total_dependencies: int
    vulnerabilities_count: Dict[str, int]
    status: str

@dataclass
class SnykScanResult:
    """Snyk scan result."""
    project_id: str
    scan_type: SnykScanType
    vulnerabilities: List[SnykVulnerability]
    summary: Dict[str, Any]
    scan_time: datetime
    scan_duration: float
    status: str

@dataclass
class SnykLicense:
    """Snyk license information."""
    id: str
    name: str
    severity: str
    description: str
    license_type: str
    package_name: str
    package_version: str

class SnykIntegration:
    """Snyk integration for security scanning and monitoring."""
    
    def __init__(self, config: SnykConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Initialize session
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Token {config.api_token}',
            'Content-Type': 'application/json'
        })
        
        # Verify SSL
        if not config.verify_ssl:
            self.session.verify = False
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # Base URL
        self.base_url = f"{config.base_url}/api/{config.api_version}"
    
    def _make_request(self, method: str, endpoint: str, data: Dict = None, 
                     params: Dict = None) -> Dict:
        """Make HTTP request to Snyk API."""
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
            self.logger.error(f"Snyk API request failed: {e}")
            raise SnykIntegrationError(f"Snyk API request failed: {e}")
    
    # Project Management
    def list_projects(self, org_id: str = None) -> List[SnykProject]:
        """List all projects in an organization."""
        try:
            org = org_id or self.config.org_id
            response = self._make_request('GET', f'/org/{org}/projects')
            
            projects = []
            for project_data in response.get('projects', []):
                project = SnykProject(
                    id=project_data['id'],
                    name=project_data['name'],
                    type=project_data['type'],
                    owner=project_data['owner'],
                    created=project_data['created'],
                    last_tested=project_data.get('lastTestedDate'),
                    total_dependencies=project_data.get('totalDependencies', 0),
                    vulnerabilities_count=project_data.get('issueCountsBySeverity', {}),
                    status=project_data.get('status', 'unknown')
                )
                projects.append(project)
            
            return projects
            
        except SnykIntegrationError as e:
            self.logger.error(f"Failed to list projects: {e}")
            return []
    
    def get_project(self, project_id: str, org_id: str = None) -> Optional[SnykProject]:
        """Get project by ID."""
        try:
            org = org_id or self.config.org_id
            response = self._make_request('GET', f'/org/{org}/project/{project_id}')
            
            return SnykProject(
                id=response['id'],
                name=response['name'],
                type=response['type'],
                owner=response['owner'],
                created=response['created'],
                last_tested=response.get('lastTestedDate'),
                total_dependencies=response.get('totalDependencies', 0),
                vulnerabilities_count=response.get('issueCountsBySeverity', {}),
                status=response.get('status', 'unknown')
            )
            
        except SnykIntegrationError:
            return None
    
    def create_project(self, name: str, project_type: str, target_file: str = None,
                      org_id: str = None) -> Optional[SnykProject]:
        """Create a new project."""
        try:
            org = org_id or self.config.org_id
            
            project_data = {
                'name': name,
                'type': project_type
            }
            
            if target_file:
                project_data['targetFile'] = target_file
            
            response = self._make_request('POST', f'/org/{org}/projects', data=project_data)
            
            return self.get_project(response['id'], org)
            
        except SnykIntegrationError as e:
            self.logger.error(f"Failed to create project: {e}")
            return None
    
    def delete_project(self, project_id: str, org_id: str = None) -> bool:
        """Delete a project."""
        try:
            org = org_id or self.config.org_id
            self._make_request('DELETE', f'/org/{org}/project/{project_id}')
            
            self.logger.info(f"Project {project_id} deleted successfully")
            return True
            
        except SnykIntegrationError as e:
            self.logger.error(f"Failed to delete project: {e}")
            return False
    
    # Vulnerability Scanning
    def scan_project(self, project_id: str, org_id: str = None) -> Optional[SnykScanResult]:
        """Scan a project for vulnerabilities."""
        try:
            org = org_id or self.config.org_id
            start_time = datetime.now(timezone.utc)
            
            # Trigger scan
            response = self._make_request('POST', f'/org/{org}/project/{project_id}/test')
            
            scan_duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            
            # Parse vulnerabilities
            vulnerabilities = []
            for issue in response.get('issues', {}).get('vulnerabilities', []):
                vuln = SnykVulnerability(
                    id=issue['id'],
                    title=issue['title'],
                    description=issue.get('description', ''),
                    severity=SnykSeverity(issue['severity']),
                    cvss_score=issue.get('cvssScore', 0.0),
                    cvss_vector=issue.get('cvssVector', ''),
                    cve_id=issue.get('identifiers', {}).get('CVE', [None])[0],
                    cwe_id=issue.get('identifiers', {}).get('CWE', [None])[0],
                    package_name=issue.get('packageName', ''),
                    package_version=issue.get('packageVersion', ''),
                    fixed_in=issue.get('fixedIn', [None])[0],
                    disclosure_time=issue.get('disclosureTime', ''),
                    publish_time=issue.get('publishTime', ''),
                    references=issue.get('references', []),
                    credit=issue.get('credit', [])
                )
                vulnerabilities.append(vuln)
            
            # Create summary
            summary = {
                'total_vulnerabilities': len(vulnerabilities),
                'critical_count': len([v for v in vulnerabilities if v.severity == SnykSeverity.CRITICAL]),
                'high_count': len([v for v in vulnerabilities if v.severity == SnykSeverity.HIGH]),
                'medium_count': len([v for v in vulnerabilities if v.severity == SnykSeverity.MEDIUM]),
                'low_count': len([v for v in vulnerabilities if v.severity == SnykSeverity.LOW])
            }
            
            return SnykScanResult(
                project_id=project_id,
                scan_type=SnykScanType.OPEN_SOURCE,
                vulnerabilities=vulnerabilities,
                summary=summary,
                scan_time=start_time,
                scan_duration=scan_duration,
                status='completed'
            )
            
        except SnykIntegrationError as e:
            self.logger.error(f"Failed to scan project: {e}")
            return None
    
    def scan_container_image(self, image_name: str, org_id: str = None) -> Optional[SnykScanResult]:
        """Scan a container image for vulnerabilities."""
        try:
            org = org_id or self.config.org_id
            start_time = datetime.now(timezone.utc)
            
            # Trigger container scan
            scan_data = {
                'image': image_name
            }
            
            response = self._make_request('POST', f'/org/{org}/test-dependencies', data=scan_data)
            
            scan_duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            
            # Parse vulnerabilities
            vulnerabilities = []
            for issue in response.get('issues', {}).get('vulnerabilities', []):
                vuln = SnykVulnerability(
                    id=issue['id'],
                    title=issue['title'],
                    description=issue.get('description', ''),
                    severity=SnykSeverity(issue['severity']),
                    cvss_score=issue.get('cvssScore', 0.0),
                    cvss_vector=issue.get('cvssVector', ''),
                    cve_id=issue.get('identifiers', {}).get('CVE', [None])[0],
                    cwe_id=issue.get('identifiers', {}).get('CWE', [None])[0],
                    package_name=issue.get('packageName', ''),
                    package_version=issue.get('packageVersion', ''),
                    fixed_in=issue.get('fixedIn', [None])[0],
                    disclosure_time=issue.get('disclosureTime', ''),
                    publish_time=issue.get('publishTime', ''),
                    references=issue.get('references', []),
                    credit=issue.get('credit', [])
                )
                vulnerabilities.append(vuln)
            
            # Create summary
            summary = {
                'total_vulnerabilities': len(vulnerabilities),
                'critical_count': len([v for v in vulnerabilities if v.severity == SnykSeverity.CRITICAL]),
                'high_count': len([v for v in vulnerabilities if v.severity == SnykSeverity.HIGH]),
                'medium_count': len([v for v in vulnerabilities if v.severity == SnykSeverity.MEDIUM]),
                'low_count': len([v for v in vulnerabilities if v.severity == SnykSeverity.LOW])
            }
            
            return SnykScanResult(
                project_id=image_name,
                scan_type=SnykScanType.CONTAINER,
                vulnerabilities=vulnerabilities,
                summary=summary,
                scan_time=start_time,
                scan_duration=scan_duration,
                status='completed'
            )
            
        except SnykIntegrationError as e:
            self.logger.error(f"Failed to scan container image: {e}")
            return None
    
    def scan_infrastructure(self, iac_file_path: str, org_id: str = None) -> Optional[SnykScanResult]:
        """Scan Infrastructure as Code files."""
        try:
            org = org_id or self.config.org_id
            start_time = datetime.now(timezone.utc)
            
            # Read IaC file
            with open(iac_file_path, 'r') as f:
                iac_content = f.read()
            
            # Trigger IaC scan
            scan_data = {
                'targetFile': iac_file_path,
                'content': base64.b64encode(iac_content.encode()).decode()
            }
            
            response = self._make_request('POST', f'/org/{org}/test-iac', data=scan_data)
            
            scan_duration = (datetime.now(timezone.utc) - start_time).total_seconds()
            
            # Parse vulnerabilities
            vulnerabilities = []
            for issue in response.get('issues', []):
                vuln = SnykVulnerability(
                    id=issue['id'],
                    title=issue['title'],
                    description=issue.get('description', ''),
                    severity=SnykSeverity(issue['severity']),
                    cvss_score=issue.get('cvssScore', 0.0),
                    cvss_vector=issue.get('cvssVector', ''),
                    cve_id=issue.get('identifiers', {}).get('CVE', [None])[0],
                    cwe_id=issue.get('identifiers', {}).get('CWE', [None])[0],
                    package_name=issue.get('packageName', ''),
                    package_version=issue.get('packageVersion', ''),
                    fixed_in=issue.get('fixedIn', [None])[0],
                    disclosure_time=issue.get('disclosureTime', ''),
                    publish_time=issue.get('publishTime', ''),
                    references=issue.get('references', []),
                    credit=issue.get('credit', [])
                )
                vulnerabilities.append(vuln)
            
            # Create summary
            summary = {
                'total_vulnerabilities': len(vulnerabilities),
                'critical_count': len([v for v in vulnerabilities if v.severity == SnykSeverity.CRITICAL]),
                'high_count': len([v for v in vulnerabilities if v.severity == SnykSeverity.HIGH]),
                'medium_count': len([v for v in vulnerabilities if v.severity == SnykSeverity.MEDIUM]),
                'low_count': len([v for v in vulnerabilities if v.severity == SnykSeverity.LOW])
            }
            
            return SnykScanResult(
                project_id=iac_file_path,
                scan_type=SnykScanType.INFRASTRUCTURE,
                vulnerabilities=vulnerabilities,
                summary=summary,
                scan_time=start_time,
                scan_duration=scan_duration,
                status='completed'
            )
            
        except SnykIntegrationError as e:
            self.logger.error(f"Failed to scan infrastructure: {e}")
            return None
    
    # License Compliance
    def check_licenses(self, project_id: str, org_id: str = None) -> List[SnykLicense]:
        """Check license compliance for a project."""
        try:
            org = org_id or self.config.org_id
            response = self._make_request('GET', f'/org/{org}/project/{project_id}/licenses')
            
            licenses = []
            for license_data in response.get('licenses', []):
                license_obj = SnykLicense(
                    id=license_data['id'],
                    name=license_data['name'],
                    severity=license_data['severity'],
                    description=license_data.get('description', ''),
                    license_type=license_data.get('licenseType', ''),
                    package_name=license_data.get('packageName', ''),
                    package_version=license_data.get('packageVersion', '')
                )
                licenses.append(license_obj)
            
            return licenses
            
        except SnykIntegrationError as e:
            self.logger.error(f"Failed to check licenses: {e}")
            return []
    
    # Monitoring
    def enable_monitoring(self, project_id: str, org_id: str = None) -> bool:
        """Enable monitoring for a project."""
        try:
            org = org_id or self.config.org_id
            self._make_request('POST', f'/org/{org}/project/{project_id}/monitor')
            
            self.logger.info(f"Monitoring enabled for project {project_id}")
            return True
            
        except SnykIntegrationError as e:
            self.logger.error(f"Failed to enable monitoring: {e}")
            return False
    
    def disable_monitoring(self, project_id: str, org_id: str = None) -> bool:
        """Disable monitoring for a project."""
        try:
            org = org_id or self.config.org_id
            self._make_request('DELETE', f'/org/{org}/project/{project_id}/monitor')
            
            self.logger.info(f"Monitoring disabled for project {project_id}")
            return True
            
        except SnykIntegrationError as e:
            self.logger.error(f"Failed to disable monitoring: {e}")
            return False
    
    # Auto-fix
    def apply_auto_fix(self, project_id: str, org_id: str = None) -> Dict:
        """Apply auto-fix for vulnerabilities."""
        try:
            org = org_id or self.config.org_id
            response = self._make_request('POST', f'/org/{org}/project/{project_id}/fix')
            
            self.logger.info(f"Auto-fix applied for project {project_id}")
            return response
            
        except SnykIntegrationError as e:
            self.logger.error(f"Failed to apply auto-fix: {e}")
            return {}
    
    # Reporting
    def generate_report(self, project_id: str, report_type: str = "json", 
                       org_id: str = None) -> Dict:
        """Generate security report for a project."""
        try:
            org = org_id or self.config.org_id
            params = {'format': report_type}
            
            response = self._make_request('GET', f'/org/{org}/project/{project_id}/report', params=params)
            
            return response
            
        except SnykIntegrationError as e:
            self.logger.error(f"Failed to generate report: {e}")
            return {}
    
    def get_organization_report(self, org_id: str = None) -> Dict:
        """Get organization-wide security report."""
        try:
            org = org_id or self.config.org_id
            response = self._make_request('GET', f'/org/{org}/report')
            
            return response
            
        except SnykIntegrationError as e:
            self.logger.error(f"Failed to get organization report: {e}")
            return {}
    
    # Policy Management
    def get_policies(self, org_id: str = None) -> List[Dict]:
        """Get security policies for an organization."""
        try:
            org = org_id or self.config.org_id
            response = self._make_request('GET', f'/org/{org}/policies')
            
            return response.get('policies', [])
            
        except SnykIntegrationError as e:
            self.logger.error(f"Failed to get policies: {e}")
            return []
    
    def create_policy(self, policy_data: Dict, org_id: str = None) -> Dict:
        """Create a new security policy."""
        try:
            org = org_id or self.config.org_id
            response = self._make_request('POST', f'/org/{org}/policies', data=policy_data)
            
            self.logger.info("Security policy created successfully")
            return response
            
        except SnykIntegrationError as e:
            self.logger.error(f"Failed to create policy: {e}")
            return {}
    
    # Integration with CI/CD
    def get_ci_integration_config(self, ci_platform: str) -> Dict:
        """Get CI/CD integration configuration."""
        try:
            response = self._make_request('GET', f'/ci/{ci_platform}/config')
            
            return response
            
        except SnykIntegrationError as e:
            self.logger.error(f"Failed to get CI integration config: {e}")
            return {}
    
    def test_ci_integration(self, ci_platform: str, config: Dict) -> bool:
        """Test CI/CD integration."""
        try:
            response = self._make_request('POST', f'/ci/{ci_platform}/test', data=config)
            
            if response.get('status') == 'success':
                self.logger.info(f"CI integration test passed for {ci_platform}")
                return True
            else:
                self.logger.error(f"CI integration test failed for {ci_platform}")
                return False
                
        except SnykIntegrationError as e:
            self.logger.error(f"Failed to test CI integration: {e}")
            return False
    
    # Webhook Management
    def create_webhook(self, webhook_data: Dict, org_id: str = None) -> Dict:
        """Create a webhook for notifications."""
        try:
            org = org_id or self.config.org_id
            response = self._make_request('POST', f'/org/{org}/webhooks', data=webhook_data)
            
            self.logger.info("Webhook created successfully")
            return response
            
        except SnykIntegrationError as e:
            self.logger.error(f"Failed to create webhook: {e}")
            return {}
    
    def list_webhooks(self, org_id: str = None) -> List[Dict]:
        """List webhooks for an organization."""
        try:
            org = org_id or self.config.org_id
            response = self._make_request('GET', f'/org/{org}/webhooks')
            
            return response.get('webhooks', [])
            
        except SnykIntegrationError as e:
            self.logger.error(f"Failed to list webhooks: {e}")
            return []
    
    # Vulnerability Assessment
    def assess_vulnerability_risk(self, scan_result: SnykScanResult) -> Dict[str, Any]:
        """Assess overall risk based on scan results."""
        risk_assessment = {
            'overall_risk': 'low',
            'risk_score': 0,
            'critical_issues': 0,
            'high_issues': 0,
            'medium_issues': 0,
            'low_issues': 0,
            'recommendations': []
        }
        
        # Count vulnerabilities by severity
        for vuln in scan_result.vulnerabilities:
            if vuln.severity == SnykSeverity.CRITICAL:
                risk_assessment['critical_issues'] += 1
            elif vuln.severity == SnykSeverity.HIGH:
                risk_assessment['high_issues'] += 1
            elif vuln.severity == SnykSeverity.MEDIUM:
                risk_assessment['medium_issues'] += 1
            elif vuln.severity == SnykSeverity.LOW:
                risk_assessment['low_issues'] += 1
        
        # Calculate risk score (weighted)
        risk_assessment['risk_score'] = (
            risk_assessment['critical_issues'] * 10 +
            risk_assessment['high_issues'] * 5 +
            risk_assessment['medium_issues'] * 2 +
            risk_assessment['low_issues'] * 1
        )
        
        # Determine overall risk level
        if risk_assessment['critical_issues'] > 0 or risk_assessment['risk_score'] >= 20:
            risk_assessment['overall_risk'] = 'critical'
        elif risk_assessment['high_issues'] > 0 or risk_assessment['risk_score'] >= 10:
            risk_assessment['overall_risk'] = 'high'
        elif risk_assessment['medium_issues'] > 0 or risk_assessment['risk_score'] >= 5:
            risk_assessment['overall_risk'] = 'medium'
        else:
            risk_assessment['overall_risk'] = 'low'
        
        # Generate recommendations
        if risk_assessment['critical_issues'] > 0:
            risk_assessment['recommendations'].append(
                "Immediate action required: Critical vulnerabilities detected"
            )
        if risk_assessment['high_issues'] > 0:
            risk_assessment['recommendations'].append(
                "High priority: Address high severity vulnerabilities"
            )
        if risk_assessment['medium_issues'] > 5:
            risk_assessment['recommendations'].append(
                "Consider addressing medium severity vulnerabilities"
            )
        
        return risk_assessment
    
    # Health Check
    def health_check(self) -> Dict[str, Any]:
        """Perform health check of Snyk integration."""
        health_status = {
            'overall_status': 'healthy',
            'services': {},
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        # Check API connectivity
        try:
            self._make_request('GET', '/user/me')
            health_status['services']['api'] = 'healthy'
        except Exception as e:
            health_status['services']['api'] = f'unhealthy: {str(e)}'
            health_status['overall_status'] = 'unhealthy'
        
        # Check organization access
        try:
            self._make_request('GET', f'/org/{self.config.org_id}')
            health_status['services']['organization'] = 'healthy'
        except Exception as e:
            health_status['services']['organization'] = f'unhealthy: {str(e)}'
            health_status['overall_status'] = 'unhealthy'
        
        return health_status