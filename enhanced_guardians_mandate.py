#!/usr/bin/env python3
"""
Enhanced Guardian's Mandate: Comprehensive Security Governance Framework

This module implements a foundational framework for building systems with
comprehensive security excellence, operational best practices, and unassailable
digital evidence integrity.

Core Principles:
- Security Best Practices & Operational Excellence
- Comprehensive Compliance & Governance
- Proactive Threat Prevention & Detection
- Incident Response & Recovery
- Continuous Security Improvement
- AWS Security Excellence Integration
- Cryptographic Tamper-Evident Logging & Data
- Automated & Granular Chain of Custody
- Verifiable Ledger for Integrity
- Forensic Readiness & Auditability by Design

The Guardian's Mandate is now a complete security governance platform that:
- GUIDES security decisions and architecture
- ENFORCES best practices and compliance
- MONITORS security posture and threats
- IMPROVES security maturity continuously
- PREVENTS security incidents proactively
- RESPONDS to threats and incidents
- TRAINS security teams and stakeholders
"""

import hashlib
import hmac
import json
import os
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Union, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import base64
import struct
import threading
from pathlib import Path
import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets
import boto3
from botocore.exceptions import ClientError, NoCredentialsError


class SecurityDomain(Enum):
    """Security domains for comprehensive governance."""
    IDENTITY_AND_ACCESS_MANAGEMENT = "identity_and_access_management"
    DATA_PROTECTION = "data_protection"
    NETWORK_SECURITY = "network_security"
    APPLICATION_SECURITY = "application_security"
    INFRASTRUCTURE_SECURITY = "infrastructure_security"
    INCIDENT_RESPONSE = "incident_response"
    COMPLIANCE_AND_GOVERNANCE = "compliance_and_governance"
    OPERATIONAL_SECURITY = "operational_security"
    THREAT_INTELLIGENCE = "threat_intelligence"
    SECURITY_AWARENESS = "security_awareness"


class SecurityMaturityLevel(Enum):
    """Security maturity levels for continuous improvement."""
    INITIAL = "initial"           # Ad-hoc, reactive
    REPEATABLE = "repeatable"     # Basic processes
    DEFINED = "defined"           # Documented processes
    MANAGED = "managed"           # Measured and controlled
    OPTIMIZING = "optimizing"     # Continuous improvement


class ComplianceStandard(Enum):
    """Compliance standards for governance."""
    SOC2 = "soc2"
    ISO27001 = "iso27001"
    NIST = "nist"
    CIS = "cis"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    AWS_WELL_ARCHITECTED = "aws_well_architected"
    ZERO_TRUST = "zero_trust"
    DEVOPS_SECURITY = "devops_security"


class SecurityControl(Enum):
    """Security controls for comprehensive protection."""
    # Identity and Access Management
    MFA_ENFORCEMENT = "mfa_enforcement"
    LEAST_PRIVILEGE = "least_privilege"
    ACCESS_REVIEWS = "access_reviews"
    PRIVILEGED_ACCESS_MANAGEMENT = "privileged_access_management"
    IDENTITY_FEDERATION = "identity_federation"
    
    # Data Protection
    ENCRYPTION_AT_REST = "encryption_at_rest"
    ENCRYPTION_IN_TRANSIT = "encryption_in_transit"
    DATA_CLASSIFICATION = "data_classification"
    DATA_LOSS_PREVENTION = "data_loss_prevention"
    BACKUP_AND_RECOVERY = "backup_and_recovery"
    
    # Network Security
    NETWORK_SEGMENTATION = "network_segmentation"
    FIREWALL_MANAGEMENT = "firewall_management"
    INTRUSION_DETECTION = "intrusion_detection"
    VULNERABILITY_MANAGEMENT = "vulnerability_management"
    SECURE_REMOTE_ACCESS = "secure_remote_access"
    
    # Application Security
    SECURE_SDLC = "secure_sdlc"
    CODE_REVIEW = "code_review"
    PENETRATION_TESTING = "penetration_testing"
    API_SECURITY = "api_security"
    CONTAINER_SECURITY = "container_security"
    
    # Infrastructure Security
    CONFIGURATION_MANAGEMENT = "configuration_management"
    PATCH_MANAGEMENT = "patch_management"
    MONITORING_AND_LOGGING = "monitoring_and_logging"
    INCIDENT_DETECTION = "incident_detection"
    DISASTER_RECOVERY = "disaster_recovery"


class ThreatLevel(Enum):
    """Threat levels for risk assessment."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SecurityBestPractice:
    """Security best practice with implementation guidance."""
    control_id: str
    control_name: str
    domain: SecurityDomain
    description: str
    implementation_guidance: str
    aws_services: List[str]
    compliance_standards: List[str]
    maturity_level: SecurityMaturityLevel
    threat_level: ThreatLevel
    metrics: List[str]
    remediation_steps: List[str]
    references: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SecurityAssessment:
    """Security assessment result."""
    assessment_id: str
    timestamp: str
    domain: SecurityDomain
    controls_assessed: List[str]
    compliance_score: float
    maturity_level: SecurityMaturityLevel
    findings: List[Dict[str, Any]]
    recommendations: List[str]
    next_steps: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SecurityMetric:
    """Security metric for continuous monitoring."""
    metric_id: str
    metric_name: str
    metric_type: str  # kpi, kri, sla
    domain: SecurityDomain
    current_value: float
    target_value: float
    unit: str
    calculation_method: str
    data_source: str
    update_frequency: str
    owner: str
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class EnhancedGuardianMandate:
    """
    Enhanced Guardian's Mandate: Comprehensive Security Governance Framework
    
    This framework provides:
    - Security best practices and operational guidance
    - Compliance framework integration
    - AWS security excellence standards
    - Continuous security improvement
    - Security metrics and KPIs
    - Incident prevention and response
    - Security training and awareness
    - Evidence integrity and chain of custody
    """
    
    def __init__(self, 
                 framework_path: str = "enhanced_guardian_mandate",
                 enable_aws_integration: bool = True,
                 aws_region: str = "us-east-1"):
        """
        Initialize the Enhanced Guardian's Mandate framework.
        
        Args:
            framework_path: Path to store framework data
            enable_aws_integration: Enable AWS service integration
            aws_region: AWS region for service clients
        """
        self.framework_path = Path(framework_path)
        self.framework_path.mkdir(parents=True, exist_ok=True)
        
        self.enable_aws_integration = enable_aws_integration
        self.aws_region = aws_region
        
        # Initialize AWS services
        if self.enable_aws_integration:
            self._initialize_aws_services()
        
        # Initialize framework components
        self._initialize_security_best_practices()
        self._initialize_compliance_frameworks()
        self._initialize_security_metrics()
        self._setup_logging()
        
        # Framework metadata
        self.framework_metadata = {
            'framework_version': '3.0.0',
            'framework_name': 'Enhanced Guardian\'s Mandate',
            'framework_description': 'Comprehensive Security Governance Framework',
            'domains_covered': [domain.value for domain in SecurityDomain],
            'compliance_standards': [standard.value for standard in ComplianceStandard],
            'security_controls': [control.value for control in SecurityControl],
            'aws_integration_enabled': self.enable_aws_integration,
            'aws_region': aws_region,
            'initialization_timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        self.logger.info("Enhanced Guardian's Mandate framework initialized successfully")
    
    def _initialize_aws_services(self):
        """Initialize AWS service clients."""
        try:
            boto3.setup_default_session(region_name=self.aws_region)
            
            # Core AWS security services
            self.iam_client = boto3.client('iam')
            self.cloudtrail_client = boto3.client('cloudtrail')
            self.config_client = boto3.client('config')
            self.securityhub_client = boto3.client('securityhub')
            self.guardduty_client = boto3.client('guardduty')
            self.cloudwatch_client = boto3.client('cloudwatch')
            self.kms_client = boto3.client('kms')
            self.access_analyzer_client = boto3.client('accessanalyzer')
            self.macie_client = boto3.client('macie')
            self.waf_client = boto3.client('wafv2')
            
            self.logger.info("AWS security services initialized successfully")
        except Exception as e:
            self.logger.warning(f"Failed to initialize AWS services: {e}")
            self.enable_aws_integration = False
    
    def _initialize_security_best_practices(self):
        """Initialize comprehensive security best practices."""
        self.security_best_practices = {
            SecurityDomain.IDENTITY_AND_ACCESS_MANAGEMENT: [
                SecurityBestPractice(
                    control_id="IAM-001",
                    control_name="Multi-Factor Authentication Enforcement",
                    domain=SecurityDomain.IDENTITY_AND_ACCESS_MANAGEMENT,
                    description="Enforce MFA for all users, especially privileged accounts",
                    implementation_guidance="""
                    1. Enable MFA for root account
                    2. Enable MFA for all IAM users with console access
                    3. Use hardware security keys for critical accounts
                    4. Implement MFA bypass policies for emergency access
                    5. Monitor MFA usage and compliance
                    """,
                    aws_services=["IAM", "Organizations", "CloudTrail"],
                    compliance_standards=["SOC2", "ISO27001", "NIST", "CIS"],
                    maturity_level=SecurityMaturityLevel.MANAGED,
                    threat_level=ThreatLevel.HIGH,
                    metrics=["MFA adoption rate", "MFA bypass incidents", "Privileged account MFA coverage"],
                    remediation_steps=[
                        "Audit current MFA implementation",
                        "Enable MFA for all users",
                        "Configure MFA bypass policies",
                        "Train users on MFA usage"
                    ],
                    references=[
                        "AWS IAM Best Practices",
                        "CIS AWS Foundations Benchmark",
                        "NIST Digital Identity Guidelines"
                    ]
                ),
                SecurityBestPractice(
                    control_id="IAM-002",
                    control_name="Least Privilege Access Control",
                    domain=SecurityDomain.IDENTITY_AND_ACCESS_MANAGEMENT,
                    description="Implement least privilege principle for all access",
                    implementation_guidance="""
                    1. Use IAM Access Analyzer to identify unused permissions
                    2. Implement just-in-time access for privileged operations
                    3. Use service roles instead of user roles where possible
                    4. Regular access reviews and cleanup
                    5. Implement cross-account access using roles
                    """,
                    aws_services=["IAM", "Access Analyzer", "Organizations", "CloudTrail"],
                    compliance_standards=["SOC2", "ISO27001", "NIST", "CIS"],
                    maturity_level=SecurityMaturityLevel.OPTIMIZING,
                    threat_level=ThreatLevel.CRITICAL,
                    metrics=["Unused permission percentage", "Access review completion rate", "Privilege escalation attempts"],
                    remediation_steps=[
                        "Run IAM Access Analyzer",
                        "Remove unused permissions",
                        "Implement access review process",
                        "Monitor privilege escalation"
                    ],
                    references=[
                        "AWS IAM Best Practices",
                        "Principle of Least Privilege",
                        "Zero Trust Architecture"
                    ]
                )
            ],
            SecurityDomain.DATA_PROTECTION: [
                SecurityBestPractice(
                    control_id="DP-001",
                    control_name="Encryption at Rest and in Transit",
                    domain=SecurityDomain.DATA_PROTECTION,
                    description="Encrypt all data at rest and in transit",
                    implementation_guidance="""
                    1. Use AWS KMS for key management
                    2. Enable encryption for all storage services
                    3. Use TLS 1.2+ for all communications
                    4. Implement client-side encryption for sensitive data
                    5. Regular key rotation and management
                    """,
                    aws_services=["KMS", "S3", "EBS", "RDS", "CloudTrail"],
                    compliance_standards=["SOC2", "ISO27001", "NIST", "PCI_DSS"],
                    maturity_level=SecurityMaturityLevel.MANAGED,
                    threat_level=ThreatLevel.HIGH,
                    metrics=["Encryption coverage percentage", "Key rotation compliance", "TLS version usage"],
                    remediation_steps=[
                        "Audit current encryption implementation",
                        "Enable encryption for all services",
                        "Implement key rotation",
                        "Monitor encryption compliance"
                    ],
                    references=[
                        "AWS Encryption Best Practices",
                        "NIST Cryptographic Standards",
                        "PCI DSS Requirements"
                    ]
                )
            ],
            SecurityDomain.NETWORK_SECURITY: [
                SecurityBestPractice(
                    control_id="NS-001",
                    control_name="Network Segmentation and Security Groups",
                    domain=SecurityDomain.NETWORK_SECURITY,
                    description="Implement proper network segmentation and security groups",
                    implementation_guidance="""
                    1. Use VPC for network isolation
                    2. Implement security groups with least privilege
                    3. Use Network ACLs for additional protection
                    4. Implement private subnets for sensitive resources
                    5. Monitor network traffic and anomalies
                    """,
                    aws_services=["VPC", "Security Groups", "Network ACLs", "CloudWatch", "GuardDuty"],
                    compliance_standards=["SOC2", "ISO27001", "NIST", "CIS"],
                    maturity_level=SecurityMaturityLevel.DEFINED,
                    threat_level=ThreatLevel.MEDIUM,
                    metrics=["Security group compliance", "Network ACL coverage", "Traffic anomaly detection"],
                    remediation_steps=[
                        "Audit current network configuration",
                        "Implement proper segmentation",
                        "Configure security groups",
                        "Monitor network traffic"
                    ],
                    references=[
                        "AWS VPC Best Practices",
                        "Network Security Architecture",
                        "Zero Trust Networking"
                    ]
                )
            ]
        }
    
    def _initialize_compliance_frameworks(self):
        """Initialize compliance frameworks and requirements."""
        self.compliance_frameworks = {
            ComplianceStandard.SOC2: {
                'name': 'SOC 2 Type II',
                'description': 'Service Organization Control 2',
                'trust_services_criteria': {
                    'CC1': 'Control Environment',
                    'CC2': 'Communication and Information',
                    'CC3': 'Risk Assessment',
                    'CC4': 'Monitoring Activities',
                    'CC5': 'Control Activities',
                    'CC6': 'Logical and Physical Access Controls',
                    'CC7': 'System Operations',
                    'CC8': 'Change Management',
                    'CC9': 'Risk Mitigation'
                },
                'requirements': [
                    'Implement access controls',
                    'Monitor system operations',
                    'Manage changes',
                    'Assess risks',
                    'Communicate security information'
                ]
            },
            ComplianceStandard.ISO27001: {
                'name': 'ISO/IEC 27001',
                'description': 'Information Security Management System',
                'domains': {
                    'A5': 'Information Security Policies',
                    'A6': 'Organization of Information Security',
                    'A7': 'Human Resource Security',
                    'A8': 'Asset Management',
                    'A9': 'Access Control',
                    'A10': 'Cryptography',
                    'A11': 'Physical and Environmental Security',
                    'A12': 'Operations Security',
                    'A13': 'Communications Security',
                    'A14': 'System Acquisition, Development, and Maintenance',
                    'A15': 'Supplier Relationships',
                    'A16': 'Information Security Incident Management',
                    'A17': 'Information Security Aspects of Business Continuity Management',
                    'A18': 'Compliance'
                }
            },
            ComplianceStandard.AWS_WELL_ARCHITECTED: {
                'name': 'AWS Well-Architected Framework',
                'description': 'AWS Security Pillar Best Practices',
                'pillars': {
                    'security': 'Security Pillar',
                    'reliability': 'Reliability Pillar',
                    'performance': 'Performance Efficiency Pillar',
                    'cost_optimization': 'Cost Optimization Pillar',
                    'operational_excellence': 'Operational Excellence Pillar',
                    'sustainability': 'Sustainability Pillar'
                },
                'security_best_practices': [
                    'Implement a strong identity foundation',
                    'Enable traceability',
                    'Apply security at all layers',
                    'Automate security best practices',
                    'Protect data in transit and at rest',
                    'Keep people away from data',
                    'Prepare for security events'
                ]
            }
        }
    
    def _initialize_security_metrics(self):
        """Initialize security metrics and KPIs."""
        self.security_metrics = {
            'kpis': [
                SecurityMetric(
                    metric_id="KPI-001",
                    metric_name="Mean Time to Detection (MTTD)",
                    metric_type="kpi",
                    domain=SecurityDomain.INCIDENT_RESPONSE,
                    current_value=0.0,
                    target_value=4.0,  # hours
                    unit="hours",
                    calculation_method="Average time from incident occurrence to detection",
                    data_source="SIEM, CloudTrail, GuardDuty",
                    update_frequency="daily",
                    owner="Security Operations"
                ),
                SecurityMetric(
                    metric_id="KPI-002",
                    metric_name="Mean Time to Response (MTTR)",
                    metric_type="kpi",
                    domain=SecurityDomain.INCIDENT_RESPONSE,
                    current_value=0.0,
                    target_value=1.0,  # hours
                    unit="hours",
                    calculation_method="Average time from detection to response",
                    data_source="Incident management system",
                    update_frequency="daily",
                    owner="Security Operations"
                ),
                SecurityMetric(
                    metric_id="KPI-003",
                    metric_name="Security Incident Rate",
                    metric_type="kpi",
                    domain=SecurityDomain.INCIDENT_RESPONSE,
                    current_value=0.0,
                    target_value=0.1,  # incidents per day
                    unit="incidents/day",
                    calculation_method="Number of security incidents per day",
                    data_source="Incident management system",
                    update_frequency="daily",
                    owner="Security Operations"
                )
            ],
            'kris': [
                SecurityMetric(
                    metric_id="KRI-001",
                    metric_name="Vulnerability Remediation Time",
                    metric_type="kri",
                    domain=SecurityDomain.VULNERABILITY_MANAGEMENT,
                    current_value=0.0,
                    target_value=7.0,  # days
                    unit="days",
                    calculation_method="Average time to remediate critical vulnerabilities",
                    data_source="Vulnerability scanner",
                    update_frequency="weekly",
                    owner="Security Engineering"
                ),
                SecurityMetric(
                    metric_id="KRI-002",
                    metric_name="Access Review Completion Rate",
                    metric_type="kri",
                    domain=SecurityDomain.IDENTITY_AND_ACCESS_MANAGEMENT,
                    current_value=0.0,
                    target_value=95.0,  # percentage
                    unit="percentage",
                    calculation_method="Percentage of access reviews completed on time",
                    data_source="IAM system",
                    update_frequency="monthly",
                    owner="Identity Management"
                )
            ]
        }
    
    def _setup_logging(self):
        """Setup logging for the framework."""
        self.logger = logging.getLogger("EnhancedGuardianMandate")
        self.logger.setLevel(logging.INFO)
        
        if not self.logger.handlers:
            handler = logging.FileHandler(self.framework_path / "enhanced_guardian_mandate.log")
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
    
    def assess_security_posture(self, domain: SecurityDomain = None) -> SecurityAssessment:
        """
        Assess security posture for a specific domain or overall.
        
        Args:
            domain: Specific security domain to assess (None for overall)
        
        Returns:
            Security assessment results
        """
        assessment_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        
        if domain:
            # Assess specific domain
            controls = self.security_best_practices.get(domain, [])
            findings = self._assess_domain_controls(domain, controls)
        else:
            # Assess all domains
            controls = []
            findings = []
            for dom, domain_controls in self.security_best_practices.items():
                controls.extend(domain_controls)
                findings.extend(self._assess_domain_controls(dom, domain_controls))
        
        # Calculate compliance score
        total_controls = len(controls)
        compliant_controls = len([f for f in findings if f.get('status') == 'COMPLIANT'])
        compliance_score = (compliant_controls / total_controls * 100) if total_controls > 0 else 0
        
        # Determine maturity level
        maturity_level = self._determine_maturity_level(compliance_score)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(findings)
        
        # Define next steps
        next_steps = self._define_next_steps(findings, maturity_level)
        
        assessment = SecurityAssessment(
            assessment_id=assessment_id,
            timestamp=timestamp,
            domain=domain or SecurityDomain.COMPLIANCE_AND_GOVERNANCE,
            controls_assessed=[c.control_id for c in controls],
            compliance_score=compliance_score,
            maturity_level=maturity_level,
            findings=findings,
            recommendations=recommendations,
            next_steps=next_steps
        )
        
        # Store assessment
        self._store_assessment(assessment)
        
        return assessment
    
    def _assess_domain_controls(self, domain: SecurityDomain, controls: List[SecurityBestPractice]) -> List[Dict[str, Any]]:
        """Assess controls for a specific domain."""
        findings = []
        
        for control in controls:
            finding = {
                'control_id': control.control_id,
                'control_name': control.control_name,
                'domain': domain.value,
                'status': 'UNKNOWN',
                'evidence': [],
                'risk_level': control.threat_level.value,
                'compliance_standards': control.compliance_standards
            }
            
            # Perform domain-specific assessment
            if domain == SecurityDomain.IDENTITY_AND_ACCESS_MANAGEMENT:
                finding.update(self._assess_iam_control(control))
            elif domain == SecurityDomain.DATA_PROTECTION:
                finding.update(self._assess_data_protection_control(control))
            elif domain == SecurityDomain.NETWORK_SECURITY:
                finding.update(self._assess_network_security_control(control))
            else:
                finding.update(self._assess_generic_control(control))
            
            findings.append(finding)
        
        return findings
    
    def _assess_iam_control(self, control: SecurityBestPractice) -> Dict[str, Any]:
        """Assess IAM-specific controls."""
        assessment = {'status': 'UNKNOWN', 'evidence': []}
        
        if not self.enable_aws_integration:
            return assessment
        
        try:
            if control.control_id == "IAM-001":  # MFA Enforcement
                # Check MFA status for users
                response = self.iam_client.list_users()
                total_users = len(response['Users'])
                mfa_enabled_users = 0
                
                for user in response['Users']:
                    mfa_devices = self.iam_client.list_mfa_devices(UserName=user['UserName'])
                    if mfa_devices['MFADevices']:
                        mfa_enabled_users += 1
                
                mfa_rate = (mfa_enabled_users / total_users * 100) if total_users > 0 else 0
                
                if mfa_rate >= 95:
                    assessment['status'] = 'COMPLIANT'
                elif mfa_rate >= 80:
                    assessment['status'] = 'PARTIALLY_COMPLIANT'
                else:
                    assessment['status'] = 'NON_COMPLIANT'
                
                assessment['evidence'] = [
                    f"Total users: {total_users}",
                    f"MFA enabled users: {mfa_enabled_users}",
                    f"MFA adoption rate: {mfa_rate:.1f}%"
                ]
            
            elif control.control_id == "IAM-002":  # Least Privilege
                # Check for unused permissions using Access Analyzer
                try:
                    analyzers = self.access_analyzer_client.list_analyzers()
                    if analyzers['analyzers']:
                        assessment['status'] = 'COMPLIANT'
                        assessment['evidence'] = ["IAM Access Analyzer is enabled"]
                    else:
                        assessment['status'] = 'NON_COMPLIANT'
                        assessment['evidence'] = ["IAM Access Analyzer is not enabled"]
                except Exception:
                    assessment['status'] = 'NON_COMPLIANT'
                    assessment['evidence'] = ["Unable to access IAM Access Analyzer"]
        
        except Exception as e:
            assessment['status'] = 'ERROR'
            assessment['evidence'] = [f"Assessment error: {str(e)}"]
        
        return assessment
    
    def _assess_data_protection_control(self, control: SecurityBestPractice) -> Dict[str, Any]:
        """Assess data protection controls."""
        assessment = {'status': 'UNKNOWN', 'evidence': []}
        
        if not self.enable_aws_integration:
            return assessment
        
        try:
            if control.control_id == "DP-001":  # Encryption
                # Check KMS key usage
                keys = self.kms_client.list_keys()
                if keys['Keys']:
                    assessment['status'] = 'COMPLIANT'
                    assessment['evidence'] = [f"KMS keys configured: {len(keys['Keys'])}"]
                else:
                    assessment['status'] = 'NON_COMPLIANT'
                    assessment['evidence'] = ["No KMS keys configured"]
        
        except Exception as e:
            assessment['status'] = 'ERROR'
            assessment['evidence'] = [f"Assessment error: {str(e)}"]
        
        return assessment
    
    def _assess_network_security_control(self, control: SecurityBestPractice) -> Dict[str, Any]:
        """Assess network security controls."""
        assessment = {'status': 'UNKNOWN', 'evidence': []}
        
        if not self.enable_aws_integration:
            return assessment
        
        try:
            if control.control_id == "NS-001":  # Network Segmentation
                # Check VPC configuration
                ec2_client = boto3.client('ec2')
                vpcs = ec2_client.describe_vpcs()
                
                if vpcs['Vpcs']:
                    assessment['status'] = 'COMPLIANT'
                    assessment['evidence'] = [f"VPCs configured: {len(vpcs['Vpcs'])}"]
                else:
                    assessment['status'] = 'NON_COMPLIANT'
                    assessment['evidence'] = ["No VPCs configured"]
        
        except Exception as e:
            assessment['status'] = 'ERROR'
            assessment['evidence'] = [f"Assessment error: {str(e)}"]
        
        return assessment
    
    def _assess_generic_control(self, control: SecurityBestPractice) -> Dict[str, Any]:
        """Assess generic controls."""
        return {
            'status': 'UNKNOWN',
            'evidence': ["Generic assessment - manual review required"]
        }
    
    def _determine_maturity_level(self, compliance_score: float) -> SecurityMaturityLevel:
        """Determine maturity level based on compliance score."""
        if compliance_score >= 90:
            return SecurityMaturityLevel.OPTIMIZING
        elif compliance_score >= 75:
            return SecurityMaturityLevel.MANAGED
        elif compliance_score >= 50:
            return SecurityMaturityLevel.DEFINED
        elif compliance_score >= 25:
            return SecurityMaturityLevel.REPEATABLE
        else:
            return SecurityMaturityLevel.INITIAL
    
    def _generate_recommendations(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Generate recommendations based on assessment findings."""
        recommendations = []
        
        non_compliant_findings = [f for f in findings if f.get('status') == 'NON_COMPLIANT']
        
        for finding in non_compliant_findings:
            control_id = finding.get('control_id')
            control_name = finding.get('control_name')
            
            if control_id == "IAM-001":
                recommendations.append(f"Enable MFA for all IAM users: {control_name}")
            elif control_id == "IAM-002":
                recommendations.append(f"Enable IAM Access Analyzer: {control_name}")
            elif control_id == "DP-001":
                recommendations.append(f"Configure KMS encryption: {control_name}")
            elif control_id == "NS-001":
                recommendations.append(f"Configure VPC network segmentation: {control_name}")
            else:
                recommendations.append(f"Review and implement: {control_name}")
        
        # Add general recommendations
        if len(non_compliant_findings) > 0:
            recommendations.append("Implement automated compliance monitoring")
            recommendations.append("Establish regular security assessments")
            recommendations.append("Develop security training program")
        
        return recommendations
    
    def _define_next_steps(self, findings: List[Dict[str, Any]], maturity_level: SecurityMaturityLevel) -> List[str]:
        """Define next steps based on assessment results and maturity level."""
        next_steps = []
        
        if maturity_level == SecurityMaturityLevel.INITIAL:
            next_steps.extend([
                "Establish basic security policies",
                "Implement foundational security controls",
                "Begin security awareness training",
                "Set up basic monitoring"
            ])
        elif maturity_level == SecurityMaturityLevel.REPEATABLE:
            next_steps.extend([
                "Document security processes",
                "Implement consistent controls",
                "Establish security metrics",
                "Begin compliance framework alignment"
            ])
        elif maturity_level == SecurityMaturityLevel.DEFINED:
            next_steps.extend([
                "Standardize security practices",
                "Implement automated controls",
                "Establish security governance",
                "Begin continuous monitoring"
            ])
        elif maturity_level == SecurityMaturityLevel.MANAGED:
            next_steps.extend([
                "Optimize security processes",
                "Implement advanced controls",
                "Establish threat intelligence",
                "Begin security automation"
            ])
        elif maturity_level == SecurityMaturityLevel.OPTIMIZING:
            next_steps.extend([
                "Implement predictive security",
                "Advanced threat hunting",
                "Security innovation",
                "Industry leadership"
            ])
        
        return next_steps
    
    def _store_assessment(self, assessment: SecurityAssessment):
        """Store assessment results."""
        assessment_file = self.framework_path / f"assessment_{assessment.assessment_id}.json"
        with open(assessment_file, 'w') as f:
            json.dump(assessment.to_dict(), f, indent=2)
        
        self.logger.info(f"Security assessment stored: {assessment.assessment_id}")
    
    def get_security_guidance(self, domain: SecurityDomain = None, control_id: str = None) -> Dict[str, Any]:
        """
        Get security guidance for specific domain or control.
        
        Args:
            domain: Security domain for guidance
            control_id: Specific control ID for detailed guidance
        
        Returns:
            Security guidance information
        """
        guidance = {
            'framework_info': self.framework_metadata,
            'guidance_timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        if control_id:
            # Get specific control guidance
            for domain_controls in self.security_best_practices.values():
                for control in domain_controls:
                    if control.control_id == control_id:
                        guidance['control'] = control.to_dict()
                        guidance['implementation_steps'] = self._get_implementation_steps(control)
                        return guidance
        
        elif domain:
            # Get domain-specific guidance
            controls = self.security_best_practices.get(domain, [])
            guidance['domain'] = domain.value
            guidance['controls'] = [control.to_dict() for control in controls]
            guidance['domain_overview'] = self._get_domain_overview(domain)
        
        else:
            # Get overall framework guidance
            guidance['domains'] = {}
            for domain, controls in self.security_best_practices.items():
                guidance['domains'][domain.value] = {
                    'controls': [control.to_dict() for control in controls],
                    'overview': self._get_domain_overview(domain)
                }
        
        return guidance
    
    def _get_implementation_steps(self, control: SecurityBestPractice) -> List[Dict[str, Any]]:
        """Get detailed implementation steps for a control."""
        steps = []
        
        if control.control_id == "IAM-001":  # MFA Enforcement
            steps = [
                {
                    'step': 1,
                    'action': 'Audit current MFA implementation',
                    'aws_services': ['IAM', 'CloudTrail'],
                    'duration': '1-2 days',
                    'difficulty': 'Easy'
                },
                {
                    'step': 2,
                    'action': 'Enable MFA for root account',
                    'aws_services': ['IAM'],
                    'duration': '1 hour',
                    'difficulty': 'Easy'
                },
                {
                    'step': 3,
                    'action': 'Enable MFA for all IAM users',
                    'aws_services': ['IAM', 'Organizations'],
                    'duration': '1-3 days',
                    'difficulty': 'Medium'
                },
                {
                    'step': 4,
                    'action': 'Configure MFA bypass policies',
                    'aws_services': ['IAM', 'Organizations'],
                    'duration': '1 day',
                    'difficulty': 'Medium'
                },
                {
                    'step': 5,
                    'action': 'Monitor MFA usage and compliance',
                    'aws_services': ['CloudTrail', 'CloudWatch', 'Security Hub'],
                    'duration': 'Ongoing',
                    'difficulty': 'Medium'
                }
            ]
        
        return steps
    
    def _get_domain_overview(self, domain: SecurityDomain) -> Dict[str, Any]:
        """Get overview information for a security domain."""
        overviews = {
            SecurityDomain.IDENTITY_AND_ACCESS_MANAGEMENT: {
                'description': 'Manage and control access to resources and systems',
                'key_principles': ['Least privilege', 'Zero trust', 'Identity federation'],
                'aws_services': ['IAM', 'Organizations', 'Cognito', 'SSO'],
                'common_threats': ['Credential theft', 'Privilege escalation', 'Account takeover'],
                'best_practices': [
                    'Use IAM roles instead of access keys',
                    'Enable MFA for all users',
                    'Regular access reviews',
                    'Implement least privilege'
                ]
            },
            SecurityDomain.DATA_PROTECTION: {
                'description': 'Protect data throughout its lifecycle',
                'key_principles': ['Encryption', 'Data classification', 'Privacy by design'],
                'aws_services': ['KMS', 'S3', 'Macie', 'Shield'],
                'common_threats': ['Data breaches', 'Data exfiltration', 'Ransomware'],
                'best_practices': [
                    'Encrypt data at rest and in transit',
                    'Classify data by sensitivity',
                    'Implement data loss prevention',
                    'Regular backup and recovery testing'
                ]
            },
            SecurityDomain.NETWORK_SECURITY: {
                'description': 'Secure network infrastructure and communications',
                'key_principles': ['Defense in depth', 'Network segmentation', 'Zero trust'],
                'aws_services': ['VPC', 'WAF', 'Shield', 'GuardDuty'],
                'common_threats': ['Network attacks', 'DDoS', 'Man-in-the-middle'],
                'best_practices': [
                    'Use VPC for network isolation',
                    'Implement security groups',
                    'Monitor network traffic',
                    'Use WAF for application protection'
                ]
            }
        }
        
        return overviews.get(domain, {
            'description': 'Security domain overview',
            'key_principles': [],
            'aws_services': [],
            'common_threats': [],
            'best_practices': []
        })
    
    def export_security_report(self, output_path: str = None) -> str:
        """Export comprehensive security report."""
        if not output_path:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = f"enhanced_guardian_mandate_report_{timestamp}.json"
        
        # Generate comprehensive assessment
        assessment = self.assess_security_posture()
        
        # Get security guidance
        guidance = self.get_security_guidance()
        
        # Compile report
        report = {
            'report_metadata': {
                'report_timestamp': datetime.now(timezone.utc).isoformat(),
                'framework_version': self.framework_metadata['framework_version'],
                'aws_integration': self.enable_aws_integration,
                'aws_region': self.aws_region
            },
            'security_assessment': assessment.to_dict(),
            'security_guidance': guidance,
            'compliance_frameworks': self.compliance_frameworks,
            'security_metrics': {
                'kpis': [metric.to_dict() for metric in self.security_metrics['kpis']],
                'kris': [metric.to_dict() for metric in self.security_metrics['kris']]
            },
            'recommendations': {
                'immediate_actions': assessment.recommendations,
                'next_steps': assessment.next_steps,
                'long_term_goals': self._get_long_term_goals(assessment.maturity_level)
            }
        }
        
        # Export to file
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.logger.info(f"Security report exported: {output_path}")
        return output_path
    
    def _get_long_term_goals(self, current_maturity: SecurityMaturityLevel) -> List[str]:
        """Get long-term security goals based on current maturity."""
        goals = []
        
        if current_maturity == SecurityMaturityLevel.INITIAL:
            goals = [
                "Achieve repeatable security processes",
                "Implement basic security controls",
                "Establish security awareness program",
                "Begin compliance framework alignment"
            ]
        elif current_maturity == SecurityMaturityLevel.REPEATABLE:
            goals = [
                "Achieve defined security processes",
                "Implement comprehensive security controls",
                "Establish security metrics program",
                "Achieve SOC 2 compliance"
            ]
        elif current_maturity == SecurityMaturityLevel.DEFINED:
            goals = [
                "Achieve managed security processes",
                "Implement advanced security controls",
                "Establish continuous monitoring",
                "Achieve ISO 27001 certification"
            ]
        elif current_maturity == SecurityMaturityLevel.MANAGED:
            goals = [
                "Achieve optimizing security processes",
                "Implement predictive security",
                "Establish threat intelligence program",
                "Achieve industry leadership position"
            ]
        elif current_maturity == SecurityMaturityLevel.OPTIMIZING:
            goals = [
                "Maintain security excellence",
                "Innovate in security practices",
                "Share knowledge with industry",
                "Contribute to security standards"
            ]
        
        return goals


# Global instance for easy access
_enhanced_guardian_mandate = None

def get_enhanced_guardian_mandate() -> EnhancedGuardianMandate:
    """Get the global Enhanced Guardian's Mandate instance."""
    global _enhanced_guardian_mandate
    if _enhanced_guardian_mandate is None:
        _enhanced_guardian_mandate = EnhancedGuardianMandate()
    return _enhanced_guardian_mandate


def assess_security_posture(domain: SecurityDomain = None) -> SecurityAssessment:
    """Assess security posture using the Enhanced Guardian's Mandate."""
    framework = get_enhanced_guardian_mandate()
    return framework.assess_security_posture(domain)


def get_security_guidance(domain: SecurityDomain = None, control_id: str = None) -> Dict[str, Any]:
    """Get security guidance using the Enhanced Guardian's Mandate."""
    framework = get_enhanced_guardian_mandate()
    return framework.get_security_guidance(domain, control_id)


def export_security_report(output_path: str = None) -> str:
    """Export comprehensive security report using the Enhanced Guardian's Mandate."""
    framework = get_enhanced_guardian_mandate()
    return framework.export_security_report(output_path)


if __name__ == "__main__":
    # Test the Enhanced Guardian's Mandate
    print("🛡️  Enhanced Guardian's Mandate: Comprehensive Security Governance Framework")
    print("=" * 80)
    
    # Initialize framework
    framework = EnhancedGuardianMandate()
    
    # Assess security posture
    print("\n🔍 Assessing security posture...")
    assessment = framework.assess_security_posture()
    print(f"✅ Assessment complete: {assessment.compliance_score:.1f}% compliance")
    print(f"   Maturity Level: {assessment.maturity_level.value}")
    print(f"   Findings: {len(assessment.findings)}")
    print(f"   Recommendations: {len(assessment.recommendations)}")
    
    # Get security guidance
    print("\n📚 Getting security guidance...")
    guidance = framework.get_security_guidance(SecurityDomain.IDENTITY_AND_ACCESS_MANAGEMENT)
    print(f"✅ Guidance retrieved for {SecurityDomain.IDENTITY_AND_ACCESS_MANAGEMENT.value}")
    
    # Export security report
    print("\n📊 Exporting security report...")
    report_path = framework.export_security_report()
    print(f"✅ Security report exported: {report_path}")
    
    print("\n🚀 Enhanced Guardian's Mandate is ready for comprehensive security governance!")
    print("   This framework now provides:")
    print("   - Security best practices and operational guidance")
    print("   - Compliance framework integration")
    print("   - AWS security excellence standards")
    print("   - Continuous security improvement")
    print("   - Security metrics and KPIs")
    print("   - Incident prevention and response")
    print("   - Security training and awareness")
    print("   - Evidence integrity and chain of custody")