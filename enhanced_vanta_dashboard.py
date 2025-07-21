#!/usr/bin/env python3
"""
Enhanced Vanta-Style GRC Dashboard with Detailed Technical Transparency
=====================================================================

A comprehensive dashboard that shows:
- Beautiful dark-mode interface inspired by Vanta Trust
- Detailed technical parameters with full transparency
- Data source attribution and evidence trails
- Real-time monitoring status
- Drill-down capabilities for technical details
- Framework-specific compliance views

Author: Guardians Forge
"""

import json
import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

class ControlStatus(Enum):
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    NOT_APPLICABLE = "not_applicable"

class DataSource(Enum):
    AWS_CLOUDTRAIL = "aws_cloudtrail"
    AWS_CONFIG = "aws_config"
    AWS_SECURITY_HUB = "aws_security_hub"
    AWS_GUARDDUTY = "aws_guardduty"
    AWS_IAM = "aws_iam"
    AWS_S3 = "aws_s3"
    AWS_EC2 = "aws_ec2"
    MANUAL_ASSESSMENT = "manual_assessment"
    API_SCAN = "api_scan"
    CODE_ANALYSIS = "code_analysis"
    PENETRATION_TEST = "penetration_test"
    VULNERABILITY_SCAN = "vulnerability_scan"

@dataclass
class TechnicalParameter:
    """Detailed technical parameter with full transparency"""
    parameter_id: str
    name: str
    description: str
    expected_value: str
    actual_value: str
    status: ControlStatus
    data_source: DataSource
    last_checked: datetime.datetime
    evidence: str
    raw_data: Dict[str, Any]  # Raw technical data
    remediation_steps: List[str]
    risk_level: str
    automation_level: str  # Fully Automated, Semi-Automated, Manual
    check_frequency: str
    owner: str

@dataclass
class SecurityControl:
    """Security control with comprehensive technical details"""
    control_id: str
    name: str
    description: str
    framework: str
    category: str
    status: ControlStatus
    parameters: List[TechnicalParameter]
    last_assessment: datetime.datetime
    next_assessment: datetime.datetime
    owner: str
    priority: str
    automated: bool
    evidence_summary: str
    technical_details: Dict[str, Any]

class EnhancedVantaDashboard:
    """Enhanced dashboard with detailed technical transparency"""
    
    def __init__(self):
        self.controls: Dict[str, SecurityControl] = {}
        self._initialize_detailed_controls()
    
    def _initialize_detailed_controls(self):
        """Initialize controls with comprehensive technical details"""
        
        # Access Control - SOC2 CC6.1 with detailed parameters
        access_params = [
            TechnicalParameter(
                parameter_id="acc_001",
                name="IAM User Access Review",
                description="Verify quarterly access reviews for all IAM users",
                expected_value="All users reviewed within last 90 days",
                actual_value="Last review: 2024-01-15 (45 days ago)",
                status=ControlStatus.PASSED,
                data_source=DataSource.AWS_IAM,
                last_checked=datetime.datetime.now() - datetime.timedelta(hours=2),
                evidence="AWS IAM API call: ListUsers() shows 45 users, all reviewed",
                raw_data={
                    "total_users": 45,
                    "reviewed_users": 45,
                    "last_review_date": "2024-01-15",
                    "reviewer": "security-team",
                    "api_calls": ["ListUsers", "GetUser", "ListAccessKeys"],
                    "compliance_score": 100
                },
                remediation_steps=["Schedule next quarterly review", "Document review process"],
                risk_level="High",
                automation_level="Fully Automated",
                check_frequency="Daily",
                owner="Security Team"
            ),
            TechnicalParameter(
                parameter_id="acc_002",
                name="MFA Enforcement",
                description="Ensure MFA is enabled for all IAM users",
                expected_value="MFA enabled for 100% of users",
                actual_value="MFA enabled for 98% of users (2 users pending)",
                status=ControlStatus.WARNING,
                data_source=DataSource.AWS_SECURITY_HUB,
                last_checked=datetime.datetime.now() - datetime.timedelta(hours=1),
                evidence="Security Hub finding: 2 IAM users without MFA devices",
                raw_data={
                    "total_users": 45,
                    "mfa_enabled_users": 43,
                    "mfa_disabled_users": 2,
                    "finding_id": "arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/IAM.1/finding/12345678-1234-1234-1234-123456789012",
                    "severity": "MEDIUM",
                    "compliance_score": 95.6
                },
                remediation_steps=["Enable MFA for remaining users", "Set MFA enforcement policy"],
                risk_level="Critical",
                automation_level="Fully Automated",
                check_frequency="Hourly",
                owner="Security Team"
            ),
            TechnicalParameter(
                parameter_id="acc_003",
                name="Privileged Access Management",
                description="Verify privileged access is limited and monitored",
                expected_value="No users with excessive permissions",
                actual_value="3 users with admin privileges identified",
                status=ControlStatus.FAILED,
                data_source=DataSource.AWS_CLOUDTRAIL,
                last_checked=datetime.datetime.now() - datetime.timedelta(minutes=30),
                evidence="CloudTrail logs show admin actions by non-admin users",
                raw_data={
                    "admin_users": 3,
                    "admin_actions_last_24h": 15,
                    "unauthorized_admin_actions": 3,
                    "cloudtrail_logs": [
                        {"timestamp": "2024-02-22T10:30:00Z", "user": "user1", "action": "CreateUser"},
                        {"timestamp": "2024-02-22T11:15:00Z", "user": "user2", "action": "DeleteRole"}
                    ],
                    "compliance_score": 0
                },
                remediation_steps=["Review admin privileges", "Implement least privilege principle"],
                risk_level="Critical",
                automation_level="Semi-Automated",
                check_frequency="Real-time",
                owner="Security Team"
            )
        ]
        
        self.controls["CC6.1"] = SecurityControl(
            control_id="CC6.1",
            name="Access Control",
            description="The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events to meet the entity's objectives.",
            framework="SOC2",
            category="Access Control",
            status=ControlStatus.WARNING,
            parameters=access_params,
            last_assessment=datetime.datetime.now() - datetime.timedelta(hours=2),
            next_assessment=datetime.datetime.now() + datetime.timedelta(days=7),
            owner="Security Team",
            priority="Critical",
            automated=True,
            evidence_summary="2/3 parameters passed, 1 warning, 1 failed",
            technical_details={
                "automation_coverage": "85%",
                "api_integrations": ["AWS IAM", "AWS Security Hub", "AWS CloudTrail"],
                "monitoring_frequency": "Real-time",
                "compliance_frameworks": ["SOC2", "ISO27001", "NIST"],
                "risk_assessment": "High"
            }
        )
        
        # Data Protection - SOC2 CC6.7
        data_protection_params = [
            TechnicalParameter(
                parameter_id="dp_001",
                name="S3 Bucket Encryption",
                description="Verify all S3 buckets are encrypted at rest",
                expected_value="100% of S3 buckets encrypted",
                actual_value="100% of S3 buckets encrypted with AES-256",
                status=ControlStatus.PASSED,
                data_source=DataSource.AWS_S3,
                last_checked=datetime.datetime.now() - datetime.timedelta(hours=3),
                evidence="AWS S3 API: GetBucketEncryption() returned encryption config for all buckets",
                raw_data={
                    "total_buckets": 12,
                    "encrypted_buckets": 12,
                    "encryption_algorithm": "AES256",
                    "bucket_names": ["prod-data", "backup-data", "logs-data"],
                    "compliance_score": 100
                },
                remediation_steps=["Continue monitoring encryption status"],
                risk_level="High",
                automation_level="Fully Automated",
                check_frequency="Daily",
                owner="Infrastructure Team"
            ),
            TechnicalParameter(
                parameter_id="dp_002",
                name="TLS Configuration",
                description="Verify TLS 1.2+ is enforced on all endpoints",
                expected_value="TLS 1.2+ enforced on all endpoints",
                actual_value="TLS 1.2+ enforced on 95% of endpoints",
                status=ControlStatus.WARNING,
                data_source=DataSource.API_SCAN,
                last_checked=datetime.datetime.now() - datetime.timedelta(hours=4),
                evidence="API scan found 2 legacy endpoints using TLS 1.1",
                raw_data={
                    "total_endpoints": 20,
                    "tls_12_endpoints": 18,
                    "tls_11_endpoints": 2,
                    "endpoint_urls": ["https://legacy-api1.example.com", "https://legacy-api2.example.com"],
                    "compliance_score": 90
                },
                remediation_steps=["Upgrade legacy endpoints to TLS 1.2+", "Deprecate old endpoints"],
                risk_level="Medium",
                automation_level="Semi-Automated",
                check_frequency="Weekly",
                owner="Infrastructure Team"
            )
        ]
        
        self.controls["CC6.7"] = SecurityControl(
            control_id="CC6.7",
            name="Data Protection",
            description="The entity implements logical and physical security controls to protect against unauthorized access to and use of protected information assets.",
            framework="SOC2",
            category="Data Protection",
            status=ControlStatus.PASSED,
            parameters=data_protection_params,
            last_assessment=datetime.datetime.now() - datetime.timedelta(hours=3),
            next_assessment=datetime.datetime.now() + datetime.timedelta(days=14),
            owner="Infrastructure Team",
            priority="Critical",
            automated=True,
            evidence_summary="1/2 parameters passed, 1 warning",
            technical_details={
                "automation_coverage": "95%",
                "api_integrations": ["AWS S3", "API Gateway", "Load Balancer"],
                "monitoring_frequency": "Daily",
                "compliance_frameworks": ["SOC2", "PCI-DSS"],
                "risk_assessment": "Medium"
            }
        )
    
    def get_detailed_summary(self) -> Dict[str, Any]:
        """Get comprehensive technical summary"""
        summary = {
            "controls": {},
            "frameworks": {},
            "data_sources": {},
            "automation_stats": {},
            "risk_distribution": {}
        }
        
        # Control summary
        total_controls = len(self.controls)
        total_parameters = sum(len(c.parameters) for c in self.controls.values())
        passed_parameters = sum(
            sum(1 for p in c.parameters if p.status == ControlStatus.PASSED)
            for c in self.controls.values()
        )
        
        summary["controls"] = {
            "total": total_controls,
            "total_parameters": total_parameters,
            "passed_parameters": passed_parameters,
            "compliance_score": round((passed_parameters / total_parameters) * 100, 1) if total_parameters > 0 else 0
        }
        
        # Data source analysis
        data_sources = {}
        for control in self.controls.values():
            for param in control.parameters:
                source = param.data_source.value
                if source not in data_sources:
                    data_sources[source] = {"count": 0, "passed": 0, "failed": 0}
                data_sources[source]["count"] += 1
                if param.status == ControlStatus.PASSED:
                    data_sources[source]["passed"] += 1
                elif param.status == ControlStatus.FAILED:
                    data_sources[source]["failed"] += 1
        
        summary["data_sources"] = data_sources
        
        return summary

def generate_enhanced_html() -> str:
    """Generate enhanced Vanta-style HTML dashboard"""
    
    dashboard = EnhancedVantaDashboard()
    summary = dashboard.get_detailed_summary()
    
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Guardians Armory - Enhanced GRC Dashboard</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0a0a0a;
            color: #ffffff;
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1600px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 40px;
            padding-bottom: 20px;
            border-bottom: 1px solid #2a2a2a;
        }}
        
        .logo {{
            font-size: 24px;
            font-weight: 700;
            color: #00d4aa;
        }}
        
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }}
        
        .metric-card {{
            background: #1a1a1a;
            border: 1px solid #2a2a2a;
            border-radius: 12px;
            padding: 24px;
            transition: all 0.3s ease;
        }}
        
        .metric-card:hover {{
            border-color: #00d4aa;
            transform: translateY(-2px);
        }}
        
        .metric-value {{
            font-size: 36px;
            font-weight: 700;
            margin-bottom: 8px;
            color: #00d4aa;
        }}
        
        .metric-label {{
            color: #888;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .controls-grid {{
            display: grid;
            gap: 20px;
        }}
        
        .control-card {{
            background: #1a1a1a;
            border: 1px solid #2a2a2a;
            border-radius: 12px;
            padding: 24px;
            cursor: pointer;
            transition: all 0.3s ease;
        }}
        
        .control-card:hover {{
            border-color: #00d4aa;
            background: #1f1f1f;
        }}
        
        .control-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 16px;
        }}
        
        .control-title {{
            font-size: 18px;
            font-weight: 600;
            color: #ffffff;
        }}
        
        .control-status {{
            padding: 4px 12px;
            border-radius: 16px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }}
        
        .control-status.passed {{ background: #00d4aa20; color: #00d4aa; }}
        .control-status.warning {{ background: #ffa50020; color: #ffa500; }}
        .control-status.failed {{ background: #ff475720; color: #ff4757; }}
        
        .parameter-summary {{
            margin-top: 16px;
            padding: 16px;
            background: #0f0f0f;
            border-radius: 8px;
            border-left: 4px solid #00d4aa;
        }}
        
        .parameter-item {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 0;
            border-bottom: 1px solid #2a2a2a;
        }}
        
        .parameter-name {{
            font-weight: 500;
            color: #ffffff;
        }}
        
        .data-source {{
            font-size: 11px;
            color: #666;
            margin-top: 4px;
        }}
        
        .technical-details {{
            margin-top: 12px;
            font-size: 12px;
            color: #888;
        }}
        
        .modal {{
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.9);
            z-index: 1000;
        }}
        
        .modal-content {{
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: #1a1a1a;
            border: 1px solid #2a2a2a;
            border-radius: 12px;
            padding: 32px;
            max-width: 1000px;
            width: 95%;
            max-height: 90vh;
            overflow-y: auto;
        }}
        
        .parameter-detail {{
            background: #0f0f0f;
            border: 1px solid #2a2a2a;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 16px;
        }}
        
        .evidence-box {{
            background: #0a0a0a;
            border: 1px solid #2a2a2a;
            border-radius: 6px;
            padding: 12px;
            margin-top: 12px;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 12px;
            color: #00d4aa;
        }}
        
        .raw-data {{
            background: #0a0a0a;
            border: 1px solid #2a2a2a;
            border-radius: 6px;
            padding: 12px;
            margin-top: 12px;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 11px;
            color: #ffa500;
            max-height: 200px;
            overflow-y: auto;
        }}
        
        .remediation-step {{
            background: #ffa50010;
            border-left: 3px solid #ffa500;
            padding: 8px 12px;
            margin-bottom: 8px;
            font-size: 14px;
        }}
        
        .data-source-badge {{
            background: #2a2a2a;
            color: #00d4aa;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 10px;
            font-weight: 600;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">🛡️ Guardians Armory - Enhanced GRC Dashboard</div>
            <div style="color: #888; font-size: 14px;">Real-time Technical Transparency</div>
        </div>
        
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-value">{summary['controls']['compliance_score']}%</div>
                <div class="metric-label">Overall Compliance</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{summary['controls']['total_parameters']}</div>
                <div class="metric-label">Technical Parameters</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{summary['controls']['passed_parameters']}</div>
                <div class="metric-label">Parameters Passed</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{len(summary['data_sources'])}</div>
                <div class="metric-label">Data Sources</div>
            </div>
        </div>
        
        <div style="margin-bottom: 40px;">
            <h2 style="margin-bottom: 20px; color: #ffffff;">Security Controls with Technical Details</h2>
            <div class="controls-grid">
"""
    
    # Add control cards with enhanced details
    for control in dashboard.controls.values():
        passed_params = sum(1 for p in control.parameters if p.status == ControlStatus.PASSED)
        total_params = len(control.parameters)
        
        html += f"""
                <div class="control-card" onclick="showEnhancedDetails('{control.control_id}')">
                    <div class="control-header">
                        <div>
                            <div class="control-title">{control.name}</div>
                            <div style="display: flex; gap: 16px; font-size: 12px; color: #666; margin-top: 4px;">
                                <span>{control.framework}</span>
                                <span>•</span>
                                <span>{control.category}</span>
                                <span>•</span>
                                <span>Owner: {control.owner}</span>
                            </div>
                        </div>
                        <div class="control-status {control.status.value}">{control.status.value.upper()}</div>
                    </div>
                    <div style="color: #888; margin-bottom: 16px; line-height: 1.5;">{control.description}</div>
                    <div class="parameter-summary">
                        <div style="margin-bottom: 12px; font-weight: 600; color: #ffffff;">
                            Technical Parameters ({passed_params}/{total_params} passed)
                        </div>
"""
        
        for param in control.parameters[:3]:
            html += f"""
                        <div class="parameter-item">
                            <div>
                                <div class="parameter-name">{param.name}</div>
                                <div class="data-source">
                                    <span class="data-source-badge">{param.data_source.value.replace('_', ' ').title()}</span>
                                    <span style="margin-left: 8px;">{param.automation_level} • {param.check_frequency}</span>
                                </div>
                            </div>
                            <div style="display: flex; align-items: center; gap: 6px;">
                                <div style="width: 6px; height: 6px; border-radius: 50%; background: {'#00d4aa' if param.status == ControlStatus.PASSED else '#ffa500' if param.status == ControlStatus.WARNING else '#ff4757'};"></div>
                                <span style="font-size: 12px;">{param.status.value.upper()}</span>
                            </div>
                        </div>
"""
        
        if len(control.parameters) > 3:
            html += f"""
                        <div style="text-align: center; color: #666; font-size: 12px; margin-top: 8px;">
                            +{len(control.parameters) - 3} more technical parameters
                        </div>
"""
        
        html += """
                    </div>
                </div>
"""
    
    html += """
            </div>
        </div>
    </div>
    
    <!-- Enhanced Modal -->
    <div id="enhancedModal" class="modal">
        <div class="modal-content">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; padding-bottom: 16px; border-bottom: 1px solid #2a2a2a;">
                <h2 id="enhancedModalTitle">Enhanced Control Details</h2>
                <button onclick="closeEnhancedModal()" style="background: none; border: none; color: #888; font-size: 24px; cursor: pointer;">&times;</button>
            </div>
            <div id="enhancedModalContent">
                <!-- Content will be populated by JavaScript -->
            </div>
        </div>
    </div>
    
    <script>
        function showEnhancedDetails(controlId) {
            const modal = document.getElementById('enhancedModal');
            const modalTitle = document.getElementById('enhancedModalTitle');
            const modalContent = document.getElementById('enhancedModalContent');
            
            // Enhanced control data with technical details
            const enhancedControlData = {
                'CC6.1': {
                    name: 'Access Control',
                    description: 'The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events to meet the entity\'s objectives.',
                    framework: 'SOC2',
                    category: 'Access Control',
                    status: 'warning',
                    technical_details: {
                        automation_coverage: '85%',
                        api_integrations: ['AWS IAM', 'AWS Security Hub', 'AWS CloudTrail'],
                        monitoring_frequency: 'Real-time',
                        compliance_frameworks: ['SOC2', 'ISO27001', 'NIST'],
                        risk_assessment: 'High'
                    },
                    parameters: [
                        {
                            name: 'IAM User Access Review',
                            description: 'Verify quarterly access reviews for all IAM users',
                            expected_value: 'All users reviewed within last 90 days',
                            actual_value: 'Last review: 2024-01-15 (45 days ago)',
                            status: 'passed',
                            data_source: 'AWS IAM',
                            evidence: 'AWS IAM API call: ListUsers() shows 45 users, all reviewed',
                            raw_data: {
                                total_users: 45,
                                reviewed_users: 45,
                                last_review_date: '2024-01-15',
                                reviewer: 'security-team',
                                api_calls: ['ListUsers', 'GetUser', 'ListAccessKeys'],
                                compliance_score: 100
                            },
                            remediation_steps: ['Schedule next quarterly review', 'Document review process'],
                            risk_level: 'High',
                            automation_level: 'Fully Automated',
                            check_frequency: 'Daily',
                            owner: 'Security Team'
                        },
                        {
                            name: 'MFA Enforcement',
                            description: 'Ensure MFA is enabled for all IAM users',
                            expected_value: 'MFA enabled for 100% of users',
                            actual_value: 'MFA enabled for 98% of users (2 users pending)',
                            status: 'warning',
                            data_source: 'AWS Security Hub',
                            evidence: 'Security Hub finding: 2 IAM users without MFA devices',
                            raw_data: {
                                total_users: 45,
                                mfa_enabled_users: 43,
                                mfa_disabled_users: 2,
                                finding_id: 'arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/IAM.1/finding/12345678-1234-1234-1234-123456789012',
                                severity: 'MEDIUM',
                                compliance_score: 95.6
                            },
                            remediation_steps: ['Enable MFA for remaining users', 'Set MFA enforcement policy'],
                            risk_level: 'Critical',
                            automation_level: 'Fully Automated',
                            check_frequency: 'Hourly',
                            owner: 'Security Team'
                        }
                    ]
                }
            };
            
            const control = enhancedControlData[controlId];
            if (!control) return;
            
            modalTitle.textContent = control.name;
            
            let content = `
                <div style="margin-bottom: 24px;">
                    <h3 style="color: #888; margin-bottom: 8px;">Description</h3>
                    <p>${control.description}</p>
                </div>
                
                <div style="margin-bottom: 24px;">
                    <h3 style="color: #888; margin-bottom: 8px;">Technical Implementation Details</h3>
                    <div style="background: #0f0f0f; padding: 16px; border-radius: 8px;">
                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px;">
                            <div>
                                <strong style="color: #00d4aa;">Automation Coverage:</strong><br>
                                ${control.technical_details.automation_coverage}
                            </div>
                            <div>
                                <strong style="color: #00d4aa;">Monitoring Frequency:</strong><br>
                                ${control.technical_details.monitoring_frequency}
                            </div>
                            <div>
                                <strong style="color: #00d4aa;">Risk Assessment:</strong><br>
                                ${control.technical_details.risk_assessment}
                            </div>
                        </div>
                        <div style="margin-top: 16px;">
                            <strong style="color: #00d4aa;">API Integrations:</strong><br>
                            ${control.technical_details.api_integrations.join(', ')}
                        </div>
                    </div>
                </div>
                
                <div style="margin-bottom: 24px;">
                    <h3 style="color: #888; margin-bottom: 16px;">Technical Parameters & Evidence</h3>
            `;
            
            control.parameters.forEach(param => {
                content += `
                    <div class="parameter-detail">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                            <div>
                                <h4 style="color: #ffffff; margin-bottom: 4px;">${param.name}</h4>
                                <p style="color: #888; font-size: 14px;">${param.description}</p>
                            </div>
                            <div class="control-status ${param.status}">${param.status.toUpperCase()}</div>
                        </div>
                        
                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 16px; margin-bottom: 16px;">
                            <div>
                                <strong style="color: #00d4aa;">Expected:</strong><br>
                                ${param.expected_value}
                            </div>
                            <div>
                                <strong style="color: #ffa500;">Actual:</strong><br>
                                ${param.actual_value}
                            </div>
                            <div>
                                <strong style="color: #888;">Data Source:</strong><br>
                                <span class="data-source-badge">${param.data_source}</span>
                            </div>
                            <div>
                                <strong style="color: #888;">Automation:</strong><br>
                                ${param.automation_level} • ${param.check_frequency}
                            </div>
                        </div>
                        
                        <div class="evidence-box">
                            <strong>Evidence:</strong><br>
                            ${param.evidence}
                        </div>
                        
                        <div class="raw-data">
                            <strong>Raw Technical Data:</strong><br>
                            <pre>${JSON.stringify(param.raw_data, null, 2)}</pre>
                        </div>
                        
                        ${param.remediation_steps.length > 0 ? `
                        <div style="margin-top: 12px;">
                            <strong style="color: #ffa500; margin-bottom: 8px; display: block;">Remediation Steps:</strong>
                            ${param.remediation_steps.map(step => `<div class="remediation-step">${step}</div>`).join('')}
                        </div>
                        ` : ''}
                    </div>
                `;
            });
            
            content += '</div>';
            modalContent.innerHTML = content;
            modal.style.display = 'block';
        }
        
        function closeEnhancedModal() {
            document.getElementById('enhancedModal').style.display = 'none';
        }
        
        // Close modal when clicking outside
        window.onclick = function(event) {
            const modal = document.getElementById('enhancedModal');
            if (event.target == modal) {
                modal.style.display = 'none';
            }
        }
    </script>
</body>
</html>
"""
    
    return html

if __name__ == "__main__":
    html_content = generate_enhanced_html()
    
    with open("enhanced_vanta_dashboard.html", "w") as f:
        f.write(html_content)
    
    print("✅ Enhanced Vanta-style dashboard generated: enhanced_vanta_dashboard.html")
    print("🌐 Open the HTML file in your browser to view the enhanced dashboard")
    print("🎨 Enhanced Features:")
    print("   - Detailed technical parameters with full transparency")
    print("   - Raw data exposure and evidence trails")
    print("   - Data source attribution and automation levels")
    print("   - Risk assessment and compliance scoring")
    print("   - Interactive drill-down for technical details")
    print("   - Dark mode design with professional aesthetics")