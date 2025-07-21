#!/usr/bin/env python3
"""
Guardians Armory: Vanta-Style GRC Dashboard
==========================================

A modern, dark-mode dashboard inspired by Vanta Trust that provides:
- Beautiful visualization of GRC controls and compliance status
- Detailed transparency about parameters being checked
- Clear data source attribution and evidence trails
- Technical details accessible to both technical and non-technical users
- Real-time status with drill-down capabilities

Author: Guardians Forge
Mission: "To Create the Next Generation of Protectors"
"""

import json
import datetime
import random
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import uuid

class ControlStatus(Enum):
    PASSED = "passed"
    FAILED = "failed"
    WARNING = "warning"
    NOT_APPLICABLE = "not_applicable"
    IN_PROGRESS = "in_progress"

class DataSource(Enum):
    AWS_CLOUDTRAIL = "aws_cloudtrail"
    AWS_CONFIG = "aws_config"
    AWS_SECURITY_HUB = "aws_security_hub"
    AWS_GUARDDUTY = "aws_guardduty"
    MANUAL_ASSESSMENT = "manual_assessment"
    API_SCAN = "api_scan"
    CODE_ANALYSIS = "code_analysis"
    PENETRATION_TEST = "penetration_test"

@dataclass
class ControlParameter:
    """Individual parameter being checked within a control"""
    parameter_id: str
    name: str
    description: str
    expected_value: str
    actual_value: str
    status: ControlStatus
    data_source: DataSource
    last_checked: datetime.datetime
    evidence: str
    remediation_steps: List[str]

@dataclass
class SecurityControl:
    """Security control with detailed parameter information"""
    control_id: str
    name: str
    description: str
    framework: str  # SOC2, ISO27001, NIST, etc.
    category: str
    status: ControlStatus
    parameters: List[ControlParameter]
    last_assessment: datetime.datetime
    next_assessment: datetime.datetime
    owner: str
    priority: str  # Critical, High, Medium, Low
    automated: bool
    evidence_summary: str

class VantaStyleDashboard:
    """Vanta-inspired dashboard with detailed technical transparency"""
    
    def __init__(self):
        self.controls: Dict[str, SecurityControl] = {}
        self.frameworks = ["SOC2", "ISO27001", "NIST", "PCI-DSS", "HIPAA"]
        self._initialize_sample_controls()
    
    def _initialize_sample_controls(self):
        """Initialize sample controls with detailed parameters"""
        
        # Access Control - SOC2 CC6.1
        access_control_params = [
            ControlParameter(
                parameter_id="acc_001",
                name="IAM User Access Review",
                description="Verify that IAM user access is reviewed quarterly",
                expected_value="All users reviewed within last 90 days",
                actual_value="Last review: 2024-01-15 (45 days ago)",
                status=ControlStatus.PASSED,
                data_source=DataSource.AWS_CONFIG,
                last_checked=datetime.datetime.now() - datetime.timedelta(hours=2),
                evidence="AWS Config rule 'iam-user-access-review' returned compliant",
                remediation_steps=["Schedule quarterly access reviews", "Document review process"]
            ),
            ControlParameter(
                parameter_id="acc_002",
                name="MFA Enforcement",
                description="Ensure MFA is enabled for all IAM users",
                expected_value="MFA enabled for 100% of users",
                actual_value="MFA enabled for 98% of users (2 users pending)",
                status=ControlStatus.WARNING,
                data_source=DataSource.AWS_SECURITY_HUB,
                last_checked=datetime.datetime.now() - datetime.timedelta(hours=1),
                evidence="Security Hub finding: 2 IAM users without MFA",
                remediation_steps=["Enable MFA for remaining users", "Set MFA enforcement policy"]
            ),
            ControlParameter(
                parameter_id="acc_003",
                name="Privileged Access Management",
                description="Verify privileged access is limited and monitored",
                expected_value="No users with excessive permissions",
                actual_value="3 users with admin privileges identified",
                status=ControlStatus.FAILED,
                data_source=DataSource.AWS_CLOUDTRAIL,
                last_checked=datetime.datetime.now() - datetime.timedelta(minutes=30),
                evidence="CloudTrail logs show admin actions by non-admin users",
                remediation_steps=["Review admin privileges", "Implement least privilege principle"]
            )
        ]
        
        self.controls["CC6.1"] = SecurityControl(
            control_id="CC6.1",
            name="Access Control",
            description="The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events to meet the entity's objectives.",
            framework="SOC2",
            category="Access Control",
            status=ControlStatus.WARNING,
            parameters=access_control_params,
            last_assessment=datetime.datetime.now() - datetime.timedelta(hours=2),
            next_assessment=datetime.datetime.now() + datetime.timedelta(days=7),
            owner="Security Team",
            priority="Critical",
            automated=True,
            evidence_summary="2/3 parameters passed, 1 warning, 1 failed"
        )
        
        # Data Protection - SOC2 CC6.7
        data_protection_params = [
            ControlParameter(
                parameter_id="dp_001",
                name="Data Encryption at Rest",
                description="Verify all sensitive data is encrypted at rest",
                expected_value="100% of S3 buckets encrypted",
                actual_value="100% of S3 buckets encrypted with AES-256",
                status=ControlStatus.PASSED,
                data_source=DataSource.AWS_CONFIG,
                last_checked=datetime.datetime.now() - datetime.timedelta(hours=3),
                evidence="AWS Config rule 's3-bucket-encryption' returned compliant",
                remediation_steps=["Continue monitoring encryption status"]
            ),
            ControlParameter(
                parameter_id="dp_002",
                name="Data Encryption in Transit",
                description="Verify TLS 1.2+ is used for all data transmission",
                expected_value="TLS 1.2+ enforced on all endpoints",
                actual_value="TLS 1.2+ enforced on 95% of endpoints",
                status=ControlStatus.WARNING,
                data_source=DataSource.API_SCAN,
                last_checked=datetime.datetime.now() - datetime.timedelta(hours=4),
                evidence="API scan found 2 legacy endpoints using TLS 1.1",
                remediation_steps=["Upgrade legacy endpoints to TLS 1.2+", "Deprecate old endpoints"]
            ),
            ControlParameter(
                parameter_id="dp_003",
                name="Key Management",
                description="Verify encryption keys are properly managed",
                expected_value="All keys rotated within 90 days",
                actual_value="Last key rotation: 2024-01-01 (60 days ago)",
                status=ControlStatus.PASSED,
                data_source=DataSource.AWS_CLOUDTRAIL,
                last_checked=datetime.datetime.now() - datetime.timedelta(hours=1),
                evidence="CloudTrail shows key rotation events within policy",
                remediation_steps=["Schedule next key rotation", "Monitor key usage"]
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
            evidence_summary="2/3 parameters passed, 1 warning"
        )
        
        # Vulnerability Management - SOC2 CC7.1
        vuln_management_params = [
            ControlParameter(
                parameter_id="vm_001",
                name="Vulnerability Scanning",
                description="Verify automated vulnerability scans are running",
                expected_value="Weekly scans completed",
                actual_value="Last scan: 2024-02-20 (2 days ago)",
                status=ControlStatus.PASSED,
                data_source=DataSource.API_SCAN,
                last_checked=datetime.datetime.now() - datetime.timedelta(hours=6),
                evidence="Automated scan completed successfully, 5 medium vulnerabilities found",
                remediation_steps=["Address medium vulnerabilities", "Schedule next scan"]
            ),
            ControlParameter(
                parameter_id="vm_002",
                name="Critical Vulnerability Remediation",
                description="Verify critical vulnerabilities are remediated within 24 hours",
                expected_value="0 critical vulnerabilities",
                actual_value="1 critical vulnerability (CVE-2024-1234) - 12 hours old",
                status=ControlStatus.FAILED,
                data_source=DataSource.CODE_ANALYSIS,
                last_checked=datetime.datetime.now() - datetime.timedelta(hours=12),
                evidence="Static code analysis detected critical vulnerability in auth module",
                remediation_steps=["Patch vulnerable dependency", "Deploy fix immediately"]
            ),
            ControlParameter(
                parameter_id="vm_003",
                name="Patch Management",
                description="Verify security patches are applied within SLA",
                expected_value="Patches applied within 7 days",
                actual_value="Average patch time: 5.2 days",
                status=ControlStatus.PASSED,
                data_source=DataSource.MANUAL_ASSESSMENT,
                last_checked=datetime.datetime.now() - datetime.timedelta(hours=8),
                evidence="Patch management dashboard shows compliance with SLA",
                remediation_steps=["Continue monitoring patch compliance"]
            )
        ]
        
        self.controls["CC7.1"] = SecurityControl(
            control_id="CC7.1",
            name="Vulnerability Management",
            description="The entity identifies and develops and maintains security configurations, patches, and updates to information and information systems to protect against vulnerabilities and threats.",
            framework="SOC2",
            category="Vulnerability Management",
            status=ControlStatus.WARNING,
            parameters=vuln_management_params,
            last_assessment=datetime.datetime.now() - datetime.timedelta(hours=6),
            next_assessment=datetime.datetime.now() + datetime.timedelta(days=3),
            owner="Security Team",
            priority="High",
            automated=True,
            evidence_summary="2/3 parameters passed, 1 critical failure"
        )
    
    def get_control_summary(self) -> Dict[str, Any]:
        """Get high-level control summary"""
        total_controls = len(self.controls)
        passed_controls = sum(1 for c in self.controls.values() if c.status == ControlStatus.PASSED)
        failed_controls = sum(1 for c in self.controls.values() if c.status == ControlStatus.FAILED)
        warning_controls = sum(1 for c in self.controls.values() if c.status == ControlStatus.WARNING)
        
        total_parameters = sum(len(c.parameters) for c in self.controls.values())
        passed_parameters = sum(
            sum(1 for p in c.parameters if p.status == ControlStatus.PASSED)
            for c in self.controls.values()
        )
        
        return {
            "total_controls": total_controls,
            "passed_controls": passed_controls,
            "failed_controls": failed_controls,
            "warning_controls": warning_controls,
            "total_parameters": total_parameters,
            "passed_parameters": passed_parameters,
            "compliance_score": round((passed_parameters / total_parameters) * 100, 1) if total_parameters > 0 else 0,
            "last_updated": datetime.datetime.now().isoformat()
        }
    
    def get_control_details(self, control_id: str) -> Optional[SecurityControl]:
        """Get detailed information about a specific control"""
        return self.controls.get(control_id)
    
    def get_framework_summary(self, framework: str) -> Dict[str, Any]:
        """Get summary for a specific framework"""
        framework_controls = [c for c in self.controls.values() if c.framework == framework]
        if not framework_controls:
            return {}
        
        total = len(framework_controls)
        passed = sum(1 for c in framework_controls if c.status == ControlStatus.PASSED)
        failed = sum(1 for c in framework_controls if c.status == ControlStatus.FAILED)
        warning = sum(1 for c in framework_controls if c.status == ControlStatus.WARNING)
        
        return {
            "framework": framework,
            "total_controls": total,
            "passed_controls": passed,
            "failed_controls": failed,
            "warning_controls": warning,
            "compliance_percentage": round((passed / total) * 100, 1) if total > 0 else 0
        }

def generate_vanta_style_html() -> str:
    """Generate Vanta-style dark mode HTML dashboard"""
    
    dashboard = VantaStyleDashboard()
    summary = dashboard.get_control_summary()
    
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Guardians Armory - GRC Dashboard</title>
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
            max-width: 1400px;
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
        
        .status-indicator {{
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 8px 16px;
            border-radius: 20px;
            background: #1a1a1a;
            border: 1px solid #2a2a2a;
        }}
        
        .status-dot {{
            width: 8px;
            height: 8px;
            border-radius: 50%;
        }}
        
        .status-dot.passed {{ background: #00d4aa; }}
        .status-dot.warning {{ background: #ffa500; }}
        .status-dot.failed {{ background: #ff4757; }}
        
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
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
        }}
        
        .metric-label {{
            color: #888;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .controls-section {{
            margin-bottom: 40px;
        }}
        
        .section-title {{
            font-size: 20px;
            font-weight: 600;
            margin-bottom: 20px;
            color: #ffffff;
        }}
        
        .controls-grid {{
            display: grid;
            gap: 16px;
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
        
        .control-description {{
            color: #888;
            margin-bottom: 16px;
            line-height: 1.5;
        }}
        
        .control-meta {{
            display: flex;
            gap: 16px;
            font-size: 12px;
            color: #666;
        }}
        
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
        
        .parameter-item:last-child {{
            border-bottom: none;
        }}
        
        .parameter-name {{
            font-weight: 500;
            color: #ffffff;
        }}
        
        .parameter-status {{
            display: flex;
            align-items: center;
            gap: 6px;
        }}
        
        .parameter-dot {{
            width: 6px;
            height: 6px;
            border-radius: 50%;
        }}
        
        .parameter-dot.passed {{ background: #00d4aa; }}
        .parameter-dot.warning {{ background: #ffa500; }}
        .parameter-dot.failed {{ background: #ff4757; }}
        
        .data-source {{
            font-size: 11px;
            color: #666;
            margin-top: 4px;
        }}
        
        .modal {{
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
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
            max-width: 800px;
            width: 90%;
            max-height: 80vh;
            overflow-y: auto;
        }}
        
        .modal-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
            padding-bottom: 16px;
            border-bottom: 1px solid #2a2a2a;
        }}
        
        .close {{
            background: none;
            border: none;
            color: #888;
            font-size: 24px;
            cursor: pointer;
            padding: 0;
            width: 30px;
            height: 30px;
            display: flex;
            align-items: center;
            justify-content: center;
        }}
        
        .parameter-detail {{
            background: #0f0f0f;
            border: 1px solid #2a2a2a;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 16px;
        }}
        
        .parameter-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
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
        
        .remediation-steps {{
            margin-top: 12px;
        }}
        
        .remediation-step {{
            background: #ffa50010;
            border-left: 3px solid #ffa500;
            padding: 8px 12px;
            margin-bottom: 8px;
            font-size: 14px;
        }}
        
        @media (max-width: 768px) {{
            .container {{
                padding: 16px;
            }}
            
            .header {{
                flex-direction: column;
                gap: 16px;
                align-items: flex-start;
            }}
            
            .metrics-grid {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">🛡️ Guardians Armory</div>
            <div class="status-indicator">
                <div class="status-dot passed"></div>
                <span>Live Monitoring Active</span>
            </div>
        </div>
        
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-value">{summary['compliance_score']}%</div>
                <div class="metric-label">Overall Compliance</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{summary['total_controls']}</div>
                <div class="metric-label">Active Controls</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{summary['passed_parameters']}/{summary['total_parameters']}</div>
                <div class="metric-label">Parameters Passed</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">{summary['failed_controls']}</div>
                <div class="metric-label">Failed Controls</div>
            </div>
        </div>
        
        <div class="controls-section">
            <div class="section-title">Security Controls</div>
            <div class="controls-grid">
"""
    
    # Add control cards
    for control in dashboard.controls.values():
        passed_params = sum(1 for p in control.parameters if p.status == ControlStatus.PASSED)
        total_params = len(control.parameters)
        
        html += f"""
                <div class="control-card" onclick="showControlDetails('{control.control_id}')">
                    <div class="control-header">
                        <div>
                            <div class="control-title">{control.name}</div>
                            <div class="control-meta">
                                <span>{control.framework}</span>
                                <span>•</span>
                                <span>{control.category}</span>
                                <span>•</span>
                                <span>Owner: {control.owner}</span>
                            </div>
                        </div>
                        <div class="control-status {control.status.value}">{control.status.value.upper()}</div>
                    </div>
                    <div class="control-description">{control.description}</div>
                    <div class="parameter-summary">
                        <div style="margin-bottom: 12px; font-weight: 600; color: #ffffff;">Parameters ({passed_params}/{total_params} passed)</div>
"""
        
        for param in control.parameters[:3]:  # Show first 3 parameters
            html += f"""
                        <div class="parameter-item">
                            <div>
                                <div class="parameter-name">{param.name}</div>
                                <div class="data-source">Source: {param.data_source.value.replace('_', ' ').title()}</div>
                            </div>
                            <div class="parameter-status">
                                <div class="parameter-dot {param.status.value}"></div>
                                <span>{param.status.value.upper()}</span>
                            </div>
                        </div>
"""
        
        if len(control.parameters) > 3:
            html += f"""
                        <div style="text-align: center; color: #666; font-size: 12px; margin-top: 8px;">
                            +{len(control.parameters) - 3} more parameters
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
    
    <!-- Modal for detailed control view -->
    <div id="controlModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2 id="modalTitle">Control Details</h2>
                <button class="close" onclick="closeModal()">&times;</button>
            </div>
            <div id="modalContent">
                <!-- Content will be populated by JavaScript -->
            </div>
        </div>
    </div>
    
    <script>
        function showControlDetails(controlId) {
            const modal = document.getElementById('controlModal');
            const modalTitle = document.getElementById('modalTitle');
            const modalContent = document.getElementById('modalContent');
            
            // This would normally fetch from an API
            // For demo purposes, we'll show sample data
            const controlData = {
                'CC6.1': {
                    name: 'Access Control',
                    description: 'The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events to meet the entity\'s objectives.',
                    framework: 'SOC2',
                    category: 'Access Control',
                    status: 'warning',
                    parameters: [
                        {
                            name: 'IAM User Access Review',
                            description: 'Verify that IAM user access is reviewed quarterly',
                            expected_value: 'All users reviewed within last 90 days',
                            actual_value: 'Last review: 2024-01-15 (45 days ago)',
                            status: 'passed',
                            data_source: 'AWS Config',
                            evidence: 'AWS Config rule "iam-user-access-review" returned compliant',
                            remediation_steps: ['Schedule quarterly access reviews', 'Document review process']
                        },
                        {
                            name: 'MFA Enforcement',
                            description: 'Ensure MFA is enabled for all IAM users',
                            expected_value: 'MFA enabled for 100% of users',
                            actual_value: 'MFA enabled for 98% of users (2 users pending)',
                            status: 'warning',
                            data_source: 'AWS Security Hub',
                            evidence: 'Security Hub finding: 2 IAM users without MFA',
                            remediation_steps: ['Enable MFA for remaining users', 'Set MFA enforcement policy']
                        },
                        {
                            name: 'Privileged Access Management',
                            description: 'Verify privileged access is limited and monitored',
                            expected_value: 'No users with excessive permissions',
                            actual_value: '3 users with admin privileges identified',
                            status: 'failed',
                            data_source: 'AWS CloudTrail',
                            evidence: 'CloudTrail logs show admin actions by non-admin users',
                            remediation_steps: ['Review admin privileges', 'Implement least privilege principle']
                        }
                    ]
                }
            };
            
            const control = controlData[controlId];
            if (!control) return;
            
            modalTitle.textContent = control.name;
            
            let content = `
                <div style="margin-bottom: 24px;">
                    <h3 style="color: #888; margin-bottom: 8px;">Description</h3>
                    <p>${control.description}</p>
                </div>
                
                <div style="margin-bottom: 24px;">
                    <h3 style="color: #888; margin-bottom: 8px;">Framework & Category</h3>
                    <p><strong>${control.framework}</strong> • ${control.category}</p>
                </div>
                
                <div style="margin-bottom: 24px;">
                    <h3 style="color: #888; margin-bottom: 16px;">Parameters & Evidence</h3>
            `;
            
            control.parameters.forEach(param => {
                content += `
                    <div class="parameter-detail">
                        <div class="parameter-header">
                            <div>
                                <h4 style="color: #ffffff; margin-bottom: 4px;">${param.name}</h4>
                                <p style="color: #888; font-size: 14px;">${param.description}</p>
                            </div>
                            <div class="control-status ${param.status}">${param.status.toUpperCase()}</div>
                        </div>
                        
                        <div style="margin-top: 16px;">
                            <div style="margin-bottom: 8px;">
                                <strong style="color: #00d4aa;">Expected:</strong> ${param.expected_value}
                            </div>
                            <div style="margin-bottom: 8px;">
                                <strong style="color: #ffa500;">Actual:</strong> ${param.actual_value}
                            </div>
                            <div style="margin-bottom: 8px;">
                                <strong style="color: #888;">Data Source:</strong> ${param.data_source}
                            </div>
                        </div>
                        
                        <div class="evidence-box">
                            <strong>Evidence:</strong><br>
                            ${param.evidence}
                        </div>
                        
                        ${param.remediation_steps.length > 0 ? `
                        <div class="remediation-steps">
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
        
        function closeModal() {
            document.getElementById('controlModal').style.display = 'none';
        }
        
        // Close modal when clicking outside
        window.onclick = function(event) {
            const modal = document.getElementById('controlModal');
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
    # Generate and save the dashboard
    html_content = generate_vanta_style_html()
    
    with open("vanta_style_dashboard.html", "w") as f:
        f.write(html_content)
    
    print("✅ Vanta-style dashboard generated: vanta_style_dashboard.html")
    print("🌐 Open the HTML file in your browser to view the dashboard")
    print("🎨 Features:")
    print("   - Dark mode design inspired by Vanta Trust")
    print("   - Detailed parameter transparency")
    print("   - Data source attribution")
    print("   - Evidence trails and remediation steps")
    print("   - Interactive modal for drill-down details")
    print("   - Responsive design for all devices")