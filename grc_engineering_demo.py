#!/usr/bin/env python3
"""
Guardians Armory: GRC Engineering Demo
======================================

A demonstration of the GRC Engineering Engine implementing modern GRC principles:
- GRC-as-Code: Security controls as infrastructure code
- Automation-First: End-to-end automation of GRC processes
- Continuous Assurance: Real-time monitoring and alerting
- Stakeholder-Centric UX: Role-based experiences
- Threat Intelligence Integration: Evidence-based threat modeling
- Systems Thinking: Holistic risk assessment

Author: Guardians Forge
Mission: "To Create the Next Generation of Protectors"
"""

import json
import datetime
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum

class GRCValue(Enum):
    """GRC Engineering Values"""
    AUTOMATION_FIRST = "automation_first"
    GRC_AS_CODE = "grc_as_code"
    MEASURABLE_OUTCOMES = "measurable_outcomes"
    EVIDENCE_BASED = "evidence_based"
    CONTINUOUS_ASSURANCE = "continuous_assurance"
    STAKEHOLDER_CENTRIC = "stakeholder_centric"
    SHARED_FATE = "shared_fate"
    OPEN_SOURCE = "open_source"

class GRCPrinciple(Enum):
    """GRC Engineering Principles"""
    SHIFT_LEFT = "shift_left"
    PRACTITIONER_DRIVEN = "practitioner_driven"
    PRODUCT_MINDSET = "product_mindset"
    THREAT_INTELLIGENCE = "threat_intelligence"
    SYSTEMS_THINKING = "systems_thinking"
    DESIGN_THINKING = "design_thinking"

class StakeholderRole(Enum):
    """Stakeholder roles for UX design"""
    EXECUTIVE = "executive"
    ENGINEER = "engineer"
    AUDITOR = "auditor"
    SECURITY_ANALYST = "security_analyst"
    COMPLIANCE_OFFICER = "compliance_officer"
    DEVELOPER = "developer"
    DEVOPS = "devops"

class InfrastructureType(Enum):
    """Infrastructure types for GRC-as-Code"""
    TERRAFORM = "terraform"
    CLOUDFORMATION = "cloudformation"
    KUBERNETES = "kubernetes"
    ANSIBLE = "ansible"
    DOCKER = "docker"

@dataclass
class SecurityControlAsCode:
    """Security Control as Code implementation"""
    control_id: str
    control_name: str
    description: str
    infrastructure_type: InfrastructureType
    code_template: str
    validation_rules: List[str]
    deployment_script: str
    rollback_script: str
    monitoring_config: Dict[str, Any]
    compliance_mapping: Dict[str, List[str]]
    
    def deploy(self, environment: str, parameters: Dict[str, Any]) -> bool:
        """Deploy security control to target environment"""
        print(f"🚀 Deploying control {self.control_id} to {environment}")
        
        # Simulate deployment process
        if self._validate_parameters(parameters):
            print(f"✅ Control {self.control_id} deployed successfully")
            return True
        else:
            print(f"❌ Control {self.control_id} deployment failed")
            return False
    
    def _validate_parameters(self, parameters: Dict[str, Any]) -> bool:
        """Validate deployment parameters"""
        return True  # Simplified for demo

@dataclass
class ContinuousAssuranceRule:
    """Continuous assurance monitoring rule"""
    rule_id: str
    rule_name: str
    description: str
    monitoring_query: str
    alert_conditions: List[Dict[str, Any]]
    remediation_actions: List[str]
    severity: str
    stakeholders: List[StakeholderRole]
    metrics: List[str]

class ContinuousAssuranceEngine:
    """Continuous assurance monitoring and alerting engine"""
    
    def __init__(self):
        self.monitoring_rules: List[ContinuousAssuranceRule] = []
        self.active_incidents: List[Dict[str, Any]] = []
    
    def add_monitoring_rule(self, rule: ContinuousAssuranceRule) -> None:
        """Add monitoring rule to continuous assurance engine"""
        self.monitoring_rules.append(rule)
        print(f"✅ Added monitoring rule: {rule.rule_name}")
    
    def start_monitoring(self) -> None:
        """Start continuous monitoring"""
        print("🔄 Starting continuous assurance monitoring")
        self._monitor_rules()
    
    def _monitor_rules(self) -> None:
        """Monitor all active rules"""
        for rule in self.monitoring_rules:
            if self._evaluate_rule(rule):
                self._trigger_alert(rule)
    
    def _evaluate_rule(self, rule: ContinuousAssuranceRule) -> bool:
        """Evaluate monitoring rule"""
        # Simulate rule evaluation
        return False  # Simplified for demo
    
    def _trigger_alert(self, rule: ContinuousAssuranceRule) -> None:
        """Trigger alert for rule violation"""
        alert = {
            "rule_id": rule.rule_id,
            "rule_name": rule.rule_name,
            "severity": rule.severity,
            "timestamp": datetime.datetime.now().isoformat(),
            "stakeholders": [s.value for s in rule.stakeholders],
            "remediation_actions": rule.remediation_actions
        }
        
        self.active_incidents.append(alert)
        print(f"🚨 Alert triggered: {rule.rule_name}")

@dataclass
class StakeholderDashboard:
    """Role-based stakeholder dashboard"""
    role: StakeholderRole
    
    def get_executive_dashboard(self) -> Dict[str, Any]:
        """High-level security posture for executives"""
        return {
            "overall_risk_score": 0.25,
            "compliance_status": {
                "soc2_score": 0.92,
                "iso27001_score": 0.88,
                "nist_score": 0.85,
                "overall_compliance": 0.88
            },
            "key_metrics": [
                {"metric": "Mean Time to Detection", "value": "2.5 hours", "trend": "improving"},
                {"metric": "Mean Time to Response", "value": "4.2 hours", "trend": "stable"},
                {"metric": "Security Incidents", "value": "12", "trend": "decreasing"},
                {"metric": "Compliance Score", "value": "88%", "trend": "improving"}
            ],
            "recent_incidents": [
                {"id": "INC-001", "severity": "Medium", "status": "Resolved", "time": "2 hours ago"},
                {"id": "INC-002", "severity": "Low", "status": "In Progress", "time": "4 hours ago"}
            ],
            "trends": {
                "risk_trend": "decreasing",
                "compliance_trend": "improving",
                "incident_trend": "stable"
            }
        }
    
    def get_engineer_dashboard(self) -> Dict[str, Any]:
        """Technical security details for engineers"""
        return {
            "security_controls": [
                {"control_id": "IAM-001", "status": "Active", "last_check": "1 hour ago"},
                {"control_id": "NET-001", "status": "Active", "last_check": "30 minutes ago"}
            ],
            "vulnerabilities": [
                {"cve": "CVE-2023-1234", "severity": "High", "status": "Open", "affected_systems": 3},
                {"cve": "CVE-2023-5678", "severity": "Medium", "status": "In Progress", "affected_systems": 1}
            ],
            "deployment_status": {
                "security_controls_deployed": 45,
                "pending_deployments": 3,
                "failed_deployments": 1,
                "deployment_success_rate": 0.96
            },
            "performance_metrics": [
                {"metric": "System Uptime", "value": "99.9%"},
                {"metric": "Response Time", "value": "150ms"},
                {"metric": "Throughput", "value": "1000 req/sec"}
            ],
            "remediation_tasks": [
                {"task_id": "TASK-001", "priority": "High", "due_date": "2024-01-15", "status": "In Progress"},
                {"task_id": "TASK-002", "priority": "Medium", "due_date": "2024-01-20", "status": "Open"}
            ]
        }
    
    def get_auditor_dashboard(self) -> Dict[str, Any]:
        """Compliance evidence for auditors"""
        return {
            "compliance_evidence": [
                {"control": "IAM-001", "evidence": "Automated logs", "last_verified": "2024-01-10"},
                {"control": "NET-001", "evidence": "Network scans", "last_verified": "2024-01-09"}
            ],
            "audit_trail": [
                {"action": "User access review", "timestamp": "2024-01-10T10:00:00Z", "user": "auditor1"},
                {"action": "Control assessment", "timestamp": "2024-01-09T15:30:00Z", "user": "auditor2"}
            ],
            "control_effectiveness": {
                "preventive_controls": 0.95,
                "detective_controls": 0.88,
                "corrective_controls": 0.92,
                "overall_effectiveness": 0.92
            },
            "risk_assessments": [
                {"assessment_id": "RA-001", "date": "2024-01-01", "risk_score": 0.25, "status": "Accepted"},
                {"assessment_id": "RA-002", "date": "2024-01-05", "risk_score": 0.45, "status": "Mitigated"}
            ],
            "policy_compliance": {
                "security_policies": 0.98,
                "access_policies": 0.95,
                "data_policies": 0.92,
                "overall_policy_compliance": 0.95
            }
        }

@dataclass
class ThreatIntelligenceFeed:
    """Threat intelligence feed configuration"""
    feed_id: str
    feed_name: str
    feed_type: str
    source_url: str
    update_frequency: str
    format: str
    authentication: Dict[str, Any]
    filters: Dict[str, Any]

class ThreatIntelligenceEngine:
    """Threat intelligence integration engine"""
    
    def __init__(self):
        self.threat_feeds: List[ThreatIntelligenceFeed] = []
        self.threat_models: Dict[str, Any] = {}
        self.risk_scoring: Dict[str, Any] = {}
        self.threat_database: Dict[str, Any] = {}
    
    def add_threat_feed(self, feed: ThreatIntelligenceFeed) -> None:
        """Add threat intelligence feed"""
        self.threat_feeds.append(feed)
        print(f"✅ Added threat feed: {feed.feed_name}")
    
    def ingest_threat_data(self) -> None:
        """Ingest threat data from all feeds"""
        print("📥 Starting threat intelligence ingestion")
        
        for feed in self.threat_feeds:
            try:
                print(f"📡 Ingesting data from {feed.feed_name}")
                # Simulate data ingestion
                print(f"✅ Successfully ingested data from {feed.feed_name}")
            except Exception as e:
                print(f"❌ Failed to ingest data from {feed.feed_name}: {str(e)}")
    
    def assess_threat_risk(self, threat: Dict[str, Any]) -> float:
        """Assess risk level of specific threat"""
        base_score = threat.get('base_score', 0.5)
        environmental_score = threat.get('environmental_score', 0.5)
        temporal_score = threat.get('temporal_score', 0.5)
        
        return (base_score + environmental_score + temporal_score) / 3
    
    def generate_threat_response(self, threat: Dict[str, Any]) -> Dict[str, Any]:
        """Generate automated threat response plan"""
        risk_score = self.assess_threat_risk(threat)
        
        response_plan = {
            "threat_id": threat.get('id'),
            "risk_score": risk_score,
            "response_actions": self._get_response_actions(risk_score),
            "stakeholders": self._get_stakeholders(risk_score),
            "timeline": self._get_response_timeline(risk_score),
            "automation_available": risk_score > 0.7
        }
        
        return response_plan
    
    def _get_response_actions(self, risk_score: float) -> List[str]:
        """Get response actions based on risk score"""
        if risk_score > 0.8:
            return ["Immediate containment", "Incident response", "Stakeholder notification"]
        elif risk_score > 0.6:
            return ["Enhanced monitoring", "Control validation", "Risk assessment"]
        else:
            return ["Standard monitoring", "Documentation"]
    
    def _get_stakeholders(self, risk_score: float) -> List[str]:
        """Get stakeholders based on risk score"""
        if risk_score > 0.8:
            return ["CISO", "Security Team", "Executive Leadership"]
        elif risk_score > 0.6:
            return ["Security Team", "IT Operations"]
        else:
            return ["Security Team"]
    
    def _get_response_timeline(self, risk_score: float) -> Dict[str, str]:
        """Get response timeline based on risk score"""
        if risk_score > 0.8:
            return {"immediate": "0-1 hours", "short_term": "1-4 hours", "long_term": "24-48 hours"}
        elif risk_score > 0.6:
            return {"immediate": "1-4 hours", "short_term": "4-24 hours", "long_term": "1-7 days"}
        else:
            return {"immediate": "4-24 hours", "short_term": "1-7 days", "long_term": "1-4 weeks"}

class GRCEngineeringEngine:
    """Main GRC Engineering Engine"""
    
    def __init__(self):
        self.security_controls: Dict[str, SecurityControlAsCode] = {}
        self.continuous_assurance = ContinuousAssuranceEngine()
        self.threat_intelligence = ThreatIntelligenceEngine()
        self.stakeholder_dashboards: Dict[StakeholderRole, StakeholderDashboard] = {}
        self.grc_values = list(GRCValue)
        self.grc_principles = list(GRCPrinciple)
        
        # Initialize stakeholder dashboards
        self._initialize_stakeholder_dashboards()
    
    def _initialize_stakeholder_dashboards(self) -> None:
        """Initialize stakeholder dashboards"""
        for role in StakeholderRole:
            self.stakeholder_dashboards[role] = StakeholderDashboard(role=role)
    
    def add_security_control(self, control: SecurityControlAsCode) -> None:
        """Add security control to GRC engine"""
        self.security_controls[control.control_id] = control
        print(f"✅ Added security control: {control.control_name}")
    
    def deploy_security_controls(self, environment: str, control_ids: List[str] = None) -> Dict[str, bool]:
        """Deploy security controls to environment"""
        results = {}
        
        controls_to_deploy = control_ids if control_ids else list(self.security_controls.keys())
        
        for control_id in controls_to_deploy:
            if control_id in self.security_controls:
                control = self.security_controls[control_id]
                results[control_id] = control.deploy(environment, {})
            else:
                results[control_id] = False
                print(f"❌ Control {control_id} not found")
        
        return results
    
    def start_continuous_assurance(self) -> None:
        """Start continuous assurance monitoring"""
        self.continuous_assurance.start_monitoring()
    
    def get_stakeholder_dashboard(self, role: StakeholderRole) -> Dict[str, Any]:
        """Get dashboard for specific stakeholder role"""
        dashboard = self.stakeholder_dashboards[role]
        
        if role == StakeholderRole.EXECUTIVE:
            return dashboard.get_executive_dashboard()
        elif role == StakeholderRole.ENGINEER:
            return dashboard.get_engineer_dashboard()
        elif role == StakeholderRole.AUDITOR:
            return dashboard.get_auditor_dashboard()
        else:
            return {"role": role.value, "message": "Dashboard not yet implemented for this role"}
    
    def assess_grc_maturity(self) -> Dict[str, Any]:
        """Assess GRC engineering maturity"""
        maturity_assessment = {
            "automation_coverage": self._assess_automation_coverage(),
            "grc_as_code_implementation": self._assess_grc_as_code(),
            "continuous_assurance": self._assess_continuous_assurance(),
            "stakeholder_experience": self._assess_stakeholder_experience(),
            "threat_intelligence": self._assess_threat_intelligence(),
            "overall_maturity": 0.0
        }
        
        # Calculate overall maturity
        scores = [v for v in maturity_assessment.values() if isinstance(v, (int, float))]
        maturity_assessment["overall_maturity"] = sum(scores) / len(scores)
        
        return maturity_assessment
    
    def _assess_automation_coverage(self) -> float:
        """Assess automation coverage"""
        total_processes = 10
        automated_processes = 7
        return automated_processes / total_processes
    
    def _assess_grc_as_code(self) -> float:
        """Assess GRC-as-Code implementation"""
        total_controls = len(self.security_controls)
        coded_controls = len([c for c in self.security_controls.values() if c.code_template])
        return coded_controls / total_controls if total_controls > 0 else 0.0
    
    def _assess_continuous_assurance(self) -> float:
        """Assess continuous assurance implementation"""
        return 0.8
    
    def _assess_stakeholder_experience(self) -> float:
        """Assess stakeholder experience"""
        return 0.75
    
    def _assess_threat_intelligence(self) -> float:
        """Assess threat intelligence integration"""
        return 0.6
    
    def generate_grc_report(self) -> Dict[str, Any]:
        """Generate comprehensive GRC engineering report"""
        return {
            "report_timestamp": datetime.datetime.now().isoformat(),
            "grc_maturity": self.assess_grc_maturity(),
            "security_controls": {
                "total_controls": len(self.security_controls),
                "deployed_controls": len(self.security_controls),
                "compliance_mapping": self._get_compliance_mapping()
            },
            "continuous_assurance": {
                "active_rules": len(self.continuous_assurance.monitoring_rules),
                "active_incidents": len(self.continuous_assurance.active_incidents),
                "automation_coverage": self._assess_automation_coverage()
            },
            "threat_intelligence": {
                "active_feeds": len(self.threat_intelligence.threat_feeds),
                "threat_models": len(self.threat_intelligence.threat_models),
                "risk_scoring": len(self.threat_intelligence.risk_scoring)
            },
            "stakeholder_experience": {
                "supported_roles": len(self.stakeholder_dashboards),
                "dashboard_availability": 1.0
            },
            "grc_values_alignment": {
                value.value: self._assess_value_alignment(value) 
                for value in self.grc_values
            },
            "grc_principles_alignment": {
                principle.value: self._assess_principle_alignment(principle)
                for principle in self.grc_principles
            }
        }
    
    def _get_compliance_mapping(self) -> Dict[str, List[str]]:
        """Get compliance framework mapping"""
        return {
            "SOC2": ["CC1", "CC2", "CC3", "CC4", "CC5", "CC6", "CC7", "CC8", "CC9"],
            "ISO27001": ["A.5", "A.6", "A.7", "A.8", "A.9", "A.10", "A.11", "A.12", "A.13", "A.14", "A.15", "A.16", "A.17", "A.18"],
            "NIST": ["AC", "AT", "AU", "CA", "CM", "CP", "IA", "IR", "MA", "MP", "PE", "PL", "PS", "RA", "SA", "SC", "SI", "SR"],
            "CIS": ["CIS-1", "CIS-2", "CIS-3", "CIS-4", "CIS-5", "CIS-6", "CIS-7", "CIS-8"]
        }
    
    def _assess_value_alignment(self, value: GRCValue) -> float:
        """Assess alignment with GRC value"""
        return 0.8
    
    def _assess_principle_alignment(self, principle: GRCPrinciple) -> float:
        """Assess alignment with GRC principle"""
        return 0.75

def create_example_grc_engine() -> GRCEngineeringEngine:
    """Create example GRC Engineering Engine with sample data"""
    
    # Create GRC engine
    grc_engine = GRCEngineeringEngine()
    
    # Add example security control as code
    example_control = SecurityControlAsCode(
        control_id="IAM-001",
        control_name="Multi-Factor Authentication Enforcement",
        description="Enforce MFA for all user accounts",
        infrastructure_type=InfrastructureType.TERRAFORM,
        code_template="""
        resource "aws_iam_user" "example" {
          name = "example_user"
          force_destroy = true
        }
        
        resource "aws_iam_user_login_profile" "example" {
          user = aws_iam_user.example.name
          password_reset_required = true
        }
        """,
        validation_rules=["MFA enabled", "Password policy enforced"],
        deployment_script="terraform apply",
        rollback_script="terraform destroy",
        monitoring_config={"metric": "mfa_enabled_users", "threshold": 0.95},
        compliance_mapping={"SOC2": ["CC6"], "ISO27001": ["A.9"], "NIST": ["IA"]}
    )
    
    grc_engine.add_security_control(example_control)
    
    # Add example continuous assurance rule
    example_rule = ContinuousAssuranceRule(
        rule_id="CA-001",
        rule_name="MFA Compliance Monitoring",
        description="Monitor MFA compliance across all users",
        monitoring_query="SELECT user_id FROM users WHERE mfa_enabled = false",
        alert_conditions=[{"condition": "count > 0", "severity": "high"}],
        remediation_actions=["Enable MFA", "Notify security team"],
        severity="high",
        stakeholders=[StakeholderRole.SECURITY_ANALYST, StakeholderRole.COMPLIANCE_OFFICER],
        metrics=["mfa_compliance_rate", "mfa_enabled_users"]
    )
    
    grc_engine.continuous_assurance.add_monitoring_rule(example_rule)
    
    # Add example threat intelligence feed
    example_feed = ThreatIntelligenceFeed(
        feed_id="TI-001",
        feed_name="CVE Database",
        feed_type="vulnerability",
        source_url="https://nvd.nist.gov/vuln/data-feeds",
        update_frequency="daily",
        format="json",
        authentication={},
        filters={"severity": ["high", "critical"]}
    )
    
    grc_engine.threat_intelligence.add_threat_feed(example_feed)
    
    return grc_engine

def print_dashboard(dashboard: Dict[str, Any], role: StakeholderRole):
    """Print dashboard in a formatted way"""
    print(f"\n🛡️  Guardians Armory: {role.value.title()} Dashboard")
    print("=" * 60)
    
    if role == StakeholderRole.EXECUTIVE:
        print(f"📊 Overall Risk Score: {dashboard.get('overall_risk_score', 0):.1%}")
        print(f"🎯 Compliance Status: {dashboard.get('compliance_status', {}).get('overall_compliance', 0):.1%}")
        
        print("\n📈 Key Metrics:")
        for metric in dashboard.get('key_metrics', []):
            trend_emoji = "📈" if metric.get('trend') == 'improving' else "📉" if metric.get('trend') == 'decreasing' else "➡️"
            print(f"  {trend_emoji} {metric.get('metric', 'N/A')}: {metric.get('value', 'N/A')}")
        
        print("\n🚨 Recent Incidents:")
        for incident in dashboard.get('recent_incidents', []):
            severity_emoji = "🔴" if incident.get('severity') == 'High' else "🟡" if incident.get('severity') == 'Medium' else "🟢"
            print(f"  {severity_emoji} {incident.get('id', 'N/A')}: {incident.get('status', 'N/A')} ({incident.get('time', 'N/A')})")
    
    elif role == StakeholderRole.ENGINEER:
        print(f"🔧 Security Controls: {len(dashboard.get('security_controls', []))} active")
        print(f"⚠️  Vulnerabilities: {len(dashboard.get('vulnerabilities', []))} open")
        
        deployment = dashboard.get('deployment_status', {})
        print(f"🚀 Deployment Success Rate: {deployment.get('deployment_success_rate', 0):.1%}")
        
        print("\n🔧 Security Controls:")
        for control in dashboard.get('security_controls', []):
            status_emoji = "🟢" if control.get('status') == 'Active' else "🔴"
            print(f"  {status_emoji} {control.get('control_id', 'N/A')}: {control.get('status', 'N/A')}")
        
        print("\n⚠️  Vulnerabilities:")
        for vuln in dashboard.get('vulnerabilities', []):
            severity_emoji = "🔴" if vuln.get('severity') == 'High' else "🟡" if vuln.get('severity') == 'Medium' else "🟢"
            print(f"  {severity_emoji} {vuln.get('cve', 'N/A')}: {vuln.get('status', 'N/A')}")
    
    elif role == StakeholderRole.AUDITOR:
        effectiveness = dashboard.get('control_effectiveness', {})
        print(f"📋 Control Effectiveness: {effectiveness.get('overall_effectiveness', 0):.1%}")
        print(f"📊 Policy Compliance: {dashboard.get('policy_compliance', {}).get('overall_policy_compliance', 0):.1%}")
        
        print("\n📋 Compliance Evidence:")
        for evidence in dashboard.get('compliance_evidence', []):
            print(f"  📄 {evidence.get('control', 'N/A')}: {evidence.get('evidence', 'N/A')}")
        
        print("\n📝 Audit Trail:")
        for audit in dashboard.get('audit_trail', []):
            print(f"  📝 {audit.get('action', 'N/A')}: {audit.get('timestamp', 'N/A')}")

if __name__ == "__main__":
    print("🛡️  Guardians Armory: GRC Engineering Demo")
    print("=" * 50)
    
    # Create and demonstrate GRC Engineering Engine
    grc_engine = create_example_grc_engine()
    
    # Generate GRC report
    print("\n📋 Generating GRC Engineering Report...")
    report = grc_engine.generate_grc_report()
    print("✅ GRC Report generated successfully")
    
    # Get stakeholder dashboards
    print("\n👥 Stakeholder Dashboards:")
    for role in [StakeholderRole.EXECUTIVE, StakeholderRole.ENGINEER, StakeholderRole.AUDITOR]:
        dashboard = grc_engine.get_stakeholder_dashboard(role)
        print_dashboard(dashboard, role)
    
    # Assess GRC maturity
    print("\n📊 GRC Maturity Assessment:")
    maturity = grc_engine.assess_grc_maturity()
    print(f"  Overall Maturity: {maturity.get('overall_maturity', 0):.1%}")
    print(f"  Automation Coverage: {maturity.get('automation_coverage', 0):.1%}")
    print(f"  GRC-as-Code: {maturity.get('grc_as_code_implementation', 0):.1%}")
    print(f"  Continuous Assurance: {maturity.get('continuous_assurance', 0):.1%}")
    
    # Demonstrate GRC values and principles
    print("\n🎯 GRC Values Alignment:")
    for value in GRCValue:
        alignment = grc_engine._assess_value_alignment(value)
        print(f"  {value.value.replace('_', ' ').title()}: {alignment:.1%}")
    
    print("\n🧠 GRC Principles Alignment:")
    for principle in GRCPrinciple:
        alignment = grc_engine._assess_principle_alignment(principle)
        print(f"  {principle.value.replace('_', ' ').title()}: {alignment:.1%}")
    
    print("\n🏆 Demo completed successfully!")
    print("This demonstrates the core GRC Engineering concepts:")
    print("  • GRC-as-Code: Security controls as infrastructure code")
    print("  • Automation-First: End-to-end automation")
    print("  • Continuous Assurance: Real-time monitoring")
    print("  • Stakeholder-Centric UX: Role-based dashboards")
    print("  • Threat Intelligence: Evidence-based threat modeling")
    print("  • Systems Thinking: Holistic risk assessment")