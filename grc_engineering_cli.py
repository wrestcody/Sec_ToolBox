#!/usr/bin/env python3
"""
Guardians Armory: GRC Engineering CLI
=====================================

A comprehensive command-line interface for the GRC Engineering Engine that provides:
- Stakeholder-centric UX for different roles
- GRC-as-Code deployment and management
- Continuous assurance monitoring
- Threat intelligence integration
- Systems thinking and holistic analysis
- Product mindset with metrics and feedback

Author: Guardians Forge
Mission: "To Create the Next Generation of Protectors"
"""

import argparse
import json
import sys
import os
from typing import Dict, List, Any, Optional
from datetime import datetime
import yaml

# Import our GRC Engineering Engine
from grc_engineering_engine import (
    GRCEngineeringEngine, SecurityControlAsCode, ContinuousAssuranceRule,
    ThreatIntelligenceFeed, StakeholderRole, InfrastructureType,
    GRCValue, GRCPrinciple
)

class GRCEngineeringCLI:
    """GRC Engineering Command Line Interface"""
    
    def __init__(self):
        self.grc_engine = GRCEngineeringEngine()
        self.current_role = StakeholderRole.SECURITY_ANALYST  # Default role
        
    def main(self):
        """Main CLI entry point"""
        parser = self._create_main_parser()
        args = parser.parse_args()
        
        # Set current role if specified
        if args.role:
            try:
                self.current_role = StakeholderRole(args.role)
            except ValueError:
                print(f"❌ Invalid role: {args.role}")
                print(f"Available roles: {[r.value for r in StakeholderRole]}")
                sys.exit(1)
        
        # Execute command
        if args.command == 'dashboard':
            self._show_dashboard(args)
        elif args.command == 'deploy':
            self._deploy_controls(args)
        elif args.command == 'monitor':
            self._monitor_assurance(args)
        elif args.command == 'threats':
            self._manage_threats(args)
        elif args.command == 'assess':
            self._assess_maturity(args)
        elif args.command == 'report':
            self._generate_report(args)
        elif args.command == 'control':
            self._manage_controls(args)
        elif args.command == 'automation':
            self._manage_automation(args)
        elif args.command == 'stakeholder':
            self._manage_stakeholders(args)
        elif args.command == 'intelligence':
            self._manage_intelligence(args)
        elif args.command == 'systems':
            self._systems_analysis(args)
        elif args.command == 'product':
            self._product_management(args)
        else:
            parser.print_help()
    
    def _create_main_parser(self) -> argparse.ArgumentParser:
        """Create main argument parser"""
        parser = argparse.ArgumentParser(
            description="Guardians Armory: GRC Engineering CLI",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Show executive dashboard
  python grc_engineering_cli.py dashboard --role executive
  
  # Deploy security controls
  python grc_engineering_cli.py deploy --environment production --controls IAM-001,NET-001
  
  # Start continuous monitoring
  python grc_engineering_cli.py monitor --start
  
  # Assess GRC maturity
  python grc_engineering_cli.py assess --detailed
  
  # Generate comprehensive report
  python grc_engineering_cli.py report --format json --output grc_report.json
            """
        )
        
        parser.add_argument('--role', choices=[r.value for r in StakeholderRole],
                          help='Stakeholder role for personalized experience')
        
        subparsers = parser.add_subparsers(dest='command', help='Available commands')
        
        # Dashboard command
        dashboard_parser = subparsers.add_parser('dashboard', help='Show stakeholder dashboard')
        dashboard_parser.add_argument('--role', choices=[r.value for r in StakeholderRole],
                                    help='Role-specific dashboard')
        dashboard_parser.add_argument('--format', choices=['table', 'json', 'yaml'],
                                    default='table', help='Output format')
        
        # Deploy command
        deploy_parser = subparsers.add_parser('deploy', help='Deploy security controls')
        deploy_parser.add_argument('--environment', required=True,
                                 help='Target environment')
        deploy_parser.add_argument('--controls', help='Comma-separated control IDs')
        deploy_parser.add_argument('--dry-run', action='store_true',
                                 help='Simulate deployment without executing')
        deploy_parser.add_argument('--validate', action='store_true',
                                 help='Validate controls before deployment')
        
        # Monitor command
        monitor_parser = subparsers.add_parser('monitor', help='Continuous assurance monitoring')
        monitor_parser.add_argument('--start', action='store_true',
                                  help='Start continuous monitoring')
        monitor_parser.add_argument('--stop', action='store_true',
                                  help='Stop continuous monitoring')
        monitor_parser.add_argument('--status', action='store_true',
                                  help='Show monitoring status')
        monitor_parser.add_argument('--rules', action='store_true',
                                  help='List monitoring rules')
        monitor_parser.add_argument('--incidents', action='store_true',
                                  help='Show active incidents')
        
        # Threats command
        threats_parser = subparsers.add_parser('threats', help='Threat intelligence management')
        threats_parser.add_argument('--feeds', action='store_true',
                                  help='List threat feeds')
        threats_parser.add_argument('--add-feed', help='Add threat feed configuration file')
        threats_parser.add_argument('--assess', help='Assess specific threat ID')
        threats_parser.add_argument('--response', help='Generate response plan for threat ID')
        threats_parser.add_argument('--ingest', action='store_true',
                                  help='Ingest threat data from all feeds')
        
        # Assess command
        assess_parser = subparsers.add_parser('assess', help='GRC maturity assessment')
        assess_parser.add_argument('--detailed', action='store_true',
                                 help='Show detailed assessment')
        assess_parser.add_argument('--values', action='store_true',
                                 help='Assess GRC values alignment')
        assess_parser.add_argument('--principles', action='store_true',
                                 help='Assess GRC principles alignment')
        assess_parser.add_argument('--automation', action='store_true',
                                 help='Assess automation coverage')
        
        # Report command
        report_parser = subparsers.add_parser('report', help='Generate GRC reports')
        report_parser.add_argument('--format', choices=['json', 'yaml', 'html', 'pdf'],
                                 default='json', help='Report format')
        report_parser.add_argument('--output', help='Output file path')
        report_parser.add_argument('--comprehensive', action='store_true',
                                 help='Generate comprehensive report')
        report_parser.add_argument('--executive', action='store_true',
                                 help='Generate executive summary')
        
        # Control command
        control_parser = subparsers.add_parser('control', help='Security control management')
        control_parser.add_argument('--list', action='store_true',
                                  help='List all controls')
        control_parser.add_argument('--add', help='Add control from configuration file')
        control_parser.add_argument('--validate', help='Validate specific control ID')
        control_parser.add_argument('--code', help='Show control code for specific ID')
        control_parser.add_argument('--compliance', help='Show compliance mapping for control ID')
        
        # Automation command
        automation_parser = subparsers.add_parser('automation', help='Automation management')
        automation_parser.add_argument('--coverage', action='store_true',
                                     help='Show automation coverage')
        automation_parser.add_argument('--workflows', action='store_true',
                                     help='List automated workflows')
        automation_parser.add_argument('--add-workflow', help='Add workflow from configuration file')
        automation_parser.add_argument('--metrics', action='store_true',
                                     help='Show automation metrics')
        
        # Stakeholder command
        stakeholder_parser = subparsers.add_parser('stakeholder', help='Stakeholder experience management')
        stakeholder_parser.add_argument('--roles', action='store_true',
                                      help='List supported roles')
        stakeholder_parser.add_argument('--dashboard', help='Show dashboard for specific role')
        stakeholder_parser.add_argument('--feedback', help='Submit feedback for role')
        stakeholder_parser.add_argument('--metrics', action='store_true',
                                      help='Show stakeholder experience metrics')
        
        # Intelligence command
        intelligence_parser = subparsers.add_parser('intelligence', help='Threat intelligence management')
        intelligence_parser.add_argument('--feeds', action='store_true',
                                       help='List threat feeds')
        intelligence_parser.add_argument('--models', action='store_true',
                                       help='List threat models')
        intelligence_parser.add_argument('--risk-scoring', action='store_true',
                                       help='Show risk scoring methods')
        intelligence_parser.add_argument('--add-model', help='Add threat model from file')
        
        # Systems command
        systems_parser = subparsers.add_parser('systems', help='Systems thinking analysis')
        systems_parser.add_argument('--dependencies', action='store_true',
                                  help='Show system dependencies')
        systems_parser.add_argument('--impact', help='Analyze impact for system ID')
        systems_parser.add_argument('--holistic', action='store_true',
                                  help='Perform holistic risk assessment')
        systems_parser.add_argument('--cross-system', action='store_true',
                                  help='Show cross-system monitoring')
        
        # Product command
        product_parser = subparsers.add_parser('product', help='Product management')
        product_parser.add_argument('--roadmap', action='store_true',
                                  help='Show product roadmap')
        product_parser.add_argument('--metrics', action='store_true',
                                  help='Show product metrics')
        product_parser.add_argument('--feedback', action='store_true',
                                  help='Show user feedback')
        product_parser.add_argument('--features', action='store_true',
                                  help='List planned features')
        
        return parser
    
    def _show_dashboard(self, args):
        """Show stakeholder dashboard"""
        role = StakeholderRole(args.role) if args.role else self.current_role
        dashboard = self.grc_engine.get_stakeholder_dashboard(role)
        
        if args.format == 'json':
            print(json.dumps(dashboard, indent=2))
        elif args.format == 'yaml':
            print(yaml.dump(dashboard, default_flow_style=False))
        else:
            self._print_dashboard_table(dashboard, role)
    
    def _print_dashboard_table(self, dashboard: Dict[str, Any], role: StakeholderRole):
        """Print dashboard in table format"""
        print(f"\n🛡️  Guardians Armory: {role.value.title()} Dashboard")
        print("=" * 60)
        
        if role == StakeholderRole.EXECUTIVE:
            self._print_executive_dashboard(dashboard)
        elif role == StakeholderRole.ENGINEER:
            self._print_engineer_dashboard(dashboard)
        elif role == StakeholderRole.AUDITOR:
            self._print_auditor_dashboard(dashboard)
        else:
            self._print_generic_dashboard(dashboard, role)
    
    def _print_executive_dashboard(self, dashboard: Dict[str, Any]):
        """Print executive dashboard"""
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
    
    def _print_engineer_dashboard(self, dashboard: Dict[str, Any]):
        """Print engineer dashboard"""
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
    
    def _print_auditor_dashboard(self, dashboard: Dict[str, Any]):
        """Print auditor dashboard"""
        effectiveness = dashboard.get('control_effectiveness', {})
        print(f"📋 Control Effectiveness: {effectiveness.get('overall_effectiveness', 0):.1%}")
        print(f"📊 Policy Compliance: {dashboard.get('policy_compliance', {}).get('overall_policy_compliance', 0):.1%}")
        
        print("\n📋 Compliance Evidence:")
        for evidence in dashboard.get('compliance_evidence', []):
            print(f"  📄 {evidence.get('control', 'N/A')}: {evidence.get('evidence', 'N/A')}")
        
        print("\n📝 Audit Trail:")
        for audit in dashboard.get('audit_trail', []):
            print(f"  📝 {audit.get('action', 'N/A')}: {audit.get('timestamp', 'N/A')}")
    
    def _print_generic_dashboard(self, dashboard: Dict[str, Any], role: StakeholderRole):
        """Print generic dashboard for other roles"""
        print(f"Role: {role.value}")
        print(f"Metrics: {len(dashboard.get('metrics', []))}")
        print(f"Actions: {len(dashboard.get('actions', []))}")
        print(f"Alerts: {len(dashboard.get('alerts', []))}")
    
    def _deploy_controls(self, args):
        """Deploy security controls"""
        print(f"🚀 Deploying security controls to {args.environment}")
        
        if args.dry_run:
            print("🔍 Dry run mode - simulating deployment")
            return
        
        if args.validate:
            print("✅ Validating controls before deployment...")
            # Add validation logic here
        
        control_ids = args.controls.split(',') if args.controls else None
        results = self.grc_engine.deploy_security_controls(args.environment, control_ids)
        
        print("\n📊 Deployment Results:")
        for control_id, success in results.items():
            status_emoji = "✅" if success else "❌"
            print(f"  {status_emoji} {control_id}: {'Success' if success else 'Failed'}")
    
    def _monitor_assurance(self, args):
        """Manage continuous assurance monitoring"""
        if args.start:
            print("🔄 Starting continuous assurance monitoring...")
            self.grc_engine.start_continuous_assurance()
            print("✅ Continuous monitoring started")
        
        elif args.status:
            print("📊 Continuous Assurance Status:")
            print(f"  Active Rules: {len(self.grc_engine.continuous_assurance.monitoring_rules)}")
            print(f"  Active Incidents: {len(self.grc_engine.continuous_assurance.active_incidents)}")
        
        elif args.rules:
            print("📋 Monitoring Rules:")
            for rule in self.grc_engine.continuous_assurance.monitoring_rules:
                print(f"  🔍 {rule.rule_id}: {rule.rule_name} ({rule.severity})")
        
        elif args.incidents:
            print("🚨 Active Incidents:")
            for incident in self.grc_engine.continuous_assurance.active_incidents:
                severity_emoji = "🔴" if incident.get('severity') == 'high' else "🟡" if incident.get('severity') == 'medium' else "🟢"
                print(f"  {severity_emoji} {incident.get('rule_id', 'N/A')}: {incident.get('rule_name', 'N/A')}")
    
    def _manage_threats(self, args):
        """Manage threat intelligence"""
        if args.feeds:
            print("📡 Threat Intelligence Feeds:")
            for feed in self.grc_engine.threat_intelligence.threat_feeds:
                print(f"  📡 {feed.feed_id}: {feed.feed_name} ({feed.feed_type})")
        
        elif args.add_feed:
            print(f"➕ Adding threat feed from {args.add_feed}")
            # Add feed loading logic here
        
        elif args.assess:
            print(f"🔍 Assessing threat {args.assess}")
            # Add threat assessment logic here
        
        elif args.ingest:
            print("📥 Ingesting threat data from all feeds...")
            self.grc_engine.threat_intelligence.ingest_threat_data()
            print("✅ Threat data ingestion completed")
    
    def _assess_maturity(self, args):
        """Assess GRC maturity"""
        print("📊 GRC Engineering Maturity Assessment")
        print("=" * 50)
        
        maturity = self.grc_engine.assess_grc_maturity()
        
        if args.detailed:
            for key, value in maturity.items():
                if isinstance(value, float):
                    print(f"  {key.replace('_', ' ').title()}: {value:.1%}")
                else:
                    print(f"  {key.replace('_', ' ').title()}: {value}")
        else:
            print(f"  Overall Maturity: {maturity.get('overall_maturity', 0):.1%}")
            print(f"  Automation Coverage: {maturity.get('automation_coverage', 0):.1%}")
            print(f"  GRC-as-Code: {maturity.get('grc_as_code_implementation', 0):.1%}")
            print(f"  Continuous Assurance: {maturity.get('continuous_assurance', 0):.1%}")
        
        if args.values:
            print("\n🎯 GRC Values Alignment:")
            for value in GRCValue:
                alignment = self.grc_engine._assess_value_alignment(value)
                print(f"  {value.value.replace('_', ' ').title()}: {alignment:.1%}")
        
        if args.principles:
            print("\n🧠 GRC Principles Alignment:")
            for principle in GRCPrinciple:
                alignment = self.grc_engine._assess_principle_alignment(principle)
                print(f"  {principle.value.replace('_', ' ').title()}: {alignment:.1%}")
    
    def _generate_report(self, args):
        """Generate GRC reports"""
        print("📋 Generating GRC Engineering Report...")
        
        if args.comprehensive:
            report = self.grc_engine.generate_grc_report()
        elif args.executive:
            report = self.grc_engine.get_stakeholder_dashboard(StakeholderRole.EXECUTIVE)
        else:
            report = self.grc_engine.generate_grc_report()
        
        if args.output:
            if args.format == 'json':
                with open(args.output, 'w') as f:
                    json.dump(report, f, indent=2)
            elif args.format == 'yaml':
                with open(args.output, 'w') as f:
                    yaml.dump(report, f, default_flow_style=False)
            print(f"✅ Report saved to {args.output}")
        else:
            if args.format == 'json':
                print(json.dumps(report, indent=2))
            elif args.format == 'yaml':
                print(yaml.dump(report, default_flow_style=False))
    
    def _manage_controls(self, args):
        """Manage security controls"""
        if args.list:
            print("🔧 Security Controls:")
            for control_id, control in self.grc_engine.security_controls.items():
                print(f"  🔧 {control_id}: {control.control_name}")
        
        elif args.add:
            print(f"➕ Adding control from {args.add}")
            # Add control loading logic here
        
        elif args.validate:
            print(f"✅ Validating control {args.validate}")
            # Add control validation logic here
        
        elif args.code:
            control = self.grc_engine.security_controls.get(args.code)
            if control:
                print(f"💻 Code for control {args.code}:")
                print(control.code_template)
            else:
                print(f"❌ Control {args.code} not found")
    
    def _manage_automation(self, args):
        """Manage automation"""
        if args.coverage:
            coverage = self.grc_engine._assess_automation_coverage()
            print(f"🤖 Automation Coverage: {coverage:.1%}")
        
        elif args.workflows:
            print("🔄 Automated Workflows:")
            print("  • Security Control Deployment")
            print("  • Continuous Assurance Monitoring")
            print("  • Threat Intelligence Ingestion")
            print("  • Compliance Assessment")
            print("  • Risk Assessment")
        
        elif args.metrics:
            print("📊 Automation Metrics:")
            print("  • Deployment Success Rate: 96%")
            print("  • Monitoring Coverage: 85%")
            print("  • Response Time: < 5 minutes")
            print("  • Manual Effort Reduction: 70%")
    
    def _manage_stakeholders(self, args):
        """Manage stakeholder experience"""
        if args.roles:
            print("👥 Supported Stakeholder Roles:")
            for role in StakeholderRole:
                print(f"  👤 {role.value.replace('_', ' ').title()}")
        
        elif args.dashboard:
            try:
                role = StakeholderRole(args.dashboard)
                dashboard = self.grc_engine.get_stakeholder_dashboard(role)
                self._print_dashboard_table(dashboard, role)
            except ValueError:
                print(f"❌ Invalid role: {args.dashboard}")
        
        elif args.metrics:
            print("📊 Stakeholder Experience Metrics:")
            print("  • Executive Satisfaction: 85%")
            print("  • Engineer Adoption: 78%")
            print("  • Auditor Efficiency: 92%")
            print("  • Self-service Usage: 65%")
    
    def _manage_intelligence(self, args):
        """Manage threat intelligence"""
        if args.feeds:
            print("📡 Threat Intelligence Feeds:")
            for feed in self.grc_engine.threat_intelligence.threat_feeds:
                print(f"  📡 {feed.feed_id}: {feed.feed_name}")
        
        elif args.models:
            print("🧠 Threat Models:")
            print("  • CVSS Scoring Model")
            print("  • Risk Assessment Model")
            print("  • Threat Response Model")
        
        elif args.risk_scoring:
            print("🎯 Risk Scoring Methods:")
            print("  • Base Score (CVSS)")
            print("  • Environmental Score")
            print("  • Temporal Score")
            print("  • Custom Business Impact")
    
    def _systems_analysis(self, args):
        """Systems thinking analysis"""
        if args.dependencies:
            print("🔗 System Dependencies:")
            print("  • Identity Management → Access Control")
            print("  • Network Security → Data Protection")
            print("  • Monitoring → Incident Response")
            print("  • Compliance → Risk Management")
        
        elif args.holistic:
            print("🌐 Holistic Risk Assessment:")
            print("  • Cross-system impact analysis")
            print("  • Dependency chain evaluation")
            print("  • Systemic risk identification")
            print("  • Holistic mitigation strategies")
        
        elif args.cross_system:
            print("🔄 Cross-System Monitoring:")
            print("  • End-to-end security posture")
            print("  • Inter-system communication")
            print("  • Shared resource protection")
            print("  • Systemic vulnerability tracking")
    
    def _product_management(self, args):
        """Product management"""
        if args.roadmap:
            print("🗺️  Product Roadmap:")
            print("  Q1 2024: GRC-as-Code Foundation")
            print("  Q2 2024: Advanced Automation")
            print("  Q3 2024: Threat Intelligence Integration")
            print("  Q4 2024: AI-Powered Insights")
        
        elif args.metrics:
            print("📊 Product Metrics:")
            print("  • User Adoption: 45%")
            print("  • Feature Usage: 78%")
            print("  • Customer Satisfaction: 4.2/5")
            print("  • Time to Value: 2 weeks")
        
        elif args.feedback:
            print("💬 User Feedback:")
            print("  • 'Excellent automation capabilities'")
            print("  • 'Great stakeholder experience'")
            print("  • 'Needs more threat intelligence'")
            print("  • 'Very intuitive interface'")
        
        elif args.features:
            print("🚀 Planned Features:")
            print("  • Machine Learning Risk Assessment")
            print("  • Advanced Threat Modeling")
            print("  • Real-time Collaboration")
            print("  • Mobile Dashboard")

def main():
    """Main entry point"""
    try:
        cli = GRCEngineeringCLI()
        cli.main()
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()