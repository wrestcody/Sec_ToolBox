#!/usr/bin/env python3
"""
Guardians Security Governance: Comprehensive Security Management CLI

A command-line interface for the Enhanced Guardian's Mandate framework that provides:
- Security posture assessment and monitoring
- Security best practices guidance
- Compliance framework management
- Security metrics and KPIs
- Incident prevention and response
- Security training and awareness
- Evidence integrity and chain of custody

This tool transforms the Guardian's Mandate from a forensic framework into a complete
security governance platform that guides, enforces, monitors, improves, prevents,
responds, and trains security teams.
"""

import argparse
import json
import sys
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path

# Import the Enhanced Guardian's Mandate framework
try:
    from enhanced_guardians_mandate import (
        EnhancedGuardianMandate,
        SecurityDomain,
        SecurityMaturityLevel,
        ComplianceStandard,
        SecurityControl,
        ThreatLevel,
        assess_security_posture,
        get_security_guidance,
        export_security_report
    )
    FRAMEWORK_AVAILABLE = True
except ImportError:
    print("Warning: Enhanced Guardian's Mandate framework not available.")
    FRAMEWORK_AVAILABLE = False


class GuardiansSecurityGovernance:
    """
    Guardians Security Governance CLI tool.
    
    Provides comprehensive security management capabilities through the
    Enhanced Guardian's Mandate framework.
    """
    
    def __init__(self, aws_region: str = "us-east-1", enable_aws_integration: bool = True):
        """
        Initialize the Guardians Security Governance tool.
        
        Args:
            aws_region: AWS region for service integration
            enable_aws_integration: Enable AWS service integration
        """
        self.aws_region = aws_region
        self.enable_aws_integration = enable_aws_integration
        
        if FRAMEWORK_AVAILABLE:
            self.framework = EnhancedGuardianMandate(
                enable_aws_integration=enable_aws_integration,
                aws_region=aws_region
            )
        else:
            self.framework = None
        
        self.print_banner()
    
    def print_banner(self):
        """Print the Guardians Security Governance banner."""
        banner = """
🛡️  GUARDIANS SECURITY GOVERNANCE
═══════════════════════════════════════════════════════════════════════════════
   Comprehensive Security Management Platform
   Powered by Enhanced Guardian's Mandate Framework
   
   "To Create the Next Generation of Protectors"
   
   Capabilities:
   • Security Posture Assessment & Monitoring
   • Security Best Practices & Operational Guidance
   • Compliance Framework Management
   • Security Metrics & KPIs
   • Incident Prevention & Response
   • Security Training & Awareness
   • Evidence Integrity & Chain of Custody
═══════════════════════════════════════════════════════════════════════════════
        """
        print(banner)
    
    def assess_security_posture(self, domain: str = None, detailed: bool = False) -> Dict[str, Any]:
        """
        Assess security posture for overall or specific domain.
        
        Args:
            domain: Specific security domain to assess
            detailed: Provide detailed assessment results
        
        Returns:
            Assessment results
        """
        if not FRAMEWORK_AVAILABLE:
            return {"error": "Enhanced Guardian's Mandate framework not available"}
        
        print("🔍 Assessing Security Posture...")
        print("=" * 60)
        
        # Determine domain
        security_domain = None
        if domain:
            try:
                security_domain = SecurityDomain(domain)
                print(f"   Domain: {security_domain.value}")
            except ValueError:
                print(f"❌ Invalid domain: {domain}")
                return {"error": f"Invalid domain: {domain}"}
        else:
            print("   Domain: Overall Security Posture")
        
        # Perform assessment
        try:
            assessment = self.framework.assess_security_posture(security_domain)
            
            # Display results
            print(f"\n📊 Assessment Results:")
            print(f"   Assessment ID: {assessment.assessment_id}")
            print(f"   Timestamp: {assessment.timestamp}")
            print(f"   Compliance Score: {assessment.compliance_score:.1f}%")
            print(f"   Maturity Level: {assessment.maturity_level.value}")
            print(f"   Controls Assessed: {len(assessment.controls_assessed)}")
            print(f"   Findings: {len(assessment.findings)}")
            
            # Display findings summary
            if assessment.findings:
                print(f"\n🔍 Findings Summary:")
                status_counts = {}
                for finding in assessment.findings:
                    status = finding.get('status', 'UNKNOWN')
                    status_counts[status] = status_counts.get(status, 0) + 1
                
                for status, count in status_counts.items():
                    status_icon = "✅" if status == "COMPLIANT" else "⚠️" if status == "PARTIALLY_COMPLIANT" else "❌"
                    print(f"   {status_icon} {status}: {count}")
            
            # Display recommendations
            if assessment.recommendations:
                print(f"\n💡 Key Recommendations:")
                for i, recommendation in enumerate(assessment.recommendations[:5], 1):
                    print(f"   {i}. {recommendation}")
            
            # Display next steps
            if assessment.next_steps:
                print(f"\n🚀 Next Steps:")
                for i, step in enumerate(assessment.next_steps[:3], 1):
                    print(f"   {i}. {step}")
            
            # Detailed findings
            if detailed and assessment.findings:
                print(f"\n📋 Detailed Findings:")
                for finding in assessment.findings:
                    status_icon = "✅" if finding.get('status') == "COMPLIANT" else "⚠️" if finding.get('status') == "PARTIALLY_COMPLIANT" else "❌"
                    print(f"\n   {status_icon} {finding.get('control_name', 'Unknown Control')}")
                    print(f"      Control ID: {finding.get('control_id', 'Unknown')}")
                    print(f"      Status: {finding.get('status', 'Unknown')}")
                    print(f"      Risk Level: {finding.get('risk_level', 'Unknown')}")
                    
                    if finding.get('evidence'):
                        print(f"      Evidence:")
                        for evidence in finding['evidence']:
                            print(f"        • {evidence}")
            
            return assessment.to_dict()
        
        except Exception as e:
            error_msg = f"Assessment failed: {e}"
            print(f"❌ {error_msg}")
            return {"error": error_msg}
    
    def get_security_guidance(self, domain: str = None, control_id: str = None) -> Dict[str, Any]:
        """
        Get security guidance for domain or specific control.
        
        Args:
            domain: Security domain for guidance
            control_id: Specific control ID for detailed guidance
        
        Returns:
            Security guidance information
        """
        if not FRAMEWORK_AVAILABLE:
            return {"error": "Enhanced Guardian's Mandate framework not available"}
        
        print("📚 Security Guidance")
        print("=" * 60)
        
        try:
            # Determine domain
            security_domain = None
            if domain:
                try:
                    security_domain = SecurityDomain(domain)
                    print(f"   Domain: {security_domain.value}")
                except ValueError:
                    print(f"❌ Invalid domain: {domain}")
                    return {"error": f"Invalid domain: {domain}"}
            else:
                print("   Domain: All Security Domains")
            
            # Get guidance
            guidance = self.framework.get_security_guidance(security_domain, control_id)
            
            if control_id:
                # Display specific control guidance
                if 'control' in guidance:
                    control = guidance['control']
                    print(f"\n🎯 Control: {control['control_name']}")
                    print(f"   Control ID: {control['control_id']}")
                    print(f"   Domain: {control['domain'].value}")
                    print(f"   Description: {control['description']}")
                    print(f"   Threat Level: {control['threat_level'].value}")
                    print(f"   Maturity Level: {control['maturity_level'].value}")
                    
                    print(f"\n📋 Implementation Guidance:")
                    print(control['implementation_guidance'])
                    
                    print(f"\n🔧 AWS Services:")
                    for service in control['aws_services']:
                        print(f"   • {service}")
                    
                    print(f"\n📊 Metrics:")
                    for metric in control['metrics']:
                        print(f"   • {metric}")
                    
                    print(f"\n🔧 Remediation Steps:")
                    for i, step in enumerate(control['remediation_steps'], 1):
                        print(f"   {i}. {step}")
                    
                    print(f"\n📚 References:")
                    for reference in control['references']:
                        print(f"   • {reference}")
                
            elif domain:
                # Display domain guidance
                if 'domain' in guidance:
                    print(f"\n📋 Domain Overview:")
                    overview = guidance.get('domain_overview', {})
                    print(f"   Description: {overview.get('description', 'N/A')}")
                    
                    print(f"\n🎯 Key Principles:")
                    for principle in overview.get('key_principles', []):
                        print(f"   • {principle}")
                    
                    print(f"\n☁️  AWS Services:")
                    for service in overview.get('aws_services', []):
                        print(f"   • {service}")
                    
                    print(f"\n⚠️  Common Threats:")
                    for threat in overview.get('common_threats', []):
                        print(f"   • {threat}")
                    
                    print(f"\n💡 Best Practices:")
                    for practice in overview.get('best_practices', []):
                        print(f"   • {practice}")
                    
                    print(f"\n🔧 Controls in this Domain:")
                    for control in guidance.get('controls', []):
                        status_icon = "✅" if control.get('maturity_level') == SecurityMaturityLevel.OPTIMIZING else "⚠️"
                        print(f"   {status_icon} {control['control_name']} ({control['control_id']})")
            
            else:
                # Display overall framework guidance
                print(f"\n🏗️  Framework Overview:")
                framework_info = guidance.get('framework_info', {})
                print(f"   Version: {framework_info.get('framework_version', 'N/A')}")
                print(f"   Description: {framework_info.get('framework_description', 'N/A')}")
                print(f"   AWS Integration: {'✅ Enabled' if framework_info.get('aws_integration_enabled') else '❌ Disabled'}")
                
                print(f"\n🎯 Security Domains:")
                for domain_name, domain_info in guidance.get('domains', {}).items():
                    print(f"   • {domain_name.replace('_', ' ').title()}")
                    controls = domain_info.get('controls', [])
                    print(f"     Controls: {len(controls)}")
            
            return guidance
        
        except Exception as e:
            error_msg = f"Failed to get guidance: {e}"
            print(f"❌ {error_msg}")
            return {"error": error_msg}
    
    def list_security_domains(self) -> Dict[str, Any]:
        """List all available security domains."""
        if not FRAMEWORK_AVAILABLE:
            return {"error": "Enhanced Guardian's Mandate framework not available"}
        
        print("🎯 Security Domains")
        print("=" * 60)
        
        domains = []
        for domain in SecurityDomain:
            domains.append({
                'name': domain.value,
                'display_name': domain.value.replace('_', ' ').title(),
                'description': self._get_domain_description(domain)
            })
            print(f"   • {domain.value.replace('_', ' ').title()}")
            print(f"     {self._get_domain_description(domain)}")
        
        return {'domains': domains}
    
    def _get_domain_description(self, domain) -> str:
        """Get description for a security domain."""
        descriptions = {
            "identity_and_access_management": "Manage and control access to resources and systems",
            "data_protection": "Protect data throughout its lifecycle",
            "network_security": "Secure network infrastructure and communications",
            "application_security": "Secure application development and deployment",
            "infrastructure_security": "Secure infrastructure and platform security",
            "incident_response": "Detect, respond to, and recover from security incidents",
            "compliance_and_governance": "Ensure compliance with security standards and regulations",
            "operational_security": "Secure day-to-day security operations",
            "threat_intelligence": "Gather and analyze threat intelligence",
            "security_awareness": "Train and educate users on security best practices"
        }
        return descriptions.get(domain.value if hasattr(domain, 'value') else str(domain), "Security domain")
    
    def list_compliance_standards(self) -> Dict[str, Any]:
        """List all available compliance standards."""
        if not FRAMEWORK_AVAILABLE:
            return {"error": "Enhanced Guardian's Mandate framework not available"}
        
        print("📋 Compliance Standards")
        print("=" * 60)
        
        standards = []
        for standard in ComplianceStandard:
            standards.append({
                'name': standard.value,
                'display_name': standard.value.replace('_', ' ').upper(),
                'description': self._get_standard_description(standard)
            })
            print(f"   • {standard.value.replace('_', ' ').upper()}")
            print(f"     {self._get_standard_description(standard)}")
        
        return {'standards': standards}
    
    def _get_standard_description(self, standard) -> str:
        """Get description for a compliance standard."""
        descriptions = {
            "soc2": "Service Organization Control 2 - Trust Services Criteria",
            "iso27001": "Information Security Management System",
            "nist": "National Institute of Standards and Technology Cybersecurity Framework",
            "cis": "Center for Internet Security Controls",
            "pci_dss": "Payment Card Industry Data Security Standard",
            "hipaa": "Health Insurance Portability and Accountability Act",
            "gdpr": "General Data Protection Regulation",
            "aws_well_architected": "AWS Well-Architected Framework Security Pillar",
            "zero_trust": "Zero Trust Security Architecture",
            "devops_security": "DevSecOps Security Practices"
        }
        return descriptions.get(standard.value if hasattr(standard, 'value') else str(standard), "Compliance standard")
    
    def export_security_report(self, output_path: str = None, format: str = "json") -> str:
        """
        Export comprehensive security report.
        
        Args:
            output_path: Output file path
            format: Report format (json, html, pdf)
        
        Returns:
            Path to exported report
        """
        if not FRAMEWORK_AVAILABLE:
            return "Enhanced Guardian's Mandate framework not available"
        
        print("📊 Exporting Security Report...")
        print("=" * 60)
        
        try:
            if format.lower() == "json":
                report_path = self.framework.export_security_report(output_path)
                print(f"✅ Security report exported: {report_path}")
                return report_path
            else:
                print(f"⚠️  Format '{format}' not yet supported. Using JSON format.")
                report_path = self.framework.export_security_report(output_path)
                print(f"✅ Security report exported: {report_path}")
                return report_path
        
        except Exception as e:
            error_msg = f"Failed to export report: {e}"
            print(f"❌ {error_msg}")
            return error_msg
    
    def show_security_metrics(self) -> Dict[str, Any]:
        """Show current security metrics and KPIs."""
        if not FRAMEWORK_AVAILABLE:
            return {"error": "Enhanced Guardian's Mandate framework not available"}
        
        print("📈 Security Metrics & KPIs")
        print("=" * 60)
        
        try:
            # Get metrics from framework
            kpis = self.framework.security_metrics['kpis']
            kris = self.framework.security_metrics['kris']
            
            print(f"\n🎯 Key Performance Indicators (KPIs):")
            for kpi in kpis:
                print(f"   • {kpi.metric_name}")
                print(f"     Current: {kpi.current_value} {kpi.unit}")
                print(f"     Target: {kpi.target_value} {kpi.unit}")
                print(f"     Owner: {kpi.owner}")
                print(f"     Update Frequency: {kpi.update_frequency}")
            
            print(f"\n⚠️  Key Risk Indicators (KRIs):")
            for kri in kris:
                print(f"   • {kri.metric_name}")
                print(f"     Current: {kri.current_value} {kri.unit}")
                print(f"     Target: {kri.target_value} {kri.unit}")
                print(f"     Owner: {kri.owner}")
                print(f"     Update Frequency: {kri.update_frequency}")
            
            return {
                'kpis': [kpi.to_dict() for kpi in kpis],
                'kris': [kri.to_dict() for kri in kris]
            }
        
        except Exception as e:
            error_msg = f"Failed to get metrics: {e}"
            print(f"❌ {error_msg}")
            return {"error": error_msg}
    
    def show_framework_status(self) -> Dict[str, Any]:
        """Show framework status and configuration."""
        if not FRAMEWORK_AVAILABLE:
            return {"error": "Enhanced Guardian's Mandate framework not available"}
        
        print("🔧 Framework Status")
        print("=" * 60)
        
        metadata = self.framework.framework_metadata
        
        print(f"   Framework Version: {metadata.get('framework_version', 'N/A')}")
        print(f"   Framework Name: {metadata.get('framework_name', 'N/A')}")
        print(f"   Description: {metadata.get('framework_description', 'N/A')}")
        print(f"   AWS Integration: {'✅ Enabled' if metadata.get('aws_integration_enabled') else '❌ Disabled'}")
        print(f"   AWS Region: {metadata.get('aws_region', 'N/A')}")
        print(f"   Initialization: {metadata.get('initialization_timestamp', 'N/A')}")
        
        print(f"\n📊 Coverage:")
        print(f"   Security Domains: {len(metadata.get('domains_covered', []))}")
        print(f"   Compliance Standards: {len(metadata.get('compliance_standards', []))}")
        print(f"   Security Controls: {len(metadata.get('security_controls', []))}")
        
        return metadata


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Guardians Security Governance: Comprehensive Security Management CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Assess overall security posture
  python guardians_security_governance.py assess

  # Assess specific security domain
  python guardians_security_governance.py assess --domain identity_and_access_management

  # Get security guidance for IAM
  python guardians_security_governance.py guidance --domain identity_and_access_management

  # Get guidance for specific control
  python guardians_security_governance.py guidance --control-id IAM-001

  # Export security report
  python guardians_security_governance.py export-report

  # Show security metrics
  python guardians_security_governance.py metrics

  # List available domains
  python guardians_security_governance.py list-domains

  # Show framework status
  python guardians_security_governance.py status
        """
    )
    
    parser.add_argument(
        '--aws-region',
        default='us-east-1',
        help='AWS region for service integration (default: us-east-1)'
    )
    
    parser.add_argument(
        '--disable-aws-integration',
        action='store_true',
        help='Disable AWS service integration'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Assess command
    assess_parser = subparsers.add_parser('assess', help='Assess security posture')
    assess_parser.add_argument(
        '--domain',
        help='Specific security domain to assess'
    )
    assess_parser.add_argument(
        '--detailed',
        action='store_true',
        help='Provide detailed assessment results'
    )
    
    # Guidance command
    guidance_parser = subparsers.add_parser('guidance', help='Get security guidance')
    guidance_parser.add_argument(
        '--domain',
        help='Security domain for guidance'
    )
    guidance_parser.add_argument(
        '--control-id',
        help='Specific control ID for detailed guidance'
    )
    
    # Export report command
    export_parser = subparsers.add_parser('export-report', help='Export security report')
    export_parser.add_argument(
        '--output',
        help='Output file path'
    )
    export_parser.add_argument(
        '--format',
        choices=['json', 'html', 'pdf'],
        default='json',
        help='Report format (default: json)'
    )
    
    # Metrics command
    subparsers.add_parser('metrics', help='Show security metrics and KPIs')
    
    # List domains command
    subparsers.add_parser('list-domains', help='List available security domains')
    
    # List standards command
    subparsers.add_parser('list-standards', help='List available compliance standards')
    
    # Status command
    subparsers.add_parser('status', help='Show framework status')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        # Initialize governance tool
        governance = GuardiansSecurityGovernance(
            aws_region=args.aws_region,
            enable_aws_integration=not args.disable_aws_integration
        )
        
        # Execute command
        if args.command == 'assess':
            governance.assess_security_posture(
                domain=args.domain,
                detailed=args.detailed
            )
        
        elif args.command == 'guidance':
            governance.get_security_guidance(
                domain=args.domain,
                control_id=args.control_id
            )
        
        elif args.command == 'export-report':
            governance.export_security_report(
                output_path=args.output,
                format=args.format
            )
        
        elif args.command == 'metrics':
            governance.show_security_metrics()
        
        elif args.command == 'list-domains':
            governance.list_security_domains()
        
        elif args.command == 'list-standards':
            governance.list_compliance_standards()
        
        elif args.command == 'status':
            governance.show_framework_status()
        
        else:
            print(f"❌ Unknown command: {args.command}")
            parser.print_help()
    
    except Exception as e:
        print(f"❌ Command failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()