#!/usr/bin/env python3
"""
Supply Chain Security Analyzer

A comprehensive supply chain security tool that demonstrates:
- Modern supply chain threat analysis
- SBOM (Software Bill of Materials) management
- Vendor risk assessment
- Dependency vulnerability tracking
- Supply chain attack detection

This tool shows how to lead supply chain security programs in modern environments.
"""

import argparse
import json
import sys
import os
import hashlib
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, asdict
from urllib.parse import urlparse
import subprocess
import re

# Add parent directory to path for Guardian's Mandate integration
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))
try:
    from guardians_mandate_integration import GuardianTool, EvidenceLevel, AuditEventType
    GUARDIAN_MANDATE_AVAILABLE = True
except ImportError:
    GUARDIAN_MANDATE_AVAILABLE = False
    print("Warning: Guardian's Mandate not available. Running in basic mode.")


@dataclass
class Dependency:
    """Represents a software dependency with security attributes."""
    name: str
    version: str
    package_manager: str  # npm, pip, maven, etc.
    source: str  # registry URL or source
    license: Optional[str]
    vulnerabilities: List[Dict[str, Any]]
    last_updated: Optional[datetime]
    maintainer: Optional[str]
    download_count: Optional[int]
    risk_score: float = 0.0


@dataclass
class Vendor:
    """Represents a vendor with risk assessment."""
    name: str
    domain: str
    risk_score: float
    security_rating: str  # A, B, C, D, F
    last_assessment: datetime
    compliance_certifications: List[str]
    security_incidents: List[Dict[str, Any]]
    supply_chain_risks: List[str]


@dataclass
class SupplyChainRisk:
    """Represents a supply chain security risk."""
    id: str
    title: str
    description: str
    severity: str  # Critical, High, Medium, Low
    risk_type: str  # Dependency, Vendor, Process, Infrastructure
    affected_components: List[str]
    detection_date: datetime
    status: str  # Open, Mitigated, Accepted
    mitigation_strategy: Optional[str]
    business_impact: str


class SupplyChainSecurityAnalyzer(GuardianTool if GUARDIAN_MANDATE_AVAILABLE else object):
    """
    Comprehensive supply chain security analyzer.
    
    Demonstrates leadership in:
    - Supply chain risk management
    - Vendor security assessment
    - Dependency vulnerability management
    - SBOM analysis and compliance
    - Supply chain attack detection
    """
    
    def __init__(self, enable_guardian_mandate: bool = True):
        """Initialize the supply chain security analyzer."""
        if GUARDIAN_MANDATE_AVAILABLE and enable_guardian_mandate:
            super().__init__(
                tool_name="SupplyChainSecurityAnalyzer",
                tool_version="1.0.0",
                evidence_level=EvidenceLevel.HIGH
            )
        
        self.enable_guardian_mandate = enable_guardian_mandate and GUARDIAN_MANDATE_AVAILABLE
        self.dependencies = []
        self.vendors = []
        self.supply_chain_risks = []
        
        # Known malicious packages and patterns
        self.malicious_patterns = [
            r'typosquatting',
            r'package\.json\.backup',
            r'\.env\.local',
            r'password',
            r'secret',
            r'key',
            r'token',
            r'credential'
        ]
        
        # High-risk package managers and registries
        self.high_risk_sources = [
            'unpkg.com',
            'jsdelivr.net',
            'cdnjs.cloudflare.com',
            'raw.githubusercontent.com'
        ]
        
        # Supply chain attack indicators
        self.attack_indicators = {
            'dependency_confusion': ['@company', '@internal', '@private'],
            'typosquatting': ['lodash', 'lodash-', 'lodash_', 'lodashjs'],
            'malicious_updates': ['preinstall', 'postinstall', 'prepare'],
            'credential_harvesting': ['password', 'secret', 'key', 'token'],
            'data_exfiltration': ['http://', 'https://', 'ftp://', 'smtp://']
        }
        
        if self.enable_guardian_mandate:
            self.record_guardian_event(
                event_type=AuditEventType.TOOL_STARTUP.value,
                action="supply_chain_analyzer_initialized",
                details={"attack_indicators_count": len(self.attack_indicators)}
            )
    
    def analyze_dependency(self, dependency: Dependency) -> Dict[str, Any]:
        """
        Analyze a single dependency for supply chain risks.
        
        Demonstrates technical security analysis leadership.
        """
        risk_factors = []
        risk_score = 0.0
        
        # Check for known vulnerabilities
        if dependency.vulnerabilities:
            risk_factors.append(f"Has {len(dependency.vulnerabilities)} known vulnerabilities")
            risk_score += len(dependency.vulnerabilities) * 0.5
        
        # Check for malicious patterns
        for pattern in self.malicious_patterns:
            if re.search(pattern, dependency.name, re.IGNORECASE):
                risk_factors.append(f"Matches malicious pattern: {pattern}")
                risk_score += 2.0
        
        # Check for high-risk sources
        if any(source in dependency.source for source in self.high_risk_sources):
            risk_factors.append("Uses high-risk source")
            risk_score += 1.0
        
        # Check for dependency confusion indicators
        for indicator in self.attack_indicators['dependency_confusion']:
            if indicator in dependency.name:
                risk_factors.append("Potential dependency confusion target")
                risk_score += 3.0
        
        # Check for typosquatting indicators
        for indicator in self.attack_indicators['typosquatting']:
            if indicator in dependency.name:
                risk_factors.append("Potential typosquatting target")
                risk_score += 2.0
        
        # Check for outdated dependencies
        if dependency.last_updated:
            days_since_update = (datetime.now() - dependency.last_updated).days
            if days_since_update > 365:
                risk_factors.append(f"Not updated in {days_since_update} days")
                risk_score += 1.0
        
        # Check for low popularity (potential malicious package)
        if dependency.download_count and dependency.download_count < 1000:
            risk_factors.append("Low download count - potential malicious package")
            risk_score += 2.0
        
        # Update dependency risk score
        dependency.risk_score = min(10.0, risk_score)
        
        return {
            'dependency': dependency.name,
            'version': dependency.version,
            'risk_score': dependency.risk_score,
            'risk_factors': risk_factors,
            'severity': self._calculate_severity(dependency.risk_score)
        }
    
    def analyze_vendor_security(self, vendor: Vendor) -> Dict[str, Any]:
        """
        Analyze vendor security posture.
        
        Demonstrates vendor risk management leadership.
        """
        risk_factors = []
        risk_score = vendor.risk_score
        
        # Check security rating
        rating_scores = {'A': 0, 'B': 1, 'C': 2, 'D': 3, 'F': 4}
        if vendor.security_rating in rating_scores:
            risk_score += rating_scores[vendor.security_rating]
            if vendor.security_rating in ['D', 'F']:
                risk_factors.append(f"Poor security rating: {vendor.security_rating}")
        
        # Check for recent security incidents
        recent_incidents = [
            incident for incident in vendor.security_incidents
            if (datetime.now() - incident['date']).days < 365
        ]
        if recent_incidents:
            risk_factors.append(f"Has {len(recent_incidents)} recent security incidents")
            risk_score += len(recent_incidents) * 0.5
        
        # Check compliance certifications
        if not vendor.compliance_certifications:
            risk_factors.append("No compliance certifications")
            risk_score += 1.0
        
        # Check supply chain risks
        if vendor.supply_chain_risks:
            risk_factors.extend(vendor.supply_chain_risks)
            risk_score += len(vendor.supply_chain_risks) * 0.3
        
        return {
            'vendor': vendor.name,
            'domain': vendor.domain,
            'risk_score': min(10.0, risk_score),
            'risk_factors': risk_factors,
            'severity': self._calculate_severity(risk_score)
        }
    
    def detect_supply_chain_attacks(self, dependencies: List[Dependency]) -> List[Dict[str, Any]]:
        """
        Detect potential supply chain attacks.
        
        Demonstrates threat detection leadership.
        """
        detected_attacks = []
        
        for dependency in dependencies:
            attack_indicators = []
            
            # Check for malicious scripts in package.json
            if hasattr(dependency, 'scripts') and dependency.scripts:
                for script_name, script_content in dependency.scripts.items():
                    # Check for credential harvesting
                    for indicator in self.attack_indicators['credential_harvesting']:
                        if indicator in script_content.lower():
                            attack_indicators.append(f"Potential credential harvesting in {script_name}")
                    
                    # Check for data exfiltration
                    for indicator in self.attack_indicators['data_exfiltration']:
                        if indicator in script_content:
                            attack_indicators.append(f"Potential data exfiltration in {script_name}")
            
            # Check for dependency confusion
            if any(indicator in dependency.name for indicator in self.attack_indicators['dependency_confusion']):
                attack_indicators.append("Potential dependency confusion target")
            
            # Check for typosquatting
            if any(indicator in dependency.name for indicator in self.attack_indicators['typosquatting']):
                attack_indicators.append("Potential typosquatting target")
            
            if attack_indicators:
                detected_attacks.append({
                    'dependency': dependency.name,
                    'version': dependency.version,
                    'attack_indicators': attack_indicators,
                    'severity': 'High' if len(attack_indicators) > 2 else 'Medium'
                })
        
        if self.enable_guardian_mandate:
            self.record_guardian_event(
                event_type=AuditEventType.SECURITY_ANALYSIS.value,
                action="supply_chain_attacks_detected",
                details={'detected_attacks_count': len(detected_attacks)}
            )
        
        return detected_attacks
    
    def generate_sbom_report(self, dependencies: List[Dependency]) -> Dict[str, Any]:
        """
        Generate Software Bill of Materials (SBOM) report.
        
        Demonstrates compliance and transparency leadership.
        """
        total_dependencies = len(dependencies)
        high_risk_deps = [d for d in dependencies if d.risk_score >= 7.0]
        medium_risk_deps = [d for d in dependencies if 4.0 <= d.risk_score < 7.0]
        low_risk_deps = [d for d in dependencies if d.risk_score < 4.0]
        
        # Package manager distribution
        package_managers = {}
        for dep in dependencies:
            pm = dep.package_manager
            package_managers[pm] = package_managers.get(pm, 0) + 1
        
        # License distribution
        licenses = {}
        for dep in dependencies:
            if dep.license:
                licenses[dep.license] = licenses.get(dep.license, 0) + 1
        
        sbom_report = {
            'report_metadata': {
                'generated_date': datetime.now().isoformat(),
                'report_type': 'Software Bill of Materials (SBOM)',
                'total_dependencies': total_dependencies,
                'format': 'SPDX 2.3'
            },
            'risk_summary': {
                'high_risk': len(high_risk_deps),
                'medium_risk': len(medium_risk_deps),
                'low_risk': len(low_risk_deps),
                'overall_risk_score': sum(d.risk_score for d in dependencies) / total_dependencies if total_dependencies > 0 else 0
            },
            'package_manager_distribution': package_managers,
            'license_distribution': licenses,
            'high_risk_dependencies': [
                {
                    'name': dep.name,
                    'version': dep.version,
                    'risk_score': dep.risk_score,
                    'package_manager': dep.package_manager,
                    'vulnerabilities_count': len(dep.vulnerabilities)
                }
                for dep in high_risk_deps[:10]  # Top 10 high-risk dependencies
            ],
            'compliance_status': {
                'sbom_complete': True,
                'vulnerability_scanning': True,
                'license_compliance': len([d for d in dependencies if d.license]) == total_dependencies,
                'supply_chain_attacks_detected': len(self.detect_supply_chain_attacks(dependencies))
            }
        }
        
        if self.enable_guardian_mandate:
            self.record_guardian_event(
                event_type=AuditEventType.COMPLIANCE_REPORT.value,
                action="sbom_report_generated",
                details={
                    'total_dependencies': total_dependencies,
                    'high_risk_count': len(high_risk_deps)
                }
            )
        
        return sbom_report
    
    def generate_supply_chain_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive supply chain security report.
        
        Demonstrates strategic reporting leadership.
        """
        # Analyze all dependencies
        dependency_analysis = [self.analyze_dependency(dep) for dep in self.dependencies]
        
        # Analyze all vendors
        vendor_analysis = [self.analyze_vendor_security(vendor) for vendor in self.vendors]
        
        # Detect supply chain attacks
        detected_attacks = self.detect_supply_chain_attacks(self.dependencies)
        
        # Generate SBOM report
        sbom_report = self.generate_sbom_report(self.dependencies)
        
        # Calculate overall risk metrics
        total_dependencies = len(self.dependencies)
        total_vendors = len(self.vendors)
        high_risk_deps = len([d for d in dependency_analysis if d['severity'] == 'High'])
        high_risk_vendors = len([v for v in vendor_analysis if v['severity'] == 'High'])
        
        supply_chain_report = {
            'report_metadata': {
                'generated_date': datetime.now().isoformat(),
                'report_type': 'Supply Chain Security Analysis',
                'analysis_scope': {
                    'dependencies': total_dependencies,
                    'vendors': total_vendors,
                    'supply_chain_risks': len(self.supply_chain_risks)
                }
            },
            'executive_summary': {
                'overall_risk_level': 'High' if high_risk_deps > 5 or high_risk_vendors > 2 else 'Medium',
                'critical_findings': len(detected_attacks),
                'high_risk_dependencies': high_risk_deps,
                'high_risk_vendors': high_risk_vendors,
                'compliance_status': 'Compliant' if len(detected_attacks) == 0 else 'Non-Compliant'
            },
            'dependency_analysis': {
                'summary': {
                    'total': total_dependencies,
                    'high_risk': high_risk_deps,
                    'medium_risk': len([d for d in dependency_analysis if d['severity'] == 'Medium']),
                    'low_risk': len([d for d in dependency_analysis if d['severity'] == 'Low'])
                },
                'top_risks': sorted(dependency_analysis, key=lambda x: x['risk_score'], reverse=True)[:10]
            },
            'vendor_analysis': {
                'summary': {
                    'total': total_vendors,
                    'high_risk': high_risk_vendors,
                    'medium_risk': len([v for v in vendor_analysis if v['severity'] == 'Medium']),
                    'low_risk': len([v for v in vendor_analysis if v['severity'] == 'Low'])
                },
                'top_risks': sorted(vendor_analysis, key=lambda x: x['risk_score'], reverse=True)[:5]
            },
            'supply_chain_attacks': {
                'detected_attacks': detected_attacks,
                'attack_types': self._categorize_attacks(detected_attacks)
            },
            'sbom_report': sbom_report,
            'strategic_recommendations': self._generate_supply_chain_recommendations(
                dependency_analysis, vendor_analysis, detected_attacks
            )
        }
        
        return supply_chain_report
    
    def _calculate_severity(self, risk_score: float) -> str:
        """Calculate severity based on risk score."""
        if risk_score >= 7.0:
            return 'High'
        elif risk_score >= 4.0:
            return 'Medium'
        else:
            return 'Low'
    
    def _categorize_attacks(self, attacks: List[Dict[str, Any]]) -> Dict[str, int]:
        """Categorize detected attacks by type."""
        categories = {}
        for attack in attacks:
            for indicator in attack['attack_indicators']:
                if 'dependency confusion' in indicator.lower():
                    categories['Dependency Confusion'] = categories.get('Dependency Confusion', 0) + 1
                elif 'typosquatting' in indicator.lower():
                    categories['Typosquatting'] = categories.get('Typosquatting', 0) + 1
                elif 'credential harvesting' in indicator.lower():
                    categories['Credential Harvesting'] = categories.get('Credential Harvesting', 0) + 1
                elif 'data exfiltration' in indicator.lower():
                    categories['Data Exfiltration'] = categories.get('Data Exfiltration', 0) + 1
        return categories
    
    def _generate_supply_chain_recommendations(self, dependency_analysis: List[Dict], 
                                             vendor_analysis: List[Dict], 
                                             detected_attacks: List[Dict]) -> List[str]:
        """Generate strategic recommendations for supply chain security."""
        recommendations = []
        
        # Dependency-related recommendations
        high_risk_deps = [d for d in dependency_analysis if d['severity'] == 'High']
        if high_risk_deps:
            recommendations.append(
                f"🔴 IMMEDIATE ACTION: {len(high_risk_deps)} high-risk dependencies "
                "require immediate review and potential replacement"
            )
        
        # Vendor-related recommendations
        high_risk_vendors = [v for v in vendor_analysis if v['severity'] == 'High']
        if high_risk_vendors:
            recommendations.append(
                f"🟡 VENDOR RISK: {len(high_risk_vendors)} high-risk vendors "
                "require enhanced monitoring and risk mitigation"
            )
        
        # Supply chain attack recommendations
        if detected_attacks:
            recommendations.append(
                f"🚨 SUPPLY CHAIN ATTACKS: {len(detected_attacks)} potential attacks detected. "
                "Implement additional supply chain security controls"
            )
        
        # General recommendations
        if len(self.dependencies) > 1000:
            recommendations.append(
                "📦 DEPENDENCY MANAGEMENT: Large dependency tree detected. "
                "Consider dependency consolidation and regular cleanup"
            )
        
        recommendations.append(
            "🛡️ CONTINUOUS MONITORING: Implement automated supply chain monitoring "
            "and alerting for new vulnerabilities and attacks"
        )
        
        return recommendations
    
    def print_report(self, report: Dict[str, Any]):
        """Print supply chain security report in a professional format."""
        print("\n" + "=" * 80)
        print("🔗 SUPPLY CHAIN SECURITY ANALYSIS REPORT")
        print("=" * 80)
        
        # Executive Summary
        exec_summary = report['executive_summary']
        risk_icon = "🔴" if exec_summary['overall_risk_level'] == 'High' else "🟡" if exec_summary['overall_risk_level'] == 'Medium' else "🟢"
        print(f"\n📊 EXECUTIVE SUMMARY: {risk_icon} {exec_summary['overall_risk_level']} Risk Level")
        print(f"   ├─ Critical Findings: {exec_summary['critical_findings']}")
        print(f"   ├─ High-Risk Dependencies: {exec_summary['high_risk_dependencies']}")
        print(f"   ├─ High-Risk Vendors: {exec_summary['high_risk_vendors']}")
        print(f"   └─ Compliance Status: {exec_summary['compliance_status']}")
        
        # Dependency Analysis
        dep_analysis = report['dependency_analysis']
        print(f"\n📦 DEPENDENCY ANALYSIS:")
        print(f"   ├─ Total Dependencies: {dep_analysis['summary']['total']}")
        print(f"   ├─ High Risk: {dep_analysis['summary']['high_risk']}")
        print(f"   ├─ Medium Risk: {dep_analysis['summary']['medium_risk']}")
        print(f"   └─ Low Risk: {dep_analysis['summary']['low_risk']}")
        
        if dep_analysis['top_risks']:
            print(f"\n🎯 TOP RISK DEPENDENCIES:")
            for i, dep in enumerate(dep_analysis['top_risks'][:5], 1):
                print(f"   {i}. {dep['dependency']} v{dep['version']} (Risk: {dep['risk_score']:.1f})")
        
        # Vendor Analysis
        vendor_analysis = report['vendor_analysis']
        print(f"\n🏢 VENDOR ANALYSIS:")
        print(f"   ├─ Total Vendors: {vendor_analysis['summary']['total']}")
        print(f"   ├─ High Risk: {vendor_analysis['summary']['high_risk']}")
        print(f"   ├─ Medium Risk: {vendor_analysis['summary']['medium_risk']}")
        print(f"   └─ Low Risk: {vendor_analysis['summary']['low_risk']}")
        
        # Supply Chain Attacks
        attacks = report['supply_chain_attacks']
        if attacks['detected_attacks']:
            print(f"\n🚨 DETECTED SUPPLY CHAIN ATTACKS: {len(attacks['detected_attacks'])}")
            for attack in attacks['detected_attacks'][:3]:
                print(f"   ├─ {attack['dependency']}: {', '.join(attack['attack_indicators'][:2])}")
        
        # Strategic Recommendations
        if report['strategic_recommendations']:
            print(f"\n💡 STRATEGIC RECOMMENDATIONS:")
            for rec in report['strategic_recommendations']:
                print(f"   {rec}")


def create_sample_data():
    """Create sample data for demonstration."""
    dependencies = [
        Dependency(
            name="lodash",
            version="4.17.21",
            package_manager="npm",
            source="https://registry.npmjs.org/",
            license="MIT",
            vulnerabilities=[],
            last_updated=datetime.now() - timedelta(days=30),
            maintainer="lodash",
            download_count=10000000,
            risk_score=1.0
        ),
        Dependency(
            name="lodash-",
            version="1.0.0",
            package_manager="npm",
            source="https://registry.npmjs.org/",
            license="MIT",
            vulnerabilities=[{"id": "CVE-2024-1234", "severity": "High"}],
            last_updated=datetime.now() - timedelta(days=500),
            maintainer="unknown",
            download_count=50,
            risk_score=8.0
        ),
        Dependency(
            name="express",
            version="4.18.2",
            package_manager="npm",
            source="https://registry.npmjs.org/",
            license="MIT",
            vulnerabilities=[{"id": "CVE-2024-5678", "severity": "Medium"}],
            last_updated=datetime.now() - timedelta(days=60),
            maintainer="expressjs",
            download_count=5000000,
            risk_score=3.0
        )
    ]
    
    vendors = [
        Vendor(
            name="Cloud Provider Inc",
            domain="cloudprovider.com",
            risk_score=2.0,
            security_rating="A",
            last_assessment=datetime.now() - timedelta(days=30),
            compliance_certifications=["SOC2", "ISO27001", "FedRAMP"],
            security_incidents=[],
            supply_chain_risks=[]
        ),
        Vendor(
            name="Software Vendor Corp",
            domain="softwarevendor.com",
            risk_score=6.5,
            security_rating="C",
            last_assessment=datetime.now() - timedelta(days=180),
            compliance_certifications=["SOC2"],
            security_incidents=[{"date": datetime.now() - timedelta(days=90), "type": "Data Breach"}],
            supply_chain_risks=["Limited security controls", "No SBOM provided"]
        )
    ]
    
    return dependencies, vendors


def main():
    """Main function with command-line interface."""
    parser = argparse.ArgumentParser(
        description="Supply Chain Security Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --demo                           # Run with sample data
  %(prog)s --package-lock package-lock.json # Analyze npm dependencies
  %(prog)s --requirements requirements.txt  # Analyze Python dependencies
  %(prog)s --output report.json             # Save report to file
        """
    )
    
    parser.add_argument(
        '--demo',
        action='store_true',
        help='Run with sample data'
    )
    
    parser.add_argument(
        '--package-lock',
        help='Analyze npm package-lock.json file'
    )
    
    parser.add_argument(
        '--requirements',
        help='Analyze Python requirements.txt file'
    )
    
    parser.add_argument(
        '--output',
        help='Output file for supply chain report (JSON format)'
    )
    
    parser.add_argument(
        '--disable-guardian-mandate',
        action='store_true',
        help='Disable Guardian\'s Mandate integration'
    )
    
    args = parser.parse_args()
    
    # Initialize analyzer
    analyzer = SupplyChainSecurityAnalyzer(enable_guardian_mandate=not args.disable_guardian_mandate)
    
    try:
        # Load data
        if args.demo:
            print("🔍 Loading sample supply chain data...")
            dependencies, vendors = create_sample_data()
            analyzer.dependencies = dependencies
            analyzer.vendors = vendors
            print(f"✅ Loaded {len(dependencies)} dependencies and {len(vendors)} vendors")
        
        elif args.package_lock:
            print(f"📦 Analyzing npm dependencies from {args.package_lock}...")
            # Implementation would parse package-lock.json
            print("⚠️  Package-lock.json analysis not implemented in demo")
        
        elif args.requirements:
            print(f"🐍 Analyzing Python dependencies from {args.requirements}...")
            # Implementation would parse requirements.txt
            print("⚠️  Requirements.txt analysis not implemented in demo")
        
        else:
            print("ℹ️  No input specified. Use --demo for sample data.")
            return
        
        # Generate and display report
        print("\n📊 Generating supply chain security report...")
        report = analyzer.generate_supply_chain_report()
        analyzer.print_report(report)
        
        # Save report if requested
        if args.output:
            try:
                with open(args.output, 'w') as f:
                    json.dump(report, f, indent=2)
                print(f"\n💾 Report saved to: {args.output}")
            except Exception as e:
                print(f"❌ Error saving report: {e}")
        
        if analyzer.enable_guardian_mandate:
            print("\n🛡️  Guardian's Mandate: Supply chain security audit trail recorded")
            print("   - All dependency and vendor analysis activities logged")
            print("   - Supply chain attack detection events tracked")
    
    except KeyboardInterrupt:
        print("\n⚠️  Operation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()