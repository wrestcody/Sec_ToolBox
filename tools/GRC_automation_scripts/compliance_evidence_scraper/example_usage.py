#!/usr/bin/env python3
"""
Example usage of Cloud Compliance Evidence Scraper

This script demonstrates how to use the ComplianceEvidenceScraper class
programmatically and integrate it into other tools or workflows.
"""

import sys
import json
from pathlib import Path
from datetime import datetime

# Add the current directory to the path so we can import the scraper
sys.path.append(str(Path(__file__).parent))

from compliance_scraper import ComplianceEvidenceScraper

def example_basic_usage():
    """Example of basic usage with default settings."""
    print("🔧 Example 1: Basic Usage")
    print("-" * 40)
    
    try:
        # Initialize the scraper
        scraper = ComplianceEvidenceScraper(
            config_path="controls_mapping.yaml",
            region="us-east-1"
        )
        
        # Collect evidence for all controls
        evidence = scraper.collect_evidence()
        
        if evidence:
            print(f"✅ Collected evidence for {len(evidence)} controls")
            
            # Generate a JSON report
            report = scraper.generate_report(output_format='json')
            print("📄 Generated JSON report")
            
            # Save to file
            with open('compliance_report.json', 'w') as f:
                f.write(report)
            print("💾 Saved report to compliance_report.json")
            
        else:
            print("⚠️  No evidence collected. Check your AWS credentials and permissions.")
            
    except Exception as e:
        print(f"❌ Error: {e}")

def example_framework_specific():
    """Example of collecting evidence for a specific compliance framework."""
    print("\n🔧 Example 2: Framework-Specific Collection")
    print("-" * 40)
    
    try:
        scraper = ComplianceEvidenceScraper(
            config_path="controls_mapping.yaml",
            region="us-east-1"
        )
        
        # Collect evidence for SOC 2 controls only
        evidence = scraper.collect_evidence(framework="SOC 2")
        
        if evidence:
            print(f"✅ Collected evidence for {len(evidence)} SOC 2 controls")
            
            # Generate a markdown report
            report = scraper.generate_report(
                output_format='markdown',
                output_file='soc2_compliance_report.md'
            )
            print("📄 Generated markdown report")
            
            # Print summary
            for ev in evidence:
                print(f"   - {ev['control_id']}: {ev['control_name']}")
                
        else:
            print("⚠️  No SOC 2 controls found or no evidence collected.")
            
    except Exception as e:
        print(f"❌ Error: {e}")

def example_specific_controls():
    """Example of collecting evidence for specific control IDs."""
    print("\n🔧 Example 3: Specific Control Collection")
    print("-" * 40)
    
    try:
        scraper = ComplianceEvidenceScraper(
            config_path="controls_mapping.yaml",
            region="us-east-1"
        )
        
        # Collect evidence for specific controls
        control_ids = ["CC6.1", "3.4.1"]  # SOC 2 and PCI DSS controls
        evidence = scraper.collect_evidence(control_ids=control_ids)
        
        if evidence:
            print(f"✅ Collected evidence for {len(evidence)} specific controls")
            
            # Generate a CSV report
            report = scraper.generate_report(
                output_format='csv',
                output_file='specific_controls_report.csv'
            )
            print("📄 Generated CSV report")
            
            # Show evidence summary
            for ev in evidence:
                status = "✅" if 'error' not in ev else "❌"
                print(f"   {status} {ev['control_id']} ({ev['framework']}): {ev['evidence_type']}")
                
        else:
            print("⚠️  No evidence collected for specified controls.")
            
    except Exception as e:
        print(f"❌ Error: {e}")

def example_custom_analysis():
    """Example of custom analysis of collected evidence."""
    print("\n🔧 Example 4: Custom Evidence Analysis")
    print("-" * 40)
    
    try:
        scraper = ComplianceEvidenceScraper(
            config_path="controls_mapping.yaml",
            region="us-east-1"
        )
        
        # Collect evidence for all controls
        evidence = scraper.collect_evidence()
        
        if evidence:
            print(f"📊 Analyzing evidence for {len(evidence)} controls")
            
            # Custom analysis
            frameworks = {}
            evidence_types = {}
            issues = []
            
            for ev in evidence:
                # Count by framework
                framework = ev.get('framework', 'Unknown')
                frameworks[framework] = frameworks.get(framework, 0) + 1
                
                # Count by evidence type
                evidence_type = ev.get('evidence_type', 'Unknown')
                evidence_types[evidence_type] = evidence_types.get(evidence_type, 0) + 1
                
                # Check for issues
                if 'error' in ev:
                    issues.append(f"{ev['control_id']}: {ev['error']}")
                
                # Check for specific compliance issues
                data = ev.get('data', {})
                if ev['evidence_type'] == 'iam':
                    if not data.get('root_mfa_enabled', False):
                        issues.append(f"{ev['control_id']}: Root MFA not enabled")
                
                elif ev['evidence_type'] == 's3':
                    total_buckets = data.get('total_buckets', 0)
                    encrypted_buckets = data.get('encrypted_buckets', 0)
                    if total_buckets > 0 and encrypted_buckets < total_buckets:
                        issues.append(f"{ev['control_id']}: {total_buckets - encrypted_buckets} buckets not encrypted")
                
                elif ev['evidence_type'] == 'cloudtrail':
                    total_trails = data.get('total_trails', 0)
                    multi_region_trails = data.get('multi_region_trails', 0)
                    if total_trails > 0 and multi_region_trails == 0:
                        issues.append(f"{ev['control_id']}: No multi-region CloudTrail configured")
            
            # Print analysis results
            print("\n📈 Framework Distribution:")
            for framework, count in frameworks.items():
                print(f"   - {framework}: {count} controls")
            
            print("\n🔍 Evidence Type Distribution:")
            for evidence_type, count in evidence_types.items():
                print(f"   - {evidence_type}: {count} controls")
            
            if issues:
                print("\n⚠️  Compliance Issues Found:")
                for issue in issues:
                    print(f"   - {issue}")
            else:
                print("\n✅ No compliance issues detected")
                
        else:
            print("⚠️  No evidence to analyze.")
            
    except Exception as e:
        print(f"❌ Error: {e}")

def example_integration_workflow():
    """Example of integrating the scraper into a larger workflow."""
    print("\n🔧 Example 5: Integration Workflow")
    print("-" * 40)
    
    try:
        # Simulate a compliance monitoring workflow
        print("🔄 Starting compliance monitoring workflow...")
        
        # Step 1: Initialize scraper
        scraper = ComplianceEvidenceScraper(
            config_path="controls_mapping.yaml",
            region="us-east-1"
        )
        
        # Step 2: Collect evidence
        print("📊 Collecting compliance evidence...")
        evidence = scraper.collect_evidence()
        
        if not evidence:
            print("❌ No evidence collected. Workflow failed.")
            return
        
        # Step 3: Analyze results
        print("🔍 Analyzing compliance status...")
        compliance_score = 0
        total_controls = len(evidence)
        passed_controls = 0
        
        for ev in evidence:
            if 'error' not in ev:
                passed_controls += 1
                # Add framework-specific scoring logic here
                if ev.get('framework') == 'SOC 2':
                    compliance_score += 10
                elif ev.get('framework') == 'PCI DSS':
                    compliance_score += 15
                else:
                    compliance_score += 5
        
        # Step 4: Generate reports
        print("📄 Generating compliance reports...")
        
        # JSON report for API consumption
        scraper.generate_report(
            output_format='json',
            output_file='compliance_api_report.json'
        )
        
        # Markdown report for stakeholders
        scraper.generate_report(
            output_format='markdown',
            output_file='compliance_stakeholder_report.md'
        )
        
        # Step 5: Calculate metrics
        pass_rate = (passed_controls / total_controls) * 100 if total_controls > 0 else 0
        
        print(f"\n📊 Compliance Metrics:")
        print(f"   - Total Controls: {total_controls}")
        print(f"   - Passed Controls: {passed_controls}")
        print(f"   - Pass Rate: {pass_rate:.1f}%")
        print(f"   - Compliance Score: {compliance_score}")
        
        # Step 6: Determine next steps
        if pass_rate >= 90:
            print("✅ High compliance level achieved")
            print("   Next: Schedule quarterly review")
        elif pass_rate >= 70:
            print("⚠️  Moderate compliance level")
            print("   Next: Address failed controls within 30 days")
        else:
            print("❌ Low compliance level")
            print("   Next: Immediate remediation required")
        
        print("\n🔄 Workflow completed successfully!")
        
    except Exception as e:
        print(f"❌ Workflow error: {e}")

def main():
    """Main function to run all examples."""
    print("🚀 Cloud Compliance Evidence Scraper - Usage Examples")
    print("=" * 60)
    
    # Check if configuration file exists
    if not Path("controls_mapping.yaml").exists():
        print("❌ Configuration file 'controls_mapping.yaml' not found.")
        print("Please ensure you're running this script from the correct directory.")
        return
    
    # Run examples
    try:
        example_basic_usage()
        example_framework_specific()
        example_specific_controls()
        example_custom_analysis()
        example_integration_workflow()
        
        print("\n🎉 All examples completed!")
        print("\n📚 Additional Resources:")
        print("   - README.md: Complete documentation")
        print("   - test_scraper.py: Test script with mock data")
        print("   - controls_mapping.yaml: Configuration examples")
        
    except KeyboardInterrupt:
        print("\n⏹️  Examples interrupted by user.")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")

if __name__ == '__main__':
    main()