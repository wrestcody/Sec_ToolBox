#!/usr/bin/env python3
"""
Test script for Cloud Compliance Evidence Scraper

This script demonstrates the tool's functionality and validates the configuration
without requiring actual AWS credentials. It uses mock data to show the expected output.
"""

import json
import yaml
import sys
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Any

def load_controls_mapping(config_path: str) -> Dict[str, Any]:
    """Load and validate the controls mapping configuration."""
    try:
        with open(config_path, 'r') as file:
            config = yaml.safe_load(file)
        
        # Validate required sections
        required_sections = ['metadata', 'controls', 'evidence_methods']
        for section in required_sections:
            if section not in config:
                raise ValueError(f"Missing required section: {section}")
        
        print(f"✅ Configuration loaded successfully")
        print(f"   Version: {config['metadata']['version']}")
        print(f"   Controls: {len(config['controls'])}")
        print(f"   Evidence methods: {sum(len(methods) for methods in config['evidence_methods'].values())}")
        
        return config
    except Exception as e:
        print(f"❌ Error loading configuration: {e}")
        sys.exit(1)

def validate_controls(config: Dict[str, Any]) -> None:
    """Validate control definitions."""
    print("\n🔍 Validating control definitions...")
    
    required_fields = ['id', 'name', 'framework', 'type', 'checks']
    frameworks = set()
    control_types = set()
    
    for i, control in enumerate(config['controls']):
        # Check required fields
        for field in required_fields:
            if field not in control:
                print(f"❌ Control {i+1}: Missing required field '{field}'")
                continue
        
        frameworks.add(control['framework'])
        control_types.add(control['type'])
        
        # Validate checks exist in evidence methods
        for check in control.get('checks', []):
            found = False
            for service, methods in config['evidence_methods'].items():
                for method in methods:
                    if method['name'] == check:
                        found = True
                        break
                if found:
                    break
            
            if not found:
                print(f"⚠️  Control {control['id']}: Check '{check}' not found in evidence methods")
    
    print(f"✅ Found {len(frameworks)} frameworks: {', '.join(sorted(frameworks))}")
    print(f"✅ Found {len(control_types)} control types: {', '.join(sorted(control_types))}")

def generate_mock_evidence(config: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Generate mock evidence data for demonstration."""
    print("\n📊 Generating mock evidence...")
    
    mock_evidence = []
    
    for control in config['controls'][:3]:  # Limit to first 3 controls for demo
        evidence = {
            'control_id': control['id'],
            'control_name': control['name'],
            'framework': control['framework'],
            'category': control.get('category', 'Unknown'),
            'evidence_type': control['type'],
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'risk_level': control.get('risk_level', 'Medium'),
            'compliance_status': 'Compliant',
            'findings': [],
            'recommendations': [],
            'data': {}
        }
        
        # Generate mock data based on control type
        if control['type'] == 'iam':
            evidence['data'] = {
                'root_mfa_enabled': True,
                'root_mfa_status': 'Enabled',
                'password_policy': {
                    'MinimumPasswordLength': 12,
                    'RequireSymbols': True,
                    'RequireNumbers': True,
                    'RequireUppercaseCharacters': True,
                    'RequireLowercaseCharacters': True,
                    'ExpirePasswords': True,
                    'MaxPasswordAge': 90
                },
                'admin_users_count': 3,
                'admin_users': [
                    {'username': 'admin-user-1', 'policy': 'AdministratorAccess'},
                    {'username': 'admin-user-2', 'policy': 'AdministratorAccess'},
                    {'username': 'admin-user-3', 'policy': 'AdministratorAccess'}
                ]
            }
            evidence['findings'] = [
                "✅ Root account MFA is enabled",
                "✅ Minimum password length is 12+ characters",
                "✅ Password policy requires symbols",
                "✅ Password policy requires numbers",
                "✅ Password policy requires uppercase characters",
                "✅ Password policy requires lowercase characters",
                "✅ Password policy requires password expiration",
                "✅ Password expiration is set to 90 days",
                "⚠️ 3 users have AdministratorAccess policy"
            ]
            evidence['recommendations'] = [
                "Review and reduce the number of administrative users"
            ]
            evidence['compliance_status'] = 'Partially Compliant'
        elif control['type'] == 's3':
            evidence['data'] = {
                'total_buckets': 5,
                'encrypted_buckets': 4,
                'buckets': [
                    {'name': 'secure-bucket-1', 'encryption_enabled': True, 'encryption_algorithm': 'AES256'},
                    {'name': 'secure-bucket-2', 'encryption_enabled': True, 'encryption_algorithm': 'AES256'},
                    {'name': 'secure-bucket-3', 'encryption_enabled': True, 'encryption_algorithm': 'AES256'},
                    {'name': 'secure-bucket-4', 'encryption_enabled': True, 'encryption_algorithm': 'AES256'},
                    {'name': 'insecure-bucket-1', 'encryption_enabled': False, 'encryption_algorithm': 'None'}
                ],
                'versioning_status': {
                    'secure-bucket-1': 'Enabled',
                    'secure-bucket-2': 'Enabled',
                    'secure-bucket-3': 'Enabled',
                    'secure-bucket-4': 'Enabled',
                    'insecure-bucket-1': 'NotEnabled'
                }
            }
            evidence['findings'] = [
                "⚠️ 4/5 S3 buckets are encrypted",
                "❌ 1 buckets are not encrypted",
                "✅ All 5 S3 buckets have versioning enabled"
            ]
            evidence['recommendations'] = [
                "Enable encryption for 1 unencrypted S3 buckets"
            ]
            evidence['compliance_status'] = 'Partially Compliant'
        elif control['type'] == 'cloudtrail':
            evidence['data'] = {
                'total_trails': 2,
                'multi_region_trails': 1,
                'trails': [
                    {
                        'name': 'main-trail',
                        's3_bucket': 'cloudtrail-logs-bucket',
                        'log_file_validation_enabled': True,
                        'is_multi_region_trail': True,
                        'include_global_services': True
                    },
                    {
                        'name': 'regional-trail',
                        's3_bucket': 'regional-logs-bucket',
                        'log_file_validation_enabled': False,
                        'is_multi_region_trail': False,
                        'include_global_services': False
                    }
                ],
                'logging_status': {
                    'main-trail': {
                        'is_logging': True,
                        'latest_delivery_time': '2024-01-15T10:30:00Z',
                        'latest_notification_time': '2024-01-15T10:30:00Z'
                    },
                    'regional-trail': {
                        'is_logging': True,
                        'latest_delivery_time': '2024-01-15T10:25:00Z',
                        'latest_notification_time': '2024-01-15T10:25:00Z'
                    }
                }
            }
            evidence['findings'] = [
                "✅ 2 CloudTrail trail(s) configured",
                "✅ 1 multi-region trail(s) configured",
                "⚠️ 1 trail(s) have log file validation enabled",
                "✅ All 2 CloudTrail trail(s) are actively logging"
            ]
            evidence['recommendations'] = [
                "Enable log file validation for CloudTrail trails"
            ]
            evidence['compliance_status'] = 'Partially Compliant'
        elif control['type'] == 'rds':
            evidence['data'] = {
                'total_instances': 3,
                'encrypted_instances': 2,
                'instances': [
                    {
                        'identifier': 'prod-db-1',
                        'engine': 'mysql',
                        'storage_encrypted': True,
                        'kms_key_id': 'arn:aws:kms:us-east-1:123456789012:key/abcd1234-ef56-7890-abcd-ef1234567890',
                        'status': 'available'
                    },
                    {
                        'identifier': 'prod-db-2',
                        'engine': 'postgres',
                        'storage_encrypted': True,
                        'kms_key_id': 'arn:aws:kms:us-east-1:123456789012:key/abcd1234-ef56-7890-abcd-ef1234567890',
                        'status': 'available'
                    },
                    {
                        'identifier': 'dev-db-1',
                        'engine': 'mysql',
                        'storage_encrypted': False,
                        'kms_key_id': 'None',
                        'status': 'available'
                    }
                ]
            }
            evidence['findings'] = [
                "⚠️ 2/3 RDS instance(s) are encrypted",
                "❌ 1 instance(s) are not encrypted"
            ]
            evidence['recommendations'] = [
                "Enable encryption for 1 unencrypted RDS instance(s)"
            ]
            evidence['compliance_status'] = 'Partially Compliant'
        
        mock_evidence.append(evidence)
        print(f"   ✅ Generated mock evidence for {control['id']} - {control['name']}")
    
    return mock_evidence

def generate_mock_report(evidence: List[Dict[str, Any]], output_format: str = 'json') -> str:
    """Generate a mock report in the specified format."""
    print(f"\n📄 Generating {output_format.upper()} report...")
    
    if output_format == 'json':
        report = {
            'metadata': {
                'generated_at': datetime.now(timezone.utc).isoformat(),
                'region': 'us-east-1',
                'total_controls_checked': len(evidence),
                'note': 'This is mock data for demonstration purposes'
            },
            'evidence': evidence
        }
        return json.dumps(report, indent=2, default=str)
    
    elif output_format == 'markdown':
        report_lines = [
            "# Cloud Compliance Evidence Report (Mock Data)",
            "",
            f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "**AWS Region:** us-east-1",
            f"**Controls Checked:** {len(evidence)}",
            "**Note:** This is mock data for demonstration purposes",
            "",
            "## Summary",
            ""
        ]
        
        # Summary statistics
        frameworks = {}
        evidence_types = {}
        compliance_status = {}
        risk_levels = {}
        
        for ev in evidence:
            frameworks[ev['framework']] = frameworks.get(ev['framework'], 0) + 1
            evidence_types[ev['evidence_type']] = evidence_types.get(ev['evidence_type'], 0) + 1
            status = ev.get('compliance_status', 'Unknown')
            compliance_status[status] = compliance_status.get(status, 0) + 1
            risk_level = ev.get('risk_level', 'Unknown')
            risk_levels[risk_level] = risk_levels.get(risk_level, 0) + 1
        
        report_lines.extend([
            "### Frameworks Covered",
            ""
        ])
        for framework, count in frameworks.items():
            report_lines.append(f"- **{framework}:** {count} controls")
        
        report_lines.extend([
            "",
            "### Evidence Types Collected",
            ""
        ])
        for evidence_type, count in evidence_types.items():
            report_lines.append(f"- **{evidence_type}:** {count} controls")
        
        report_lines.extend([
            "",
            "### Compliance Status Summary",
            ""
        ])
        for status, count in compliance_status.items():
            status_icon = "✅" if status == "Compliant" else "⚠️" if status == "Partially Compliant" else "❌" if status == "Non-Compliant" else "❓"
            report_lines.append(f"- {status_icon} **{status}:** {count} controls")
        
        report_lines.extend([
            "",
            "### Risk Level Distribution",
            ""
        ])
        for risk_level, count in risk_levels.items():
            risk_icon = "🔴" if risk_level == "Critical" else "🟠" if risk_level == "High" else "🟡" if risk_level == "Medium" else "🟢" if risk_level == "Low" else "⚪"
            report_lines.append(f"- {risk_icon} **{risk_level}:** {count} controls")
        
        report_lines.extend([
            "",
            "## Detailed Evidence",
            ""
        ])
        
        for ev in evidence:
            # Determine status icon
            status = ev.get('compliance_status', 'Unknown')
            status_icon = "✅" if status == "Compliant" else "⚠️" if status == "Partially Compliant" else "❌" if status == "Non-Compliant" else "❓"
            
            # Determine risk icon
            risk_level = ev.get('risk_level', 'Unknown')
            risk_icon = "🔴" if risk_level == "Critical" else "🟠" if risk_level == "High" else "🟡" if risk_level == "Medium" else "🟢" if risk_level == "Low" else "⚪"
            
            report_lines.extend([
                f"### {ev['control_id']} - {ev['control_name']}",
                "",
                f"**Framework:** {ev.get('framework', 'Unknown')}",
                f"**Category:** {ev.get('category', 'Unknown')}",
                f"**Type:** {ev['evidence_type']}",
                f"**Risk Level:** {risk_icon} {risk_level}",
                f"**Compliance Status:** {status_icon} {status}",
                f"**Timestamp:** {ev['timestamp']}",
                ""
            ])
            
            # Add findings
            findings = ev.get('findings', [])
            if findings:
                report_lines.append("**Findings:**")
                for finding in findings:
                    report_lines.append(f"- {finding}")
                report_lines.append("")
            
            # Add recommendations
            recommendations = ev.get('recommendations', [])
            if recommendations:
                report_lines.append("**Recommendations:**")
                for recommendation in recommendations:
                    report_lines.append(f"- {recommendation}")
                report_lines.append("")
            
            # Add key data summary
            data = ev.get('data', {})
            if data:
                report_lines.append("**Data Summary:**")
                for key, value in data.items():
                    if isinstance(value, (dict, list)):
                        report_lines.append(f"- **{key}:** {len(value)} items")
                    else:
                        report_lines.append(f"- **{key}:** {value}")
                report_lines.append("")
            
            report_lines.append("---")
            report_lines.append("")
        
        return "\n".join(report_lines)
    
    elif output_format == 'csv':
        import csv
        from io import StringIO
        
        output = StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow([
            'Control ID', 'Control Name', 'Framework', 'Category', 'Evidence Type', 
            'Risk Level', 'Compliance Status', 'Timestamp', 'Findings', 'Recommendations'
        ])
        
        # Data rows
        for ev in evidence:
            # Extract findings
            findings = ev.get('findings', [])
            findings_text = '; '.join(findings) if findings else 'No findings'
            
            # Extract recommendations
            recommendations = ev.get('recommendations', [])
            recommendations_text = '; '.join(recommendations) if recommendations else 'No recommendations'
            
            writer.writerow([
                ev['control_id'],
                ev['control_name'],
                ev.get('framework', ''),
                ev.get('category', ''),
                ev['evidence_type'],
                ev.get('risk_level', ''),
                ev.get('compliance_status', ''),
                ev['timestamp'],
                findings_text,
                recommendations_text
            ])
        
        return output.getvalue()
    
    else:
        raise ValueError(f"Unsupported output format: {output_format}")

def main():
    """Main test function."""
    print("🧪 Cloud Compliance Evidence Scraper - Test Script")
    print("=" * 60)
    
    # Configuration file path
    config_path = "controls_mapping.yaml"
    
    if not Path(config_path).exists():
        print(f"❌ Configuration file not found: {config_path}")
        print("Please ensure controls_mapping.yaml exists in the current directory.")
        sys.exit(1)
    
    # Load and validate configuration
    config = load_controls_mapping(config_path)
    validate_controls(config)
    
    # Generate mock evidence
    mock_evidence = generate_mock_evidence(config)
    
    # Generate reports in different formats
    formats = ['json', 'markdown', 'csv']
    
    for fmt in formats:
        try:
            report = generate_mock_report(mock_evidence, fmt)
            
            # Save to file
            output_file = f"mock_report.{fmt}"
            with open(output_file, 'w') as f:
                f.write(report)
            
            print(f"   ✅ Saved {fmt.upper()} report to {output_file}")
            
            # Show sample for JSON
            if fmt == 'json':
                print("\n📋 Sample JSON Output:")
                print("-" * 40)
                print(json.dumps(json.loads(report)['metadata'], indent=2))
                print("... (full report saved to file)")
        
        except Exception as e:
            print(f"   ❌ Error generating {fmt.upper()} report: {e}")
    
    print("\n🎉 Test completed successfully!")
    print("\nNext steps:")
    print("1. Configure AWS credentials")
    print("2. Run: python compliance_scraper.py --config controls_mapping.yaml")
    print("3. Review the generated reports")
    print("4. Customize controls_mapping.yaml for your specific needs")

if __name__ == '__main__':
    main()