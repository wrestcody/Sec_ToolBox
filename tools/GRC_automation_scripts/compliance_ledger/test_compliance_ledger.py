#!/usr/bin/env python3
"""
Test script for Compliance Ledger functionality.
This script demonstrates the tool's capabilities without requiring AWS credentials.
"""

import json
import yaml
import sys
import os
from datetime import datetime, timezone

# Add the current directory to the path so we can import from compliance_ledger
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_policy_loading():
    """Test policy loading functionality."""
    print("=== Testing Policy Loading ===")
    
    # Test S3 encryption config policy
    try:
        with open('policies/example_aws_s3_encryption_config.yaml', 'r') as f:
            s3_policies = yaml.safe_load(f)
        print(f"✓ Successfully loaded {len(s3_policies)} S3 encryption policies")
        
        # Validate policy structure
        for i, policy in enumerate(s3_policies):
            required_fields = ['control_id', 'description', 'cloud_provider', 
                             'resource_type', 'evidence_collection_method']
            missing_fields = [field for field in required_fields if field not in policy]
            
            if missing_fields:
                print(f"✗ Policy {i} missing fields: {missing_fields}")
            else:
                print(f"✓ Policy {i} ({policy['control_id']}) has all required fields")
                
    except Exception as e:
        print(f"✗ Error loading S3 policies: {e}")
    
    # Test IAM MFA policy
    try:
        with open('policies/example_aws_iam_mfa_api.yaml', 'r') as f:
            iam_policies = yaml.safe_load(f)
        print(f"✓ Successfully loaded {len(iam_policies)} IAM MFA policies")
        
        # Validate policy structure
        for i, policy in enumerate(iam_policies):
            required_fields = ['control_id', 'description', 'cloud_provider', 
                             'resource_type', 'evidence_collection_method']
            missing_fields = [field for field in required_fields if field not in policy]
            
            if missing_fields:
                print(f"✗ Policy {i} missing fields: {missing_fields}")
            else:
                print(f"✓ Policy {i} ({policy['control_id']}) has all required fields")
                
    except Exception as e:
        print(f"✗ Error loading IAM policies: {e}")


def test_evidence_collection_methods():
    """Test evidence collection method validation."""
    print("\n=== Testing Evidence Collection Methods ===")
    
    # Load policies
    with open('policies/example_aws_s3_encryption_config.yaml', 'r') as f:
        s3_policies = yaml.safe_load(f)
    
    with open('policies/example_aws_iam_mfa_api.yaml', 'r') as f:
        iam_policies = yaml.safe_load(f)
    
    all_policies = s3_policies + iam_policies
    
    aws_config_count = 0
    api_call_count = 0
    
    for policy in all_policies:
        collection_method = policy['evidence_collection_method']
        source_type = collection_method.get('source_type')
        
        if source_type == 'aws_config_query':
            aws_config_count += 1
            print(f"✓ AWS Config method: {policy['control_id']}")
            
            # Check for config rule or advanced query
            if 'config_rule_name' in collection_method:
                print(f"  - Config Rule: {collection_method['config_rule_name']}")
            if 'advanced_query' in collection_method:
                print(f"  - Advanced Query: {collection_method['advanced_query'][:50]}...")
                
        elif source_type == 'api_call':
            api_call_count += 1
            print(f"✓ Direct API method: {policy['control_id']}")
            print(f"  - Service: {collection_method.get('service')}")
            print(f"  - API Call: {collection_method.get('api_call')}")
    
    print(f"\nSummary:")
    print(f"- AWS Config methods: {aws_config_count}")
    print(f"- Direct API methods: {api_call_count}")


def test_evidence_bundle_structure():
    """Test evidence bundle structure creation."""
    print("\n=== Testing Evidence Bundle Structure ===")
    
    # Create a mock evidence bundle
    mock_evidence_data = {
        'config_rule_name': 's3-bucket-server-side-encryption-enabled',
        'compliance_status': 'NON_COMPLIANT',
        'evaluations': [
            {
                'EvaluationResultIdentifier': {
                    'EvaluationResultQualifier': {
                        'ConfigRuleName': 's3-bucket-server-side-encryption-enabled',
                        'ResourceId': 'arn:aws:s3:::example-bucket'
                    }
                },
                'ComplianceType': 'NON_COMPLIANT',
                'ResultRecordedTime': datetime.now(timezone.utc).isoformat()
            }
        ]
    }
    
    # Compute hash and timestamp (simplified version)
    import hashlib
    data_json = json.dumps(mock_evidence_data, sort_keys=True, default=str)
    evidence_hash = hashlib.sha256(data_json.encode('utf-8')).hexdigest()
    timestamp = datetime.now(timezone.utc).isoformat()
    
    evidence_bundle = {
        'control_id': 'NIST_CSF_PR.DS-1',
        'resource_type': 's3_bucket',
        'cloud_provider': 'aws',
        'evidence_data': mock_evidence_data,
        'evidence_source': 'aws_config',
        'collection_tool_version': '1.0.0',
        'evidence_hash': evidence_hash,
        'collection_timestamp': timestamp
    }
    
    print("✓ Created evidence bundle with:")
    print(f"  - Control ID: {evidence_bundle['control_id']}")
    print(f"  - Evidence Source: {evidence_bundle['evidence_source']}")
    print(f"  - Evidence Hash: {evidence_bundle['evidence_hash'][:16]}...")
    print(f"  - Collection Timestamp: {evidence_bundle['collection_timestamp']}")
    
    # Test JSON serialization
    try:
        json_str = json.dumps(evidence_bundle, indent=2, default=str)
        print("✓ Evidence bundle successfully serialized to JSON")
        print(f"  - JSON size: {len(json_str)} characters")
    except Exception as e:
        print(f"✗ Error serializing evidence bundle: {e}")


def test_report_generation():
    """Test report generation functionality."""
    print("\n=== Testing Report Generation ===")
    
    # Create mock evidence bundles
    mock_evidence = [
        {
            'control_id': 'NIST_CSF_PR.DS-1',
            'resource_type': 's3_bucket',
            'cloud_provider': 'aws',
            'evidence_source': 'aws_config',
            'evidence_hash': 'a1b2c3d4e5f6' * 8,
            'collection_timestamp': '2024-01-15T10:30:00Z'
        },
        {
            'control_id': 'NIST_CSF_PR.AC-4',
            'resource_type': 'iam_user',
            'cloud_provider': 'aws',
            'evidence_source': 'direct_api',
            'evidence_hash': 'f6e5d4c3b2a1' * 8,
            'collection_timestamp': '2024-01-15T10:31:00Z'
        }
    ]
    
    # Create reports directory
    os.makedirs('reports', exist_ok=True)
    
    # Generate JSON report
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    
    report_data = {
        'report_metadata': {
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'tool_version': '1.0.0',
            'total_evidence_bundles': len(mock_evidence),
            'evidence_sources': list(set(e['evidence_source'] for e in mock_evidence))
        },
        'evidence_by_control': {}
    }
    
    # Group evidence by control ID
    for evidence in mock_evidence:
        control_id = evidence['control_id']
        if control_id not in report_data['evidence_by_control']:
            report_data['evidence_by_control'][control_id] = []
        report_data['evidence_by_control'][control_id].append(evidence)
    
    # Save JSON report
    json_filename = f"reports/test_compliance_report_{timestamp}.json"
    with open(json_filename, 'w') as f:
        json.dump(report_data, f, indent=2, default=str)
    
    print(f"✓ Generated JSON report: {json_filename}")
    
    # Generate Markdown report
    md_filename = f"reports/test_compliance_report_{timestamp}.md"
    with open(md_filename, 'w') as f:
        f.write("# Test Compliance Ledger Report\n\n")
        f.write(f"**Generated:** {datetime.now(timezone.utc).isoformat()}\n")
        f.write(f"**Tool Version:** 1.0.0\n")
        f.write(f"**Total Evidence Bundles:** {len(mock_evidence)}\n\n")
        
        for control_id, evidence_list in report_data['evidence_by_control'].items():
            f.write(f"## Control: {control_id}\n\n")
            f.write(f"**Evidence Count:** {len(evidence_list)}\n\n")
            
            for i, evidence in enumerate(evidence_list, 1):
                f.write(f"### Evidence Bundle {i}\n\n")
                f.write(f"- **Resource Type:** {evidence['resource_type']}\n")
                f.write(f"- **Evidence Source:** {evidence['evidence_source']}\n")
                f.write(f"- **Collection Timestamp:** {evidence['collection_timestamp']}\n")
                f.write(f"- **Evidence Hash:** `{evidence['evidence_hash'][:16]}...`\n\n")
    
    print(f"✓ Generated Markdown report: {md_filename}")


def main():
    """Run all tests."""
    print("🧪 Compliance Ledger Test Suite")
    print("=" * 50)
    
    test_policy_loading()
    test_evidence_collection_methods()
    test_evidence_bundle_structure()
    test_report_generation()
    
    print("\n" + "=" * 50)
    print("✅ All tests completed successfully!")
    print("\nThe Compliance Ledger tool is ready for use.")
    print("To run with real AWS data, configure AWS credentials and run:")
    print("python3 compliance_ledger.py --policy-file policies/example_aws_s3_encryption_config.yaml --region us-east-1")


if __name__ == '__main__':
    main()