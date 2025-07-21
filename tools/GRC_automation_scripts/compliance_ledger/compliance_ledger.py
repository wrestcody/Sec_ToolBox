#!/usr/bin/env python3
"""
Compliance Ledger: Policy-as-Code & Verifiable Evidence Collector
with AWS Config Integration

A robust, open-source Python CLI tool that automates the collection,
validation, and secure storage of GRC evidence from AWS environments.
Implements The Guardian's Mandate for unassailable digital evidence
integrity and unbreakable chain of custody.

Author: The Guardian's Forge
License: MIT
Version: 1.0.0
"""

import argparse
import boto3
import hashlib
import json
import logging
import os
import sys
import yaml
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from botocore.exceptions import ClientError, NoCredentialsError, BotoCoreError


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('compliance_ledger.log')
    ]
)
logger = logging.getLogger(__name__)

# Tool version for evidence bundles
TOOL_VERSION = "1.0.0"


class ComplianceLedgerError(Exception):
    """Custom exception for Compliance Ledger errors."""
    pass


def load_policies(filepath: str) -> List[Dict[str, Any]]:
    """
    Load compliance policies from YAML file.
    
    Args:
        filepath: Path to the YAML policy file
        
    Returns:
        List of policy definitions
        
    Raises:
        ComplianceLedgerError: If file cannot be loaded or parsed
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as file:
            policies = yaml.safe_load(file)
            
        if not isinstance(policies, list):
            raise ComplianceLedgerError("Policy file must contain a list of policies")
            
        # Validate each policy has required fields
        for i, policy in enumerate(policies):
            required_fields = ['control_id', 'description', 'cloud_provider', 
                             'resource_type', 'evidence_collection_method']
            missing_fields = [field for field in required_fields if field not in policy]
            
            if missing_fields:
                raise ComplianceLedgerError(
                    f"Policy {i} missing required fields: {missing_fields}"
                )
                
        logger.info(f"Successfully loaded {len(policies)} policies from {filepath}")
        return policies
        
    except FileNotFoundError:
        raise ComplianceLedgerError(f"Policy file not found: {filepath}")
    except yaml.YAMLError as e:
        raise ComplianceLedgerError(f"Invalid YAML in policy file: {e}")
    except Exception as e:
        raise ComplianceLedgerError(f"Error loading policies: {e}")


def compute_hash_and_timestamp(data: Any) -> Dict[str, str]:
    """
    Compute SHA-256 hash and UTC timestamp for evidence data.
    
    Args:
        data: The evidence data to hash
        
    Returns:
        Dictionary containing hash and timestamp
    """
    # Convert data to JSON string for consistent hashing
    data_json = json.dumps(data, sort_keys=True, default=str)
    
    # Compute SHA-256 hash
    hash_object = hashlib.sha256(data_json.encode('utf-8'))
    evidence_hash = hash_object.hexdigest()
    
    # Get UTC timestamp
    timestamp = datetime.now(timezone.utc).isoformat()
    
    return {
        'evidence_hash': evidence_hash,
        'collection_timestamp': timestamp
    }


def collect_aws_evidence(policy_definition: Dict[str, Any], 
                        aws_region: str, 
                        aws_profile: Optional[str] = None) -> Dict[str, Any]:
    """
    Collect evidence from AWS based on policy definition.
    Supports both direct API calls and AWS Config queries.
    
    Args:
        policy_definition: The policy definition containing collection method
        aws_region: AWS region to query
        aws_profile: AWS profile to use (optional)
        
    Returns:
        Evidence bundle with collected data, hash, and metadata
        
    Raises:
        ComplianceLedgerError: If evidence collection fails
    """
    try:
        # Initialize AWS session
        session_kwargs = {'region_name': aws_region}
        if aws_profile:
            session_kwargs['profile_name'] = aws_profile
            
        session = boto3.Session(**session_kwargs)
        
        collection_method = policy_definition['evidence_collection_method']
        source_type = collection_method.get('source_type')
        
        if source_type == 'api_call':
            return _collect_via_direct_api(session, policy_definition)
        elif source_type == 'aws_config_query':
            return _collect_via_aws_config(session, policy_definition)
        else:
            raise ComplianceLedgerError(
                f"Unsupported evidence collection method: {source_type}"
            )
            
    except NoCredentialsError:
        raise ComplianceLedgerError(
            "AWS credentials not found. Please configure AWS credentials."
        )
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'UnauthorizedOperation':
            raise ComplianceLedgerError(
                f"Insufficient permissions for {policy_definition['control_id']}"
            )
        else:
            raise ComplianceLedgerError(f"AWS API error: {e}")
    except Exception as e:
        raise ComplianceLedgerError(f"Error collecting evidence: {e}")


def _collect_via_direct_api(session: boto3.Session, 
                           policy_definition: Dict[str, Any]) -> Dict[str, Any]:
    """
    Collect evidence via direct AWS API calls.
    
    Args:
        session: AWS session
        policy_definition: Policy definition with API call details
        
    Returns:
        Evidence bundle
    """
    collection_method = policy_definition['evidence_collection_method']
    service_name = collection_method.get('service')
    api_call = collection_method.get('api_call')
    parameters = collection_method.get('parameters', {})
    
    if not service_name or not api_call:
        raise ComplianceLedgerError(
            "Direct API method requires 'service' and 'api_call' fields"
        )
    
    # Create service client
    client = session.client(service_name)
    
    # Execute API call
    method = getattr(client, api_call)
    response = method(**parameters)
    
    # Create evidence bundle
    evidence_data = {
        'raw_response': response,
        'api_details': {
            'service': service_name,
            'api_call': api_call,
            'parameters': parameters
        }
    }
    
    # Compute integrity data
    integrity_data = compute_hash_and_timestamp(evidence_data)
    
    return {
        'control_id': policy_definition['control_id'],
        'resource_type': policy_definition['resource_type'],
        'cloud_provider': policy_definition['cloud_provider'],
        'evidence_data': evidence_data,
        'evidence_source': 'direct_api',
        'collection_tool_version': TOOL_VERSION,
        **integrity_data
    }


def _collect_via_aws_config(session: boto3.Session, 
                           policy_definition: Dict[str, Any]) -> Dict[str, Any]:
    """
    Collect evidence via AWS Config queries or rule evaluations.
    
    Args:
        session: AWS session
        policy_definition: Policy definition with Config query details
        
    Returns:
        Evidence bundle
    """
    collection_method = policy_definition['evidence_collection_method']
    config_client = session.client('config')
    
    # Check if using Config Rule evaluation or Advanced Query
    if 'config_rule_name' in collection_method:
        return _collect_config_rule_evaluation(config_client, policy_definition)
    elif 'advanced_query' in collection_method:
        return _collect_config_advanced_query(config_client, policy_definition)
    else:
        raise ComplianceLedgerError(
            "AWS Config method requires either 'config_rule_name' or 'advanced_query'"
        )


def _collect_config_rule_evaluation(config_client, 
                                   policy_definition: Dict[str, Any]) -> Dict[str, Any]:
    """
    Collect evidence via AWS Config Rule evaluations.
    """
    collection_method = policy_definition['evidence_collection_method']
    rule_name = collection_method['config_rule_name']
    compliance_status = collection_method.get('compliance_status')
    
    # Get compliance details for the rule
    response = config_client.get_compliance_details_by_config_rule(
        ConfigRuleName=rule_name,
        ComplianceTypes=['NON_COMPLIANT', 'COMPLIANT'] if not compliance_status 
                       else [compliance_status]
    )
    
    evidence_data = {
        'config_rule_name': rule_name,
        'compliance_status': compliance_status,
        'evaluations': response.get('EvaluationResults', []),
        'next_token': response.get('NextToken')
    }
    
    # Compute integrity data
    integrity_data = compute_hash_and_timestamp(evidence_data)
    
    return {
        'control_id': policy_definition['control_id'],
        'resource_type': policy_definition['resource_type'],
        'cloud_provider': policy_definition['cloud_provider'],
        'evidence_data': evidence_data,
        'evidence_source': 'aws_config',
        'collection_tool_version': TOOL_VERSION,
        **integrity_data
    }


def _collect_config_advanced_query(config_client, 
                                  policy_definition: Dict[str, Any]) -> Dict[str, Any]:
    """
    Collect evidence via AWS Config Advanced Query (SQL-like).
    """
    collection_method = policy_definition['evidence_collection_method']
    query = collection_method['advanced_query']
    
    # Execute the advanced query
    response = config_client.select_resource_config(
        Expression=query
    )
    
    evidence_data = {
        'query': query,
        'results': response.get('Results', []),
        'query_info': response.get('QueryInfo', {}),
        'next_token': response.get('NextToken')
    }
    
    # Compute integrity data
    integrity_data = compute_hash_and_timestamp(evidence_data)
    
    return {
        'control_id': policy_definition['control_id'],
        'resource_type': policy_definition['resource_type'],
        'cloud_provider': policy_definition['cloud_provider'],
        'evidence_data': evidence_data,
        'evidence_source': 'aws_config',
        'collection_tool_version': TOOL_VERSION,
        **integrity_data
    }


def save_evidence_bundle_locally(evidence_bundle: Dict[str, Any]) -> str:
    """
    Save evidence bundle to local directory with integrity preservation.
    
    Args:
        evidence_bundle: The evidence bundle to save
        
    Returns:
        Path to the saved file
    """
    # Create evidence output directory
    output_dir = '_evidence_output'
    os.makedirs(output_dir, exist_ok=True)
    
    # Create filename with timestamp and control ID
    timestamp = evidence_bundle['collection_timestamp'].replace(':', '-').split('.')[0]
    control_id = evidence_bundle['control_id'].replace('/', '_')
    filename = f"{timestamp}_{control_id}_evidence.json"
    filepath = os.path.join(output_dir, filename)
    
    # Save evidence bundle
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(evidence_bundle, f, indent=2, default=str)
    
    logger.info(f"Evidence bundle saved: {filepath}")
    return filepath


def generate_report(all_evidence: List[Dict[str, Any]], 
                   output_format: str = 'json') -> str:
    """
    Generate compliance report from collected evidence.
    
    Args:
        all_evidence: List of all evidence bundles
        output_format: Report format ('json' or 'markdown')
        
    Returns:
        Path to the generated report
    """
    # Create reports directory
    reports_dir = 'reports'
    os.makedirs(reports_dir, exist_ok=True)
    
    # Generate timestamp for report
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    
    if output_format == 'json':
        return _generate_json_report(all_evidence, reports_dir, timestamp)
    elif output_format == 'markdown':
        return _generate_markdown_report(all_evidence, reports_dir, timestamp)
    else:
        raise ComplianceLedgerError(f"Unsupported output format: {output_format}")


def _generate_json_report(all_evidence: List[Dict[str, Any]], 
                         reports_dir: str, 
                         timestamp: str) -> str:
    """Generate JSON format report."""
    report_data = {
        'report_metadata': {
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'tool_version': TOOL_VERSION,
            'total_evidence_bundles': len(all_evidence),
            'evidence_sources': list(set(e['evidence_source'] for e in all_evidence))
        },
        'evidence_by_control': {}
    }
    
    # Group evidence by control ID
    for evidence in all_evidence:
        control_id = evidence['control_id']
        if control_id not in report_data['evidence_by_control']:
            report_data['evidence_by_control'][control_id] = []
        report_data['evidence_by_control'][control_id].append(evidence)
    
    # Save report
    filename = f"compliance_report_{timestamp}.json"
    filepath = os.path.join(reports_dir, filename)
    
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=2, default=str)
    
    logger.info(f"JSON report generated: {filepath}")
    return filepath


def _generate_markdown_report(all_evidence: List[Dict[str, Any]], 
                             reports_dir: str, 
                             timestamp: str) -> str:
    """Generate Markdown format report."""
    filename = f"compliance_report_{timestamp}.md"
    filepath = os.path.join(reports_dir, filename)
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write("# Compliance Ledger Report\n\n")
        f.write(f"**Generated:** {datetime.now(timezone.utc).isoformat()}\n")
        f.write(f"**Tool Version:** {TOOL_VERSION}\n")
        f.write(f"**Total Evidence Bundles:** {len(all_evidence)}\n\n")
        
        # Group by control ID
        evidence_by_control = {}
        for evidence in all_evidence:
            control_id = evidence['control_id']
            if control_id not in evidence_by_control:
                evidence_by_control[control_id] = []
            evidence_by_control[control_id].append(evidence)
        
        for control_id, evidence_list in evidence_by_control.items():
            f.write(f"## Control: {control_id}\n\n")
            f.write(f"**Evidence Count:** {len(evidence_list)}\n\n")
            
            for i, evidence in enumerate(evidence_list, 1):
                f.write(f"### Evidence Bundle {i}\n\n")
                f.write(f"- **Resource Type:** {evidence['resource_type']}\n")
                f.write(f"- **Cloud Provider:** {evidence['cloud_provider']}\n")
                f.write(f"- **Evidence Source:** {evidence['evidence_source']}\n")
                f.write(f"- **Collection Timestamp:** {evidence['collection_timestamp']}\n")
                f.write(f"- **Evidence Hash:** `{evidence['evidence_hash']}`\n\n")
                
                # Add evidence source specific details
                if evidence['evidence_source'] == 'aws_config':
                    if 'config_rule_name' in evidence['evidence_data']:
                        f.write(f"- **Config Rule:** {evidence['evidence_data']['config_rule_name']}\n")
                    if 'query' in evidence['evidence_data']:
                        f.write(f"- **Config Query:** `{evidence['evidence_data']['query']}`\n")
                elif evidence['evidence_source'] == 'direct_api':
                    api_details = evidence['evidence_data']['api_details']
                    f.write(f"- **Service:** {api_details['service']}\n")
                    f.write(f"- **API Call:** {api_details['api_call']}\n")
                
                f.write("\n---\n\n")
    
    logger.info(f"Markdown report generated: {filepath}")
    return filepath


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Compliance Ledger: Policy-as-Code & Verifiable Evidence Collector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --policy-file policies/example_aws_s3_encryption_config.yaml --region us-east-1
  %(prog)s --policy-file policies/example_aws_iam_mfa_api.yaml --region us-west-2 --profile production
  %(prog)s --policy-file policies/example_aws_s3_encryption_config.yaml --region us-east-1 --output-format markdown
        """
    )
    
    parser.add_argument(
        '--policy-file',
        required=True,
        help='Path to YAML policy file containing compliance controls'
    )
    
    parser.add_argument(
        '--region',
        required=True,
        help='AWS region to collect evidence from'
    )
    
    parser.add_argument(
        '--profile',
        help='AWS profile to use (optional)'
    )
    
    parser.add_argument(
        '--output-format',
        choices=['json', 'markdown'],
        default='json',
        help='Report output format (default: json)'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        logger.info("=== Compliance Ledger: Evidence Collection Started ===")
        logger.info(f"Policy file: {args.policy_file}")
        logger.info(f"AWS region: {args.region}")
        if args.profile:
            logger.info(f"AWS profile: {args.profile}")
        
        # Load policies
        policies = load_policies(args.policy_file)
        logger.info(f"Loaded {len(policies)} policies for processing")
        
        # Collect evidence for each policy
        all_evidence = []
        successful_collections = 0
        failed_collections = 0
        
        for i, policy in enumerate(policies, 1):
            logger.info(f"Processing policy {i}/{len(policies)}: {policy['control_id']}")
            
            try:
                evidence_bundle = collect_aws_evidence(
                    policy, args.region, args.profile
                )
                
                # Save evidence bundle locally
                save_evidence_bundle_locally(evidence_bundle)
                all_evidence.append(evidence_bundle)
                successful_collections += 1
                
                logger.info(f"✓ Successfully collected evidence for {policy['control_id']}")
                
            except Exception as e:
                failed_collections += 1
                logger.error(f"✗ Failed to collect evidence for {policy['control_id']}: {e}")
        
        # Generate report
        if all_evidence:
            report_path = generate_report(all_evidence, args.output_format)
            logger.info(f"Report generated: {report_path}")
        
        # Summary
        logger.info("=== Collection Summary ===")
        logger.info(f"Total policies processed: {len(policies)}")
        logger.info(f"Successful collections: {successful_collections}")
        logger.info(f"Failed collections: {failed_collections}")
        logger.info(f"Evidence bundles saved: {len(all_evidence)}")
        
        if failed_collections > 0:
            logger.warning(f"⚠️  {failed_collections} collection(s) failed. Check logs for details.")
        
        logger.info("=== Compliance Ledger: Evidence Collection Completed ===")
        
    except ComplianceLedgerError as e:
        logger.error(f"Compliance Ledger Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Collection interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()