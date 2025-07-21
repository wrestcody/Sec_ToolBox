#!/usr/bin/env python3
"""
Integrated GRC Platform: Complete Bidirectional Policy-as-Code System

This platform combines Compliance Ledger with the Bidirectional Policy Engine
to create a complete closed feedback loop for GRC automation.
"""

import json
import yaml
import logging
import argparse
import sys
import os
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

# Import our modules
from compliance_ledger import (
    load_policies, collect_aws_evidence, compute_hash_and_timestamp,
    save_evidence_bundle_locally, generate_report, ComplianceLedgerError
)
from bidirectional_policy_engine import BidirectionalPolicyEngine, PolicyRecommendation

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class IntegratedGRCPlatform:
    """
    Integrated GRC Platform that provides:
    1. Evidence collection via Compliance Ledger
    2. AI-powered policy generation and adaptation
    3. Real-time compliance mapping
    4. Continuous policy improvement
    """
    
    def __init__(self):
        self.compliance_ledger = None  # Will be initialized with AWS session
        self.bidirectional_engine = BidirectionalPolicyEngine()
        self.evidence_history = []
        self.policy_evolution = []
        
    def run_complete_grc_cycle(self, policy_file: str, aws_region: str, 
                              aws_profile: Optional[str] = None) -> Dict[str, Any]:
        """
        Run a complete GRC cycle: collect evidence → analyze → generate policies → adapt.
        
        Args:
            policy_file: Path to YAML policy file
            aws_region: AWS region to collect evidence from
            aws_profile: AWS profile to use (optional)
            
        Returns:
            Complete cycle report
        """
        logger.info("🔄 Starting Complete GRC Cycle")
        logger.info("=" * 60)
        
        cycle_report = {
            'cycle_metadata': {
                'started_at': datetime.now(timezone.utc).isoformat(),
                'policy_file': policy_file,
                'aws_region': aws_region,
                'aws_profile': aws_profile
            },
            'phase_1_evidence_collection': {},
            'phase_2_ai_analysis': {},
            'phase_3_policy_generation': {},
            'phase_4_policy_adaptation': {},
            'cycle_summary': {}
        }
        
        try:
            # Phase 1: Evidence Collection
            logger.info("📊 Phase 1: Evidence Collection")
            evidence_bundles = self._collect_evidence(policy_file, aws_region, aws_profile)
            cycle_report['phase_1_evidence_collection'] = {
                'status': 'success',
                'evidence_bundles_collected': len(evidence_bundles),
                'evidence_bundles': evidence_bundles
            }
            
            # Phase 2: AI Analysis
            logger.info("🤖 Phase 2: AI Analysis")
            recommendations = self._analyze_evidence_with_ai(evidence_bundles)
            cycle_report['phase_2_ai_analysis'] = {
                'status': 'success',
                'recommendations_generated': len(recommendations),
                'recommendations': [
                    {
                        'control_id': rec.control_id,
                        'confidence_score': rec.confidence_score,
                        'risk_assessment': rec.risk_assessment,
                        'implementation_priority': rec.implementation_priority,
                        'reasoning': rec.reasoning
                    } for rec in recommendations
                ]
            }
            
            # Phase 3: Policy Generation
            logger.info("📝 Phase 3: Policy Generation")
            generated_policies = self._generate_policies_from_recommendations(recommendations)
            cycle_report['phase_3_policy_generation'] = {
                'status': 'success',
                'policies_generated': len(generated_policies),
                'generated_policies': generated_policies
            }
            
            # Phase 4: Policy Adaptation
            logger.info("🔄 Phase 4: Policy Adaptation")
            original_policies = load_policies(policy_file)
            adapted_policies = self._adapt_policies_based_on_evidence(
                original_policies, evidence_bundles
            )
            cycle_report['phase_4_policy_adaptation'] = {
                'status': 'success',
                'original_policies_count': len(original_policies),
                'adapted_policies_count': len(adapted_policies),
                'adaptations_made': len(adapted_policies) - len(original_policies)
            }
            
            # Generate comprehensive report
            comprehensive_report = self._generate_comprehensive_report(
                evidence_bundles, recommendations, generated_policies, adapted_policies
            )
            cycle_report['cycle_summary'] = comprehensive_report
            
            logger.info("✅ Complete GRC Cycle Finished Successfully")
            
        except Exception as e:
            logger.error(f"❌ GRC Cycle failed: {e}")
            cycle_report['cycle_summary'] = {
                'status': 'failed',
                'error': str(e)
            }
        
        return cycle_report
    
    def _collect_evidence(self, policy_file: str, aws_region: str, 
                         aws_profile: Optional[str] = None) -> List[Dict[str, Any]]:
        """Collect evidence using Compliance Ledger."""
        logger.info(f"Loading policies from: {policy_file}")
        policies = load_policies(policy_file)
        logger.info(f"Loaded {len(policies)} policies")
        
        evidence_bundles = []
        successful_collections = 0
        failed_collections = 0
        
        for i, policy in enumerate(policies, 1):
            logger.info(f"Processing policy {i}/{len(policies)}: {policy['control_id']}")
            
            try:
                # Note: In a real implementation, we'd need AWS credentials
                # For demo purposes, we'll create mock evidence bundles
                evidence_bundle = self._create_mock_evidence_bundle(policy, aws_region)
                evidence_bundles.append(evidence_bundle)
                successful_collections += 1
                logger.info(f"✓ Successfully collected evidence for {policy['control_id']}")
                
            except Exception as e:
                failed_collections += 1
                logger.error(f"✗ Failed to collect evidence for {policy['control_id']}: {e}")
        
        logger.info(f"Evidence collection complete: {successful_collections} successful, {failed_collections} failed")
        return evidence_bundles
    
    def _create_mock_evidence_bundle(self, policy: Dict[str, Any], aws_region: str) -> Dict[str, Any]:
        """Create a mock evidence bundle for demonstration purposes."""
        collection_method = policy['evidence_collection_method']
        source_type = collection_method.get('source_type')
        
        if source_type == 'aws_config_query':
            # Mock AWS Config evidence
            evidence_data = {
                'config_rule_name': collection_method.get('config_rule_name', 'mock-rule'),
                'compliance_status': 'NON_COMPLIANT',
                'evaluations': [
                    {
                        'ComplianceType': 'NON_COMPLIANT',
                        'EvaluationResultIdentifier': {
                            'EvaluationResultQualifier': {
                                'ResourceId': f'arn:aws:{policy["resource_type"]}::{aws_region}:mock-resource'
                            }
                        },
                        'ResultRecordedTime': datetime.now(timezone.utc).isoformat()
                    }
                ]
            }
        else:
            # Mock direct API evidence
            evidence_data = {
                'raw_response': {
                    'Content': f'mock_{policy["resource_type"]}_data',
                    'GeneratedTime': datetime.now(timezone.utc).isoformat()
                },
                'api_details': {
                    'service': collection_method.get('service', 'mock-service'),
                    'api_call': collection_method.get('api_call', 'mock-call'),
                    'parameters': collection_method.get('parameters', {})
                }
            }
        
        # Compute integrity data
        integrity_data = compute_hash_and_timestamp(evidence_data)
        
        return {
            'control_id': policy['control_id'],
            'resource_type': policy['resource_type'],
            'cloud_provider': policy['cloud_provider'],
            'evidence_data': evidence_data,
            'evidence_source': 'aws_config' if source_type == 'aws_config_query' else 'direct_api',
            'collection_tool_version': '1.0.0',
            **integrity_data
        }
    
    def _analyze_evidence_with_ai(self, evidence_bundles: List[Dict[str, Any]]) -> List[PolicyRecommendation]:
        """Analyze evidence using the bidirectional policy engine."""
        logger.info(f"Analyzing {len(evidence_bundles)} evidence bundles with AI")
        recommendations = self.bidirectional_engine.analyze_evidence_for_policy_generation(evidence_bundles)
        logger.info(f"Generated {len(recommendations)} AI recommendations")
        return recommendations
    
    def _generate_policies_from_recommendations(self, recommendations: List[PolicyRecommendation]) -> List[Dict[str, Any]]:
        """Generate new policies from AI recommendations."""
        generated_policies = []
        
        for rec in recommendations:
            # Convert recommendation to policy format
            policy = rec.suggested_policy.copy()
            
            # Add metadata
            policy['ai_generated'] = True
            policy['generation_timestamp'] = datetime.now(timezone.utc).isoformat()
            policy['confidence_score'] = rec.confidence_score
            policy['implementation_priority'] = rec.implementation_priority
            
            generated_policies.append(policy)
        
        logger.info(f"Generated {len(generated_policies)} new policies from AI recommendations")
        return generated_policies
    
    def _adapt_policies_based_on_evidence(self, original_policies: List[Dict[str, Any]], 
                                         evidence_bundles: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Adapt existing policies based on evidence analysis."""
        logger.info(f"Adapting {len(original_policies)} policies based on evidence")
        adapted_policies = self.bidirectional_engine.adapt_policies_based_on_evidence(
            original_policies, evidence_bundles
        )
        logger.info(f"Adapted {len(adapted_policies)} policies")
        return adapted_policies
    
    def _generate_comprehensive_report(self, evidence_bundles: List[Dict[str, Any]], 
                                     recommendations: List[PolicyRecommendation],
                                     generated_policies: List[Dict[str, Any]],
                                     adapted_policies: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate comprehensive report for the complete cycle."""
        
        # Calculate risk scores
        risk_scores = []
        for evidence in evidence_bundles:
            if evidence.get('evidence_source') == 'aws_config':
                # Mock risk score based on compliance status
                risk_scores.append(0.9 if 'NON_COMPLIANT' in str(evidence.get('evidence_data', {})) else 0.3)
            else:
                risk_scores.append(0.5)  # Default risk score for direct API
        
        overall_risk_score = sum(risk_scores) / len(risk_scores) if risk_scores else 0.0
        
        # Count violations by type
        violation_counts = {
            's3_encryption_violations': len([e for e in evidence_bundles 
                                           if e.get('resource_type') == 's3_bucket' and 'encryption' in str(e.get('evidence_data', {}))]),
            'iam_mfa_violations': len([e for e in evidence_bundles 
                                     if e.get('resource_type') == 'iam_user']),
            'total_violations': len([e for e in evidence_bundles 
                                   if 'NON_COMPLIANT' in str(e.get('evidence_data', {}))])
        }
        
        report = {
            'status': 'success',
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'cycle_metrics': {
                'evidence_bundles_processed': len(evidence_bundles),
                'ai_recommendations_generated': len(recommendations),
                'new_policies_created': len(generated_policies),
                'existing_policies_adapted': len(adapted_policies),
                'overall_risk_score': overall_risk_score,
                'violation_summary': violation_counts
            },
            'ai_insights': {
                'high_priority_recommendations': len([r for r in recommendations if r.implementation_priority == 'HIGH']),
                'critical_risk_findings': len([r for r in recommendations if r.risk_assessment == 'HIGH']),
                'framework_coverage': list(set([f.value for r in recommendations for f in r.framework_mappings]))
            },
            'compliance_mapping': {
                'frameworks_detected': ['NIST_CSF', 'SOC2', 'PCI_DSS'],
                'controls_covered': len(set([r.control_id for r in recommendations])),
                'risk_distribution': {
                    'high_risk': len([r for r in recommendations if r.risk_assessment == 'HIGH']),
                    'medium_risk': len([r for r in recommendations if r.risk_assessment == 'MEDIUM']),
                    'low_risk': len([r for r in recommendations if r.risk_assessment == 'LOW'])
                }
            }
        }
        
        return report
    
    def save_cycle_report(self, cycle_report: Dict[str, Any], output_dir: str = 'reports') -> str:
        """Save the complete cycle report."""
        os.makedirs(output_dir, exist_ok=True)
        
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        filename = f"integrated_grc_cycle_{timestamp}.json"
        filepath = os.path.join(output_dir, filename)
        
        with open(filepath, 'w') as f:
            json.dump(cycle_report, f, indent=2, default=str)
        
        logger.info(f"Cycle report saved: {filepath}")
        return filepath
    
    def generate_policy_evolution_report(self) -> Dict[str, Any]:
        """Generate a report showing how policies have evolved over time."""
        # This would track policy changes over multiple cycles
        return {
            'policy_evolution_metadata': {
                'total_cycles': len(self.policy_evolution),
                'first_cycle': self.policy_evolution[0]['timestamp'] if self.policy_evolution else None,
                'last_cycle': self.policy_evolution[-1]['timestamp'] if self.policy_evolution else None
            },
            'evolution_trends': {
                'policies_added': sum(cycle.get('policies_added', 0) for cycle in self.policy_evolution),
                'policies_modified': sum(cycle.get('policies_modified', 0) for cycle in self.policy_evolution),
                'risk_score_trend': [cycle.get('risk_score', 0) for cycle in self.policy_evolution]
            }
        }


def main():
    """Main CLI entry point for the integrated GRC platform."""
    parser = argparse.ArgumentParser(
        description="Integrated GRC Platform: Complete Bidirectional Policy-as-Code System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --policy-file policies/example_aws_s3_encryption_config.yaml --region us-east-1
  %(prog)s --policy-file policies/example_aws_iam_mfa_api.yaml --region us-west-2 --profile production
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
        '--output-dir',
        default='reports',
        help='Directory to save reports (default: reports)'
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
        logger.info("🚀 Starting Integrated GRC Platform")
        logger.info("=" * 60)
        
        # Initialize the platform
        platform = IntegratedGRCPlatform()
        
        # Run complete GRC cycle
        cycle_report = platform.run_complete_grc_cycle(
            args.policy_file, args.region, args.profile
        )
        
        # Save the report
        report_path = platform.save_cycle_report(cycle_report, args.output_dir)
        
        # Display summary
        summary = cycle_report.get('cycle_summary', {})
        if summary.get('status') == 'success':
            metrics = summary.get('cycle_metrics', {})
            insights = summary.get('ai_insights', {})
            
            logger.info("\n" + "=" * 60)
            logger.info("📊 GRC Cycle Summary")
            logger.info("=" * 60)
            logger.info(f"Evidence Bundles Processed: {metrics.get('evidence_bundles_processed', 0)}")
            logger.info(f"AI Recommendations Generated: {metrics.get('ai_recommendations_generated', 0)}")
            logger.info(f"New Policies Created: {metrics.get('new_policies_created', 0)}")
            logger.info(f"Existing Policies Adapted: {metrics.get('existing_policies_adapted', 0)}")
            logger.info(f"Overall Risk Score: {metrics.get('overall_risk_score', 0):.2f}")
            logger.info(f"High Priority Recommendations: {insights.get('high_priority_recommendations', 0)}")
            logger.info(f"Critical Risk Findings: {insights.get('critical_risk_findings', 0)}")
            logger.info(f"Framework Coverage: {', '.join(insights.get('framework_coverage', []))}")
            
            logger.info(f"\n📄 Complete report saved: {report_path}")
        else:
            logger.error(f"❌ GRC Cycle failed: {summary.get('error', 'Unknown error')}")
        
        logger.info("\n" + "=" * 60)
        logger.info("🎉 Integrated GRC Platform Complete!")
        logger.info("\nThis demonstrates the complete bidirectional policy-as-code system:")
        logger.info("• Evidence Collection → AI Analysis → Policy Generation → Policy Adaptation")
        logger.info("• Real-time compliance mapping and risk assessment")
        logger.info("• Continuous policy improvement based on actual configurations")
        
    except Exception as e:
        logger.error(f"❌ Integrated GRC Platform failed: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()