#!/usr/bin/env python3
"""
Bidirectional Policy Engine: AI-Powered Policy Generation & Adaptation
with Real-Time Compliance Mapping

This module extends Compliance Ledger to create a closed feedback loop
between policy-as-code, evidence collection, and AI-powered policy generation.
"""

import json
import yaml
import logging
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import hashlib

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ComplianceFramework(Enum):
    """Supported compliance frameworks."""
    NIST_CSF = "NIST_CSF"
    SOC2 = "SOC2"
    PCI_DSS = "PCI_DSS"
    ISO_27001 = "ISO_27001"
    HIPAA = "HIPAA"
    GDPR = "GDPR"
    SOX = "SOX"


@dataclass
class ComplianceControl:
    """Represents a compliance control with mapping to frameworks."""
    control_id: str
    title: str
    description: str
    frameworks: List[ComplianceFramework]
    risk_level: str  # HIGH, MEDIUM, LOW
    category: str  # Access Control, Data Protection, etc.
    requirements: List[str]
    evidence_requirements: List[str]


@dataclass
class PolicyRecommendation:
    """AI-generated policy recommendation."""
    control_id: str
    confidence_score: float
    reasoning: str
    suggested_policy: Dict[str, Any]
    framework_mappings: List[ComplianceFramework]
    risk_assessment: str
    implementation_priority: str  # CRITICAL, HIGH, MEDIUM, LOW


class BidirectionalPolicyEngine:
    """
    AI-powered bidirectional policy engine that:
    1. Analyzes evidence to generate policies
    2. Maps policies to compliance frameworks
    3. Adapts policies based on real configurations
    4. Provides intelligent recommendations
    """
    
    def __init__(self):
        self.compliance_controls_db = self._load_compliance_controls()
        self.policy_templates = self._load_policy_templates()
        self.evidence_patterns = self._load_evidence_patterns()
        
    def _load_compliance_controls(self) -> Dict[str, ComplianceControl]:
        """Load compliance control database."""
        # This would typically come from a comprehensive compliance database
        controls = {
            "NIST_CSF_PR.AC-4": ComplianceControl(
                control_id="NIST_CSF_PR.AC-4",
                title="Access Control",
                description="Manage access to organizational systems and data",
                frameworks=[ComplianceFramework.NIST_CSF, ComplianceFramework.SOC2],
                risk_level="HIGH",
                category="Access Control",
                requirements=[
                    "Implement MFA for all user accounts",
                    "Regular access reviews",
                    "Principle of least privilege"
                ],
                evidence_requirements=[
                    "IAM user MFA status",
                    "Access key rotation",
                    "User permission reviews"
                ]
            ),
            "NIST_CSF_PR.DS-1": ComplianceControl(
                control_id="NIST_CSF_PR.DS-1",
                title="Data Protection",
                description="Protect data at rest and in transit",
                frameworks=[ComplianceFramework.NIST_CSF, ComplianceFramework.PCI_DSS],
                risk_level="HIGH",
                category="Data Protection",
                requirements=[
                    "Encrypt data at rest",
                    "Encrypt data in transit",
                    "Key management"
                ],
                evidence_requirements=[
                    "S3 bucket encryption status",
                    "SSL/TLS configuration",
                    "Encryption key policies"
                ]
            )
        }
        return controls
    
    def _load_policy_templates(self) -> Dict[str, Dict[str, Any]]:
        """Load policy templates for different resource types."""
        return {
            "s3_bucket": {
                "encryption": {
                    "template": {
                        "control_id": "{{control_id}}",
                        "description": "{{description}}",
                        "cloud_provider": "aws",
                        "resource_type": "s3_bucket",
                        "evidence_collection_method": {
                            "source_type": "aws_config_query",
                            "config_rule_name": "s3-bucket-server-side-encryption-enabled",
                            "compliance_status": "NON_COMPLIANT"
                        }
                    },
                    "variants": [
                        {"method": "advanced_query", "query": "SELECT ... WHERE resourceType = 'AWS::S3::Bucket' AND configuration.serverSideEncryptionConfiguration IS NULL"}
                    ]
                },
                "public_access": {
                    "template": {
                        "control_id": "{{control_id}}",
                        "description": "{{description}}",
                        "cloud_provider": "aws",
                        "resource_type": "s3_bucket",
                        "evidence_collection_method": {
                            "source_type": "aws_config_query",
                            "config_rule_name": "s3-bucket-public-read-prohibited"
                        }
                    }
                }
            },
            "iam_user": {
                "mfa": {
                    "template": {
                        "control_id": "{{control_id}}",
                        "description": "{{description}}",
                        "cloud_provider": "aws",
                        "resource_type": "iam_user",
                        "evidence_collection_method": {
                            "source_type": "api_call",
                            "service": "iam",
                            "api_call": "get_credential_report",
                            "parameters": {}
                        }
                    }
                },
                "access_keys": {
                    "template": {
                        "control_id": "{{control_id}}",
                        "description": "{{description}}",
                        "cloud_provider": "aws",
                        "resource_type": "iam_user",
                        "evidence_collection_method": {
                            "source_type": "api_call",
                            "service": "iam",
                            "api_call": "list_access_keys",
                            "parameters": {"UserName": "{{user_name}}"}
                        }
                    }
                }
            }
        }
    
    def _load_evidence_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Load patterns for analyzing evidence and generating insights."""
        return {
            "s3_encryption_violation": {
                "indicators": ["NON_COMPLIANT", "serverSideEncryptionConfiguration IS NULL"],
                "risk_score": 0.9,
                "recommended_actions": [
                    "Enable S3 bucket encryption",
                    "Configure default encryption",
                    "Review encryption policies"
                ],
                "compliance_impact": ["PCI_DSS_3.4", "SOC2_CC6.1", "NIST_CSF_PR.DS-1"]
            },
            "iam_mfa_violation": {
                "indicators": ["MFA_DEVICES = 0", "PASSWORD_ENABLED = true"],
                "risk_score": 0.8,
                "recommended_actions": [
                    "Enable MFA for all users",
                    "Disable console access for users without MFA",
                    "Implement MFA enforcement policy"
                ],
                "compliance_impact": ["NIST_CSF_PR.AC-4", "SOC2_CC6.1", "PCI_DSS_8.1"]
            }
        }
    
    def analyze_evidence_for_policy_generation(self, evidence_bundles: List[Dict[str, Any]]) -> List[PolicyRecommendation]:
        """
        Analyze collected evidence to generate policy recommendations.
        
        Args:
            evidence_bundles: List of evidence bundles from Compliance Ledger
            
        Returns:
            List of AI-generated policy recommendations
        """
        recommendations = []
        
        for evidence in evidence_bundles:
            # Analyze evidence patterns
            analysis = self._analyze_evidence_patterns(evidence)
            
            if analysis['violations_detected']:
                # Generate policy recommendations based on violations
                for violation in analysis['violations']:
                    recommendation = self._generate_policy_recommendation(
                        evidence, violation, analysis
                    )
                    recommendations.append(recommendation)
            
            # Check for missing controls
            missing_controls = self._identify_missing_controls(evidence)
            for control in missing_controls:
                recommendation = self._generate_missing_control_recommendation(
                    evidence, control
                )
                recommendations.append(recommendation)
        
        return recommendations
    
    def _analyze_evidence_patterns(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze evidence for compliance violations and patterns."""
        analysis = {
            'violations_detected': False,
            'violations': [],
            'risk_score': 0.0,
            'compliance_impact': []
        }
        
        evidence_data = evidence.get('evidence_data', {})
        resource_type = evidence.get('resource_type', '')
        
        # Check for S3 encryption violations
        if resource_type == 's3_bucket':
            if 'config_rule_name' in evidence_data:
                rule_name = evidence_data['config_rule_name']
                if 'encryption' in rule_name.lower():
                    evaluations = evidence_data.get('evaluations', [])
                    non_compliant = [e for e in evaluations if e.get('ComplianceType') == 'NON_COMPLIANT']
                    
                    if non_compliant:
                        analysis['violations_detected'] = True
                        analysis['violations'].append({
                            'type': 's3_encryption_violation',
                            'pattern': 's3_encryption_violation',
                            'resources': [e.get('EvaluationResultIdentifier', {}).get('EvaluationResultQualifier', {}).get('ResourceId') for e in non_compliant],
                            'severity': 'HIGH'
                        })
                        analysis['risk_score'] = 0.9
                        analysis['compliance_impact'] = ['PCI_DSS_3.4', 'SOC2_CC6.1', 'NIST_CSF_PR.DS-1']
        
        # Check for IAM MFA violations
        elif resource_type == 'iam_user':
            if 'raw_response' in evidence_data:
                # Analyze credential report for MFA violations
                # This is a simplified analysis - real implementation would parse the report
                analysis['violations_detected'] = True
                analysis['violations'].append({
                    'type': 'iam_mfa_violation',
                    'pattern': 'iam_mfa_violation',
                    'severity': 'HIGH'
                })
                analysis['risk_score'] = 0.8
                analysis['compliance_impact'] = ['NIST_CSF_PR.AC-4', 'SOC2_CC6.1', 'PCI_DSS_8.1']
        
        return analysis
    
    def _generate_policy_recommendation(self, evidence: Dict[str, Any], 
                                      violation: Dict[str, Any], 
                                      analysis: Dict[str, Any]) -> PolicyRecommendation:
        """Generate a policy recommendation based on evidence analysis."""
        
        resource_type = evidence.get('resource_type', '')
        violation_type = violation.get('type', '')
        
        # Get appropriate template
        template = self._get_policy_template(resource_type, violation_type)
        
        if template:
            # Generate control ID based on violation
            control_id = self._generate_control_id(violation_type, resource_type)
            
            # Get compliance control details
            control = self.compliance_controls_db.get(control_id)
            
            # Create policy recommendation
            recommendation = PolicyRecommendation(
                control_id=control_id,
                confidence_score=analysis.get('risk_score', 0.7),
                reasoning=f"Detected {violation_type} violation in {resource_type} resources. "
                         f"Risk score: {analysis.get('risk_score', 0.7)}",
                suggested_policy=template,
                framework_mappings=control.frameworks if control else [ComplianceFramework.NIST_CSF],
                risk_assessment=violation.get('severity', 'MEDIUM'),
                implementation_priority='HIGH' if analysis.get('risk_score', 0) > 0.8 else 'MEDIUM'
            )
            
            return recommendation
        
        return None
    
    def _get_policy_template(self, resource_type: str, violation_type: str) -> Optional[Dict[str, Any]]:
        """Get appropriate policy template based on resource type and violation."""
        if resource_type == 's3_bucket' and 'encryption' in violation_type:
            return self.policy_templates.get('s3_bucket', {}).get('encryption', {}).get('template')
        elif resource_type == 'iam_user' and 'mfa' in violation_type:
            return self.policy_templates.get('iam_user', {}).get('mfa', {}).get('template')
        
        return None
    
    def _generate_control_id(self, violation_type: str, resource_type: str) -> str:
        """Generate control ID based on violation type and resource."""
        if 'encryption' in violation_type:
            return "NIST_CSF_PR.DS-1"
        elif 'mfa' in violation_type:
            return "NIST_CSF_PR.AC-4"
        else:
            return f"CUSTOM_{resource_type.upper()}_{violation_type.upper()}"
    
    def _identify_missing_controls(self, evidence: Dict[str, Any]) -> List[str]:
        """Identify missing compliance controls based on evidence."""
        # This would analyze evidence against a comprehensive control framework
        # and identify gaps
        return []
    
    def _generate_missing_control_recommendation(self, evidence: Dict[str, Any], 
                                               control_id: str) -> PolicyRecommendation:
        """Generate recommendation for missing control."""
        # Implementation for missing control recommendations
        pass
    
    def map_policy_to_frameworks(self, policy: Dict[str, Any]) -> Dict[str, List[str]]:
        """
        Map a policy to relevant compliance frameworks.
        
        Args:
            policy: Policy definition
            
        Returns:
            Dictionary mapping frameworks to relevant controls
        """
        control_id = policy.get('control_id', '')
        control = self.compliance_controls_db.get(control_id)
        
        if control:
            return {
                framework.value: [control_id] for framework in control.frameworks
            }
        
        return {}
    
    def generate_compliance_report(self, evidence_bundles: List[Dict[str, Any]], 
                                 recommendations: List[PolicyRecommendation]) -> Dict[str, Any]:
        """
        Generate comprehensive compliance report with AI insights.
        
        Args:
            evidence_bundles: Collected evidence
            recommendations: AI-generated recommendations
            
        Returns:
            Comprehensive compliance report
        """
        report = {
            'report_metadata': {
                'generated_at': datetime.now(timezone.utc).isoformat(),
                'total_evidence_bundles': len(evidence_bundles),
                'total_recommendations': len(recommendations),
                'ai_analysis_version': '1.0.0'
            },
            'compliance_summary': {
                'frameworks_covered': [],
                'high_risk_violations': 0,
                'medium_risk_violations': 0,
                'low_risk_violations': 0,
                'overall_risk_score': 0.0
            },
            'evidence_analysis': [],
            'policy_recommendations': [],
            'framework_mappings': {},
            'risk_assessment': {}
        }
        
        # Analyze evidence
        for evidence in evidence_bundles:
            analysis = self._analyze_evidence_patterns(evidence)
            report['evidence_analysis'].append({
                'control_id': evidence.get('control_id'),
                'resource_type': evidence.get('resource_type'),
                'violations_detected': analysis['violations_detected'],
                'risk_score': analysis['risk_score'],
                'compliance_impact': analysis['compliance_impact']
            })
        
        # Process recommendations
        for rec in recommendations:
            report['policy_recommendations'].append({
                'control_id': rec.control_id,
                'confidence_score': rec.confidence_score,
                'reasoning': rec.reasoning,
                'risk_assessment': rec.risk_assessment,
                'implementation_priority': rec.implementation_priority,
                'framework_mappings': [f.value for f in rec.framework_mappings]
            })
        
        # Calculate overall risk score
        risk_scores = [analysis['risk_score'] for analysis in report['evidence_analysis']]
        report['compliance_summary']['overall_risk_score'] = sum(risk_scores) / len(risk_scores) if risk_scores else 0.0
        
        # Update total recommendations count
        report['compliance_summary']['total_recommendations'] = len(recommendations)
        
        return report
    
    def adapt_policies_based_on_evidence(self, existing_policies: List[Dict[str, Any]], 
                                        evidence_bundles: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Adapt existing policies based on evidence analysis.
        
        Args:
            existing_policies: Current policy definitions
            evidence_bundles: Collected evidence
            
        Returns:
            Adapted policy definitions
        """
        adapted_policies = existing_policies.copy()
        
        # Analyze evidence for policy adaptation opportunities
        for evidence in evidence_bundles:
            analysis = self._analyze_evidence_patterns(evidence)
            
            if analysis['violations_detected']:
                # Find corresponding policy and adapt it
                for policy in adapted_policies:
                    if policy.get('control_id') == evidence.get('control_id'):
                        adapted_policy = self._adapt_policy_based_on_violations(
                            policy, analysis['violations']
                        )
                        if adapted_policy:
                            # Replace the policy
                            idx = adapted_policies.index(policy)
                            adapted_policies[idx] = adapted_policy
        
        return adapted_policies
    
    def _adapt_policy_based_on_violations(self, policy: Dict[str, Any], 
                                        violations: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Adapt a policy based on detected violations."""
        adapted_policy = policy.copy()
        
        for violation in violations:
            violation_type = violation.get('type', '')
            
            # Adapt evidence collection method based on violation
            if violation_type == 's3_encryption_violation':
                # Add more specific query or additional checks
                collection_method = adapted_policy.get('evidence_collection_method', {})
                if collection_method.get('source_type') == 'aws_config_query':
                    # Add advanced query as backup
                    collection_method['advanced_query'] = """
                    SELECT
                        configurationItemId,
                        resourceId,
                        resourceName,
                        configuration.serverSideEncryptionConfiguration
                    WHERE
                        resourceType = 'AWS::S3::Bucket'
                        AND (
                            configuration.serverSideEncryptionConfiguration IS NULL
                            OR configuration.serverSideEncryptionConfiguration.rules[0].applyServerSideEncryptionByDefault.sseAlgorithm IS NULL
                        )
                    """
            
            elif violation_type == 'iam_mfa_violation':
                # Add additional IAM checks
                collection_method = adapted_policy.get('evidence_collection_method', {})
                if collection_method.get('source_type') == 'api_call':
                    # Add additional API calls for comprehensive MFA checking
                    adapted_policy['additional_checks'] = [
                        {
                            'service': 'iam',
                            'api_call': 'list_mfa_devices',
                            'parameters': {}
                        }
                    ]
        
        return adapted_policy


def main():
    """Demo the bidirectional policy engine."""
    print("🔄 Bidirectional Policy Engine Demo")
    print("=" * 50)
    
    # Initialize the engine
    engine = BidirectionalPolicyEngine()
    
    # Mock evidence bundles (simulating output from Compliance Ledger)
    mock_evidence = [
        {
            'control_id': 'NIST_CSF_PR.DS-1',
            'resource_type': 's3_bucket',
            'evidence_source': 'aws_config',
            'evidence_data': {
                'config_rule_name': 's3-bucket-server-side-encryption-enabled',
                'compliance_status': 'NON_COMPLIANT',
                'evaluations': [
                    {
                        'ComplianceType': 'NON_COMPLIANT',
                        'EvaluationResultIdentifier': {
                            'EvaluationResultQualifier': {
                                'ResourceId': 'arn:aws:s3:::example-bucket'
                            }
                        }
                    }
                ]
            }
        },
        {
            'control_id': 'NIST_CSF_PR.AC-4',
            'resource_type': 'iam_user',
            'evidence_source': 'direct_api',
            'evidence_data': {
                'raw_response': {
                    'Content': 'mock_credential_report_data'
                }
            }
        }
    ]
    
    # Analyze evidence and generate recommendations
    print("📊 Analyzing evidence for policy generation...")
    recommendations = engine.analyze_evidence_for_policy_generation(mock_evidence)
    
    print(f"✅ Generated {len(recommendations)} policy recommendations")
    
    for i, rec in enumerate(recommendations, 1):
        print(f"\n🔍 Recommendation {i}:")
        print(f"  Control ID: {rec.control_id}")
        print(f"  Confidence: {rec.confidence_score:.2f}")
        print(f"  Risk Level: {rec.risk_assessment}")
        print(f"  Priority: {rec.implementation_priority}")
        print(f"  Frameworks: {[f.value for f in rec.framework_mappings]}")
        print(f"  Reasoning: {rec.reasoning}")
    
    # Generate comprehensive compliance report
    print("\n📋 Generating compliance report...")
    report = engine.generate_compliance_report(mock_evidence, recommendations)
    
    print(f"✅ Compliance Report Generated:")
    print(f"  Overall Risk Score: {report['compliance_summary']['overall_risk_score']:.2f}")
    print(f"  Total Recommendations: {report['compliance_summary']['total_recommendations']}")
    
    # Save report
    timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    report_filename = f"bidirectional_compliance_report_{timestamp}.json"
    
    with open(report_filename, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    print(f"📄 Report saved: {report_filename}")
    
    print("\n" + "=" * 50)
    print("🎉 Bidirectional Policy Engine Demo Complete!")
    print("\nThis demonstrates how AI can:")
    print("• Analyze evidence to generate policies")
    print("• Map policies to compliance frameworks")
    print("• Adapt policies based on real violations")
    print("• Provide intelligent recommendations")


if __name__ == '__main__':
    main()