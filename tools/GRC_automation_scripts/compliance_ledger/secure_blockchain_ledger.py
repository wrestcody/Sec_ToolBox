#!/usr/bin/env python3
"""
Secure Blockchain Ledger: Zero-Knowledge Compliance Evidence Storage

This module implements a secure blockchain integration that ensures:
1. NO sensitive data is ever published to the blockchain
2. Cryptographic proof of evidence integrity and chain of custody
3. Zero-knowledge proofs for compliance verification
4. Immutable audit trail without data exposure
"""

import json
import hashlib
import hmac
import secrets
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import base64


class EvidenceType(Enum):
    """Types of evidence that can be stored."""
    CONFIGURATION = "configuration"
    ACCESS_LOG = "access_log"
    SECURITY_SCAN = "security_scan"
    COMPLIANCE_CHECK = "compliance_check"
    POLICY_VIOLATION = "policy_violation"


@dataclass
class SecureEvidenceBundle:
    """Secure evidence bundle with zero-knowledge properties."""
    evidence_id: str
    evidence_type: EvidenceType
    timestamp: str
    hash_tree_root: str  # Merkle tree root of evidence
    zero_knowledge_proof: str  # ZK proof of evidence integrity
    compliance_framework: str
    risk_score: float
    metadata_hash: str  # Hash of non-sensitive metadata
    signature: str  # Digital signature for authenticity


@dataclass
class BlockchainEntry:
    """What actually gets published to the blockchain (NO sensitive data)."""
    entry_id: str
    timestamp: str
    evidence_hash: str  # Hash of the evidence bundle
    compliance_framework: str
    risk_level: str  # HIGH, MEDIUM, LOW
    evidence_type: str
    metadata_hash: str
    zero_knowledge_proof: str
    signature: str
    previous_entry_hash: str  # Chain integrity


class SecureBlockchainLedger:
    """
    Secure blockchain ledger that ensures NO sensitive data is ever exposed.
    
    Key Security Principles:
    1. Only cryptographic hashes and proofs are published
    2. Zero-knowledge proofs verify compliance without revealing data
    3. Merkle trees enable efficient verification
    4. Digital signatures ensure authenticity
    5. Chain of custody is maintained cryptographically
    """
    
    def __init__(self):
        self.private_key = self._generate_private_key()
        self.public_key = self._derive_public_key(self.private_key)
        self.ledger_entries = []
        self.evidence_store = {}  # Local secure storage (not on blockchain)
        
    def _generate_private_key(self) -> bytes:
        """Generate a secure private key."""
        return secrets.token_bytes(32)
    
    def _derive_public_key(self, private_key: bytes) -> bytes:
        """Derive public key from private key."""
        # In production, use proper cryptographic key derivation
        return hashlib.sha256(private_key).digest()
    
    def _create_merkle_tree(self, evidence_data: Dict[str, Any]) -> Tuple[str, List[str]]:
        """Create a Merkle tree from evidence data."""
        # Convert evidence to sorted list of key-value pairs
        evidence_items = []
        for key, value in sorted(evidence_data.items()):
            if key not in ['pii_data', 'sensitive_config', 'credentials', 'raw_response']:
                # Only include non-sensitive data in Merkle tree
                evidence_items.append(f"{key}:{value}")
        
        # Create leaf hashes
        leaf_hashes = [hashlib.sha256(item.encode()).hexdigest() for item in evidence_items]
        
        # Build Merkle tree
        while len(leaf_hashes) > 1:
            if len(leaf_hashes) % 2 == 1:
                leaf_hashes.append(leaf_hashes[-1])  # Duplicate last element if odd
            
            new_level = []
            for i in range(0, len(leaf_hashes), 2):
                combined = leaf_hashes[i] + leaf_hashes[i + 1]
                new_level.append(hashlib.sha256(combined.encode()).hexdigest())
            leaf_hashes = new_level
        
        return leaf_hashes[0], leaf_hashes  # Root and all hashes
    
    def _create_zero_knowledge_proof(self, evidence_data: Dict[str, Any], 
                                   compliance_requirements: List[str]) -> str:
        """
        Create a zero-knowledge proof that evidence meets compliance requirements
        without revealing the actual evidence data.
        """
        # This is a simplified ZK proof - in production, use proper ZK protocols
        
        # Create proof components
        proof_components = []
        
        # 1. Prove evidence exists without revealing content
        evidence_hash = hashlib.sha256(json.dumps(evidence_data, sort_keys=True).encode()).hexdigest()
        proof_components.append(f"evidence_exists:{evidence_hash}")
        
        # 2. Prove compliance without revealing specific values
        for requirement in compliance_requirements:
            # Create a commitment to compliance status
            if self._check_compliance_requirement(evidence_data, requirement):
                commitment = hashlib.sha256(f"compliant:{requirement}".encode()).hexdigest()
            else:
                commitment = hashlib.sha256(f"non_compliant:{requirement}".encode()).hexdigest()
            proof_components.append(f"compliance_commitment:{commitment}")
        
        # 3. Prove risk assessment without revealing details
        risk_score = self._calculate_risk_score(evidence_data)
        risk_commitment = hashlib.sha256(f"risk_score:{risk_score}".encode()).hexdigest()
        proof_components.append(f"risk_commitment:{risk_commitment}")
        
        # Combine all proof components
        combined_proof = "|".join(proof_components)
        return hashlib.sha256(combined_proof.encode()).hexdigest()
    
    def _check_compliance_requirement(self, evidence_data: Dict[str, Any], 
                                    requirement: str) -> bool:
        """Check if evidence meets a specific compliance requirement."""
        # Simplified compliance checking
        if "encryption" in requirement.lower():
            return "encryption_enabled" in evidence_data and evidence_data["encryption_enabled"]
        elif "mfa" in requirement.lower():
            return "mfa_enabled" in evidence_data and evidence_data["mfa_enabled"]
        elif "access_control" in requirement.lower():
            return "access_controlled" in evidence_data and evidence_data["access_controlled"]
        return True
    
    def _calculate_risk_score(self, evidence_data: Dict[str, Any]) -> float:
        """Calculate risk score from evidence data."""
        risk_score = 0.0
        
        # Check for high-risk indicators
        if evidence_data.get("encryption_enabled", False) == False:
            risk_score += 0.4
        if evidence_data.get("mfa_enabled", False) == False:
            risk_score += 0.3
        if evidence_data.get("public_access", False) == True:
            risk_score += 0.3
        
        return min(risk_score, 1.0)
    
    def _sign_data(self, data: str) -> str:
        """Sign data with private key."""
        signature = hmac.new(self.private_key, data.encode(), hashlib.sha256).hexdigest()
        return signature
    
    def _sanitize_evidence_data(self, evidence_data: Dict[str, Any]) -> Dict[str, Any]:
        """Remove sensitive data from evidence before any processing."""
        sensitive_keys = [
            'pii_data', 'sensitive_config', 'credentials', 'raw_response',
            'api_keys', 'passwords', 'tokens', 'private_keys', 'secret_data',
            'user_data', 'customer_data', 'financial_data', 'health_data'
        ]
        
        sanitized = evidence_data.copy()
        for key in sensitive_keys:
            if key in sanitized:
                # Replace sensitive data with hash
                sanitized[key] = f"HASHED_{hashlib.sha256(str(sanitized[key]).encode()).hexdigest()[:16]}"
        
        return sanitized
    
    def store_evidence_securely(self, evidence_data: Dict[str, Any], 
                              evidence_type: EvidenceType,
                              compliance_framework: str) -> SecureEvidenceBundle:
        """
        Store evidence securely with zero-knowledge properties.
        
        Args:
            evidence_data: Raw evidence data (may contain sensitive info)
            evidence_type: Type of evidence
            compliance_framework: Compliance framework (NIST, SOC2, etc.)
            
        Returns:
            SecureEvidenceBundle with cryptographic proofs
        """
        # 1. Sanitize evidence data
        sanitized_data = self._sanitize_evidence_data(evidence_data)
        
        # 2. Create Merkle tree for integrity
        merkle_root, merkle_tree = self._create_merkle_tree(sanitized_data)
        
        # 3. Create zero-knowledge proof
        compliance_requirements = self._get_compliance_requirements(compliance_framework)
        zk_proof = self._create_zero_knowledge_proof(sanitized_data, compliance_requirements)
        
        # 4. Calculate risk score
        risk_score = self._calculate_risk_score(sanitized_data)
        
        # 5. Create evidence bundle
        evidence_id = hashlib.sha256(f"{merkle_root}{datetime.now(timezone.utc).isoformat()}".encode()).hexdigest()
        
        bundle = SecureEvidenceBundle(
            evidence_id=evidence_id,
            evidence_type=evidence_type,
            timestamp=datetime.now(timezone.utc).isoformat(),
            hash_tree_root=merkle_root,
            zero_knowledge_proof=zk_proof,
            compliance_framework=compliance_framework,
            risk_score=risk_score,
            metadata_hash=hashlib.sha256(json.dumps(sanitized_data, sort_keys=True).encode()).hexdigest(),
            signature=""
        )
        
        # 6. Sign the bundle
        bundle_data = f"{bundle.evidence_id}{bundle.timestamp}{bundle.hash_tree_root}"
        bundle.signature = self._sign_data(bundle_data)
        
        # 7. Store evidence locally (NOT on blockchain)
        self.evidence_store[evidence_id] = {
            'raw_evidence': evidence_data,  # Original data with sensitive info
            'sanitized_evidence': sanitized_data,  # Sanitized version
            'merkle_tree': merkle_tree,
            'bundle': bundle
        }
        
        return bundle
    
    def _get_compliance_requirements(self, framework: str) -> List[str]:
        """Get compliance requirements for a framework."""
        requirements = {
            'NIST_CSF': ['encryption_required', 'access_control_required', 'mfa_required'],
            'SOC2': ['data_protection_required', 'access_control_required', 'monitoring_required'],
            'PCI_DSS': ['encryption_required', 'access_control_required', 'audit_required'],
            'HIPAA': ['data_protection_required', 'access_control_required', 'privacy_required']
        }
        return requirements.get(framework, ['basic_security_required'])
    
    def publish_to_blockchain(self, evidence_bundle: SecureEvidenceBundle) -> BlockchainEntry:
        """
        Publish evidence to blockchain (ONLY cryptographic proofs, NO sensitive data).
        
        Args:
            evidence_bundle: Secure evidence bundle
            
        Returns:
            BlockchainEntry that gets published to blockchain
        """
        # Create blockchain entry with NO sensitive data
        entry_id = hashlib.sha256(f"{evidence_bundle.evidence_id}{datetime.now(timezone.utc).isoformat()}".encode()).hexdigest()
        
        # Determine risk level
        if evidence_bundle.risk_score >= 0.7:
            risk_level = "HIGH"
        elif evidence_bundle.risk_score >= 0.4:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        # Get previous entry hash for chain integrity
        previous_hash = self.ledger_entries[-1].entry_id if self.ledger_entries else "0" * 64
        
        entry = BlockchainEntry(
            entry_id=entry_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            evidence_hash=evidence_bundle.evidence_id,
            compliance_framework=evidence_bundle.compliance_framework,
            risk_level=risk_level,
            evidence_type=evidence_bundle.evidence_type.value,
            metadata_hash=evidence_bundle.metadata_hash,
            zero_knowledge_proof=evidence_bundle.zero_knowledge_proof,
            signature=evidence_bundle.signature,
            previous_entry_hash=previous_hash
        )
        
        # Add to ledger (in production, this would be published to actual blockchain)
        self.ledger_entries.append(entry)
        
        return entry
    
    def verify_evidence_integrity(self, evidence_id: str) -> Dict[str, Any]:
        """
        Verify evidence integrity using blockchain data and zero-knowledge proofs.
        
        Args:
            evidence_id: ID of evidence to verify
            
        Returns:
            Verification result
        """
        # Find evidence in local store
        if evidence_id not in self.evidence_store:
            return {"verified": False, "error": "Evidence not found"}
        
        stored_data = self.evidence_store[evidence_id]
        bundle = stored_data['bundle']
        
        # Find corresponding blockchain entry
        blockchain_entry = None
        for entry in self.ledger_entries:
            if entry.evidence_hash == evidence_id:
                blockchain_entry = entry
                break
        
        if not blockchain_entry:
            return {"verified": False, "error": "Blockchain entry not found"}
        
        # Verify signature
        bundle_data = f"{bundle.evidence_id}{bundle.timestamp}{bundle.hash_tree_root}"
        expected_signature = self._sign_data(bundle_data)
        
        if bundle.signature != expected_signature:
            return {"verified": False, "error": "Signature verification failed"}
        
        # Verify Merkle tree
        merkle_root, _ = self._create_merkle_tree(stored_data['sanitized_evidence'])
        if merkle_root != bundle.hash_tree_root:
            return {"verified": False, "error": "Merkle tree verification failed"}
        
        # Verify zero-knowledge proof
        compliance_requirements = self._get_compliance_requirements(bundle.compliance_framework)
        expected_zk_proof = self._create_zero_knowledge_proof(stored_data['sanitized_evidence'], compliance_requirements)
        
        if bundle.zero_knowledge_proof != expected_zk_proof:
            return {"verified": False, "error": "Zero-knowledge proof verification failed"}
        
        return {
            "verified": True,
            "evidence_id": evidence_id,
            "timestamp": bundle.timestamp,
            "compliance_framework": bundle.compliance_framework,
            "risk_score": bundle.risk_score,
            "blockchain_entry_id": blockchain_entry.entry_id,
            "chain_of_custody": "verified"
        }
    
    def get_compliance_report(self, framework: str, start_date: str, end_date: str) -> Dict[str, Any]:
        """
        Generate compliance report using blockchain data (NO sensitive data exposed).
        
        Args:
            framework: Compliance framework
            start_date: Start date for report
            end_date: End date for report
            
        Returns:
            Compliance report with cryptographic proofs
        """
        # Filter blockchain entries by framework and date
        relevant_entries = []
        for entry in self.ledger_entries:
            if (entry.compliance_framework == framework and
                start_date <= entry.timestamp <= end_date):
                relevant_entries.append(entry)
        
        # Calculate compliance metrics
        total_evidence = len(relevant_entries)
        high_risk_count = len([e for e in relevant_entries if e.risk_level == "HIGH"])
        medium_risk_count = len([e for e in relevant_entries if e.risk_level == "MEDIUM"])
        low_risk_count = len([e for e in relevant_entries if e.risk_level == "LOW"])
        
        # Create report hash for integrity
        report_data = f"{framework}{start_date}{end_date}{total_evidence}{high_risk_count}{medium_risk_count}{low_risk_count}"
        report_hash = hashlib.sha256(report_data.encode()).hexdigest()
        
        return {
            "framework": framework,
            "start_date": start_date,
            "end_date": end_date,
            "total_evidence": total_evidence,
            "risk_distribution": {
                "high": high_risk_count,
                "medium": medium_risk_count,
                "low": low_risk_count
            },
            "compliance_score": (low_risk_count / total_evidence) if total_evidence > 0 else 0,
            "report_hash": report_hash,
            "blockchain_entries": [e.entry_id for e in relevant_entries],
            "zero_knowledge_proof": hashlib.sha256(report_hash.encode()).hexdigest(),
            "generated_at": datetime.now(timezone.utc).isoformat()
        }


def main():
    """Demo the secure blockchain ledger functionality."""
    print("🔐 Secure Blockchain Ledger Demo")
    print("Zero-Knowledge Compliance Evidence Storage")
    print("=" * 60)
    
    # Initialize secure ledger
    ledger = SecureBlockchainLedger()
    
    # Demo 1: Store evidence securely
    print("\n📊 Demo 1: Secure Evidence Storage")
    print("-" * 40)
    
    # Sample evidence data (contains sensitive information)
    sensitive_evidence = {
        "resource_id": "arn:aws:s3:::example-bucket",
        "encryption_enabled": False,  # Sensitive configuration
        "mfa_enabled": False,  # Sensitive configuration
        "public_access": True,  # Sensitive configuration
        "pii_data": "customer_12345_ssn_123-45-6789",  # HIGHLY SENSITIVE
        "api_keys": "AKIAIOSFODNN7EXAMPLE",  # HIGHLY SENSITIVE
        "raw_response": "Detailed AWS API response with sensitive data",  # SENSITIVE
        "compliance_status": "NON_COMPLIANT"
    }
    
    print("Original evidence data (contains sensitive information):")
    for key, value in sensitive_evidence.items():
        if key in ['pii_data', 'api_keys', 'raw_response']:
            print(f"  {key}: [SENSITIVE DATA - {len(str(value))} characters]")
        else:
            print(f"  {key}: {value}")
    
    # Store evidence securely
    bundle = ledger.store_evidence_securely(
        sensitive_evidence,
        EvidenceType.CONFIGURATION,
        "NIST_CSF"
    )
    
    print(f"\n✅ Evidence stored securely:")
    print(f"  Evidence ID: {bundle.evidence_id}")
    print(f"  Merkle Root: {bundle.hash_tree_root}")
    print(f"  ZK Proof: {bundle.zero_knowledge_proof}")
    print(f"  Risk Score: {bundle.risk_score:.2f}")
    print(f"  Signature: {bundle.signature[:32]}...")
    
    # Demo 2: Publish to blockchain (NO sensitive data)
    print("\n⛓️ Demo 2: Blockchain Publication")
    print("-" * 40)
    
    blockchain_entry = ledger.publish_to_blockchain(bundle)
    
    print("What gets published to blockchain (NO sensitive data):")
    print(f"  Entry ID: {blockchain_entry.entry_id}")
    print(f"  Evidence Hash: {blockchain_entry.evidence_hash}")
    print(f"  Compliance Framework: {blockchain_entry.compliance_framework}")
    print(f"  Risk Level: {blockchain_entry.risk_level}")
    print(f"  Evidence Type: {blockchain_entry.evidence_type}")
    print(f"  Metadata Hash: {blockchain_entry.metadata_hash}")
    print(f"  ZK Proof: {blockchain_entry.zero_knowledge_proof}")
    print(f"  Signature: {blockchain_entry.signature[:32]}...")
    
    print("\n🔒 Security Guarantees:")
    print("  ✅ NO PII data published to blockchain")
    print("  ✅ NO sensitive configuration exposed")
    print("  ✅ NO API keys or credentials revealed")
    print("  ✅ NO raw response data visible")
    print("  ✅ Only cryptographic hashes and proofs published")
    
    # Demo 3: Verify evidence integrity
    print("\n🔍 Demo 3: Evidence Integrity Verification")
    print("-" * 40)
    
    verification_result = ledger.verify_evidence_integrity(bundle.evidence_id)
    
    print("Verification Results:")
    for key, value in verification_result.items():
        print(f"  {key}: {value}")
    
    # Demo 4: Generate compliance report
    print("\n📋 Demo 4: Compliance Report Generation")
    print("-" * 40)
    
    # Add more evidence for comprehensive report
    additional_evidence = {
        "resource_id": "arn:aws:iam::123456789012:user/example-user",
        "encryption_enabled": True,
        "mfa_enabled": True,
        "public_access": False,
        "compliance_status": "COMPLIANT"
    }
    
    bundle2 = ledger.store_evidence_securely(
        additional_evidence,
        EvidenceType.ACCESS_LOG,
        "NIST_CSF"
    )
    ledger.publish_to_blockchain(bundle2)
    
    # Generate report
    start_date = "2024-01-01T00:00:00Z"
    end_date = "2024-12-31T23:59:59Z"
    
    report = ledger.get_compliance_report("NIST_CSF", start_date, end_date)
    
    print("Compliance Report (NO sensitive data exposed):")
    for key, value in report.items():
        if key == "blockchain_entries":
            print(f"  {key}: {len(value)} entries")
        else:
            print(f"  {key}: {value}")
    
    print("\n" + "=" * 60)
    print("🎉 Secure Blockchain Ledger Demo Complete!")
    print("\nThis demonstrates:")
    print("• Zero-knowledge evidence storage")
    print("• Cryptographic integrity without data exposure")
    print("• Blockchain immutability for audit trails")
    print("• Compliance verification without revealing sensitive data")
    print("• Complete chain of custody protection")


if __name__ == '__main__':
    main()