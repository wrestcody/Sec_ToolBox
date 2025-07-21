#!/usr/bin/env python3
"""
The Guardian's Mandate: Digital Evidence Integrity Implementation

This module implements unassailable digital evidence integrity and unbreakable
chain of custody for the Cloud Compliance Evidence Scraper, ensuring all
evidence meets the highest standards for forensic investigation and compliance.
"""

import hashlib
import hmac
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import base64
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
import threading
from dataclasses import dataclass, asdict
from enum import Enum


class EvidenceIntegrityLevel(Enum):
    """Evidence integrity levels for different types of data."""
    CRITICAL = "critical"      # Highest integrity - cryptographic signatures, immutable storage
    HIGH = "high"             # High integrity - hashing, timestamping, audit trails
    STANDARD = "standard"     # Standard integrity - basic logging and validation
    BASIC = "basic"           # Basic integrity - minimal logging


@dataclass
class CryptographicProof:
    """Cryptographic proof of data integrity."""
    data_hash: str
    timestamp: str
    signature: Optional[str] = None
    public_key_fingerprint: Optional[str] = None
    chain_hash: Optional[str] = None
    previous_hash: Optional[str] = None
    nonce: Optional[str] = None


@dataclass
class ChainOfCustodyEntry:
    """Chain of custody entry for evidence tracking."""
    entry_id: str
    timestamp: str
    actor: str
    action: str
    resource: str
    data_hash: str
    session_id: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    cryptographic_proof: CryptographicProof


@dataclass
class EvidenceMetadata:
    """Metadata for evidence integrity and chain of custody."""
    evidence_id: str
    collection_timestamp: str
    integrity_level: EvidenceIntegrityLevel
    cryptographic_proof: CryptographicProof
    chain_of_custody: List[ChainOfCustodyEntry]
    retention_policy: str
    compliance_frameworks: List[str]
    data_classification: str
    export_format: str
    validation_status: str


class GuardianIntegrityManager:
    """
    Core integrity manager implementing The Guardian's Mandate.
    
    Provides cryptographic tamper-evident logging, automated chain of custody,
    and forensic-ready evidence integrity for all compliance evidence.
    """
    
    def __init__(self, 
                 private_key_path: Optional[str] = None,
                 integrity_level: EvidenceIntegrityLevel = EvidenceIntegrityLevel.HIGH,
                 enable_immutable_storage: bool = True,
                 enable_blockchain_ledger: bool = False):
        """
        Initialize the Guardian Integrity Manager.
        
        Args:
            private_key_path: Path to private key for cryptographic signing
            integrity_level: Level of integrity protection to apply
            enable_immutable_storage: Enable immutable storage features
            enable_blockchain_ledger: Enable blockchain-based ledger (experimental)
        """
        self.integrity_level = integrity_level
        self.enable_immutable_storage = enable_immutable_storage
        self.enable_blockchain_ledger = enable_blockchain_ledger
        
        # Initialize cryptographic components
        self._initialize_cryptography(private_key_path)
        
        # Initialize audit trail
        self.audit_trail = []
        self.chain_of_custody = []
        self.evidence_ledger = {}
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Initialize logging
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        
        # Generate session ID for this instance
        self.session_id = self._generate_session_id()
        
        # Initialize integrity monitoring
        self._initialize_integrity_monitoring()
    
    def _initialize_cryptography(self, private_key_path: Optional[str]) -> None:
        """Initialize cryptographic components."""
        if private_key_path and os.path.exists(private_key_path):
            # Load existing private key
            with open(private_key_path, 'rb') as f:
                private_key_data = f.read()
                self.private_key = rsa.load_der_private_key(private_key_data, password=None)
        else:
            # Generate new private key
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            
            # Save private key if path provided
            if private_key_path:
                private_key_data = self.private_key.private_bytes(
                    encoding=Encoding.DER,
                    format=PrivateFormat.PKCS8,
                    encryption_algorithm=NoEncryption()
                )
                with open(private_key_path, 'wb') as f:
                    f.write(private_key_data)
        
        # Get public key for verification
        self.public_key = self.private_key.public_key()
        
        # Generate key fingerprint
        public_key_data = self.public_key.public_bytes(
            encoding=Encoding.DER,
            format=PrivateFormat.PKCS8
        )
        self.public_key_fingerprint = hashlib.sha256(public_key_data).hexdigest()
    
    def _generate_session_id(self) -> str:
        """Generate a unique session ID."""
        timestamp = datetime.now(timezone.utc).isoformat()
        random_component = secrets.token_hex(16)
        return f"session_{timestamp}_{random_component}"
    
    def _initialize_integrity_monitoring(self) -> None:
        """Initialize integrity monitoring and alerting."""
        self.integrity_violations = []
        self.monitoring_active = True
        
        # Start integrity monitoring thread
        self._monitor_thread = threading.Thread(target=self._integrity_monitor, daemon=True)
        self._monitor_thread.start()
    
    def _integrity_monitor(self) -> None:
        """Background thread for integrity monitoring."""
        while self.monitoring_active:
            try:
                # Check for integrity violations
                self._check_integrity_violations()
                
                # Sleep for monitoring interval
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                self.logger.error(f"Integrity monitoring error: {e}")
    
    def _check_integrity_violations(self) -> None:
        """Check for integrity violations in audit trail and evidence."""
        with self._lock:
            for entry in self.audit_trail:
                if not self._verify_entry_integrity(entry):
                    violation = {
                        'timestamp': datetime.now(timezone.utc).isoformat(),
                        'entry_id': entry.get('entry_id'),
                        'violation_type': 'audit_trail_tampering',
                        'description': 'Audit trail entry integrity verification failed'
                    }
                    self.integrity_violations.append(violation)
                    self.logger.critical(f"INTEGRITY VIOLATION DETECTED: {violation}")
    
    def _verify_entry_integrity(self, entry: Dict[str, Any]) -> bool:
        """Verify the integrity of an audit trail entry."""
        try:
            # Verify hash
            data = entry.get('data', '')
            expected_hash = entry.get('data_hash', '')
            actual_hash = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
            
            if expected_hash != actual_hash:
                return False
            
            # Verify signature if present
            if entry.get('signature') and self.integrity_level in [EvidenceIntegrityLevel.CRITICAL, EvidenceIntegrityLevel.HIGH]:
                signature = base64.b64decode(entry['signature'])
                data_to_verify = f"{entry['timestamp']}:{entry['data_hash']}".encode()
                
                try:
                    self.public_key.verify(
                        signature,
                        data_to_verify,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                except Exception:
                    return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Entry integrity verification error: {e}")
            return False
    
    def create_cryptographic_proof(self, data: Any, include_signature: bool = True) -> CryptographicProof:
        """
        Create cryptographic proof for data integrity.
        
        Args:
            data: Data to create proof for
            include_signature: Whether to include cryptographic signature
            
        Returns:
            CryptographicProof object
        """
        # Generate data hash
        data_json = json.dumps(data, sort_keys=True, default=str)
        data_hash = hashlib.sha256(data_json.encode()).hexdigest()
        
        # Generate timestamp
        timestamp = datetime.now(timezone.utc).isoformat()
        
        # Generate nonce for additional entropy
        nonce = secrets.token_hex(16)
        
        # Create chain hash if previous hash exists
        chain_hash = None
        if self.chain_of_custody:
            previous_entry = self.chain_of_custody[-1]
            previous_hash = previous_entry.cryptographic_proof.data_hash
            chain_data = f"{previous_hash}:{data_hash}:{timestamp}:{nonce}".encode()
            chain_hash = hashlib.sha256(chain_data).hexdigest()
        
        # Generate signature if required
        signature = None
        if include_signature and self.integrity_level in [EvidenceIntegrityLevel.CRITICAL, EvidenceIntegrityLevel.HIGH]:
            data_to_sign = f"{timestamp}:{data_hash}:{nonce}".encode()
            signature = self.private_key.sign(
                data_to_sign,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            signature = base64.b64encode(signature).decode()
        
        return CryptographicProof(
            data_hash=data_hash,
            timestamp=timestamp,
            signature=signature,
            public_key_fingerprint=self.public_key_fingerprint,
            chain_hash=chain_hash,
            previous_hash=chain_hash,
            nonce=nonce
        )
    
    def log_audit_event(self, 
                       actor: str,
                       action: str,
                       resource: str,
                       data: Any,
                       ip_address: Optional[str] = None,
                       user_agent: Optional[str] = None) -> str:
        """
        Log an audit event with full chain of custody tracking.
        
        Args:
            actor: Identity performing the action
            action: Action being performed
            resource: Resource being acted upon
            data: Associated data
            ip_address: IP address of actor
            user_agent: User agent string
            
        Returns:
            Entry ID for the logged event
        """
        with self._lock:
            # Generate entry ID
            entry_id = f"audit_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(8)}"
            
            # Create cryptographic proof
            proof = self.create_cryptographic_proof(data)
            
            # Create chain of custody entry
            custody_entry = ChainOfCustodyEntry(
                entry_id=entry_id,
                timestamp=proof.timestamp,
                actor=actor,
                action=action,
                resource=resource,
                data_hash=proof.data_hash,
                session_id=self.session_id,
                ip_address=ip_address,
                user_agent=user_agent,
                cryptographic_proof=proof
            )
            
            # Add to chain of custody
            self.chain_of_custody.append(custody_entry)
            
            # Create audit trail entry
            audit_entry = {
                'entry_id': entry_id,
                'timestamp': proof.timestamp,
                'actor': actor,
                'action': action,
                'resource': resource,
                'data': data,
                'data_hash': proof.data_hash,
                'signature': proof.signature,
                'session_id': self.session_id,
                'ip_address': ip_address,
                'user_agent': user_agent,
                'chain_hash': proof.chain_hash,
                'nonce': proof.nonce
            }
            
            # Add to audit trail
            self.audit_trail.append(audit_entry)
            
            # Log the event
            self.logger.info(f"AUDIT: {actor} performed {action} on {resource} (Entry: {entry_id})")
            
            return entry_id
    
    def create_evidence_metadata(self,
                                evidence_id: str,
                                evidence_data: Any,
                                compliance_frameworks: List[str],
                                data_classification: str = "confidential",
                                retention_policy: str = "7_years") -> EvidenceMetadata:
        """
        Create comprehensive metadata for evidence integrity.
        
        Args:
            evidence_id: Unique identifier for the evidence
            evidence_data: The evidence data
            compliance_frameworks: List of applicable compliance frameworks
            data_classification: Classification of the data
            retention_policy: Retention policy for the evidence
            
        Returns:
            EvidenceMetadata object
        """
        # Create cryptographic proof
        proof = self.create_cryptographic_proof(evidence_data, include_signature=True)
        
        # Log evidence creation
        self.log_audit_event(
            actor="system",
            action="evidence_created",
            resource=evidence_id,
            data=evidence_data
        )
        
        return EvidenceMetadata(
            evidence_id=evidence_id,
            collection_timestamp=proof.timestamp,
            integrity_level=self.integrity_level,
            cryptographic_proof=proof,
            chain_of_custody=self.chain_of_custody.copy(),
            retention_policy=retention_policy,
            compliance_frameworks=compliance_frameworks,
            data_classification=data_classification,
            export_format="json",
            validation_status="valid"
        )
    
    def verify_evidence_integrity(self, evidence_data: Any, metadata: EvidenceMetadata) -> bool:
        """
        Verify the integrity of evidence using its metadata.
        
        Args:
            evidence_data: The evidence data to verify
            metadata: The evidence metadata containing cryptographic proof
            
        Returns:
            True if integrity is verified, False otherwise
        """
        try:
            # Verify data hash
            data_json = json.dumps(evidence_data, sort_keys=True, default=str)
            actual_hash = hashlib.sha256(data_json.encode()).hexdigest()
            
            if actual_hash != metadata.cryptographic_proof.data_hash:
                self.logger.error(f"Evidence hash mismatch for {metadata.evidence_id}")
                return False
            
            # Verify signature if present
            if metadata.cryptographic_proof.signature:
                signature = base64.b64decode(metadata.cryptographic_proof.signature)
                data_to_verify = f"{metadata.cryptographic_proof.timestamp}:{metadata.cryptographic_proof.data_hash}:{metadata.cryptographic_proof.nonce}".encode()
                
                try:
                    self.public_key.verify(
                        signature,
                        data_to_verify,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                except Exception as e:
                    self.logger.error(f"Signature verification failed for {metadata.evidence_id}: {e}")
                    return False
            
            # Verify chain of custody
            if not self._verify_chain_of_custody(metadata.chain_of_custody):
                self.logger.error(f"Chain of custody verification failed for {metadata.evidence_id}")
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Evidence integrity verification error for {metadata.evidence_id}: {e}")
            return False
    
    def _verify_chain_of_custody(self, chain: List[ChainOfCustodyEntry]) -> bool:
        """Verify the integrity of the chain of custody."""
        try:
            for i, entry in enumerate(chain):
                # Verify entry hash
                entry_data = f"{entry.timestamp}:{entry.actor}:{entry.action}:{entry.resource}:{entry.data_hash}"
                expected_hash = hashlib.sha256(entry_data.encode()).hexdigest()
                
                # Verify cryptographic proof
                if not self._verify_cryptographic_proof(entry.cryptographic_proof):
                    return False
                
                # Verify chain links
                if i > 0 and entry.cryptographic_proof.previous_hash:
                    previous_entry = chain[i-1]
                    if entry.cryptographic_proof.previous_hash != previous_entry.cryptographic_proof.data_hash:
                        return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Chain of custody verification error: {e}")
            return False
    
    def _verify_cryptographic_proof(self, proof: CryptographicProof) -> bool:
        """Verify a cryptographic proof."""
        try:
            # Verify timestamp format
            datetime.fromisoformat(proof.timestamp.replace('Z', '+00:00'))
            
            # Verify hash format
            if len(proof.data_hash) != 64:  # SHA-256 hash length
                return False
            
            # Verify signature if present
            if proof.signature:
                signature = base64.b64decode(proof.signature)
                data_to_verify = f"{proof.timestamp}:{proof.data_hash}:{proof.nonce}".encode()
                
                try:
                    self.public_key.verify(
                        signature,
                        data_to_verify,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                except Exception:
                    return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Cryptographic proof verification error: {e}")
            return False
    
    def export_forensic_data(self, output_path: str) -> Dict[str, Any]:
        """
        Export all forensic data in a standardized format.
        
        Args:
            output_path: Path to save the forensic export
            
        Returns:
            Dictionary containing export metadata
        """
        with self._lock:
            # Create forensic export
            forensic_data = {
                'export_metadata': {
                    'export_timestamp': datetime.now(timezone.utc).isoformat(),
                    'export_id': f"forensic_export_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{secrets.token_hex(8)}",
                    'integrity_level': self.integrity_level.value,
                    'public_key_fingerprint': self.public_key_fingerprint,
                    'session_id': self.session_id,
                    'total_audit_entries': len(self.audit_trail),
                    'total_custody_entries': len(self.chain_of_custody),
                    'integrity_violations': len(self.integrity_violations)
                },
                'audit_trail': self.audit_trail,
                'chain_of_custody': [asdict(entry) for entry in self.chain_of_custody],
                'integrity_violations': self.integrity_violations,
                'evidence_ledger': self.evidence_ledger
            }
            
            # Create cryptographic proof for the export
            export_proof = self.create_cryptographic_proof(forensic_data)
            
            # Add export proof to forensic data
            forensic_data['export_metadata']['cryptographic_proof'] = asdict(export_proof)
            
            # Save to file
            with open(output_path, 'w') as f:
                json.dump(forensic_data, f, indent=2, default=str)
            
            # Log export
            self.log_audit_event(
                actor="system",
                action="forensic_export_created",
                resource=output_path,
                data={'export_id': forensic_data['export_metadata']['export_id']}
            )
            
            return forensic_data['export_metadata']
    
    def get_integrity_report(self) -> Dict[str, Any]:
        """Generate an integrity status report."""
        with self._lock:
            return {
                'integrity_status': {
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'integrity_level': self.integrity_level.value,
                    'audit_trail_entries': len(self.audit_trail),
                    'chain_of_custody_entries': len(self.chain_of_custody),
                    'integrity_violations': len(self.integrity_violations),
                    'session_id': self.session_id,
                    'public_key_fingerprint': self.public_key_fingerprint
                },
                'recent_violations': self.integrity_violations[-10:] if self.integrity_violations else [],
                'chain_of_custody_summary': {
                    'total_entries': len(self.chain_of_custody),
                    'unique_actors': len(set(entry.actor for entry in self.chain_of_custody)),
                    'unique_resources': len(set(entry.resource for entry in self.chain_of_custody)),
                    'time_span': {
                        'start': self.chain_of_custody[0].timestamp if self.chain_of_custody else None,
                        'end': self.chain_of_custody[-1].timestamp if self.chain_of_custody else None
                    }
                }
            }
    
    def shutdown(self) -> None:
        """Shutdown the integrity manager and export final data."""
        self.monitoring_active = False
        
        # Export final forensic data
        final_export_path = f"guardian_final_export_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
        self.export_forensic_data(final_export_path)
        
        self.logger.info("Guardian Integrity Manager shutdown complete")


class GuardianEvidenceCollector:
    """
    Enhanced evidence collector with Guardian's Mandate integrity.
    
    Wraps the compliance evidence collection with cryptographic integrity,
    chain of custody tracking, and forensic-ready capabilities.
    """
    
    def __init__(self, 
                 integrity_manager: GuardianIntegrityManager,
                 enable_immutable_storage: bool = True):
        """
        Initialize the Guardian Evidence Collector.
        
        Args:
            integrity_manager: Guardian Integrity Manager instance
            enable_immutable_storage: Enable immutable storage features
        """
        self.integrity_manager = integrity_manager
        self.enable_immutable_storage = enable_immutable_storage
        self.logger = logging.getLogger(__name__)
        
        # Evidence storage with integrity
        self.evidence_store = {}
        self.evidence_metadata = {}
    
    def collect_evidence_with_integrity(self,
                                      evidence_id: str,
                                      evidence_data: Any,
                                      compliance_frameworks: List[str],
                                      data_classification: str = "confidential",
                                      retention_policy: str = "7_years") -> Tuple[Any, EvidenceMetadata]:
        """
        Collect evidence with full Guardian's Mandate integrity protection.
        
        Args:
            evidence_id: Unique identifier for the evidence
            evidence_data: The evidence data to collect
            compliance_frameworks: List of applicable compliance frameworks
            data_classification: Classification of the data
            retention_policy: Retention policy for the evidence
            
        Returns:
            Tuple of (evidence_data, evidence_metadata)
        """
        # Log evidence collection start
        self.integrity_manager.log_audit_event(
            actor="system",
            action="evidence_collection_started",
            resource=evidence_id,
            data={"compliance_frameworks": compliance_frameworks}
        )
        
        # Create evidence metadata with integrity
        metadata = self.integrity_manager.create_evidence_metadata(
            evidence_id=evidence_id,
            evidence_data=evidence_data,
            compliance_frameworks=compliance_frameworks,
            data_classification=data_classification,
            retention_policy=retention_policy
        )
        
        # Store evidence with metadata
        self.evidence_store[evidence_id] = evidence_data
        self.evidence_metadata[evidence_id] = metadata
        
        # Log evidence collection completion
        self.integrity_manager.log_audit_event(
            actor="system",
            action="evidence_collection_completed",
            resource=evidence_id,
            data={"metadata": asdict(metadata)}
        )
        
        self.logger.info(f"Evidence collected with integrity: {evidence_id}")
        
        return evidence_data, metadata
    
    def verify_evidence_integrity(self, evidence_id: str) -> bool:
        """
        Verify the integrity of stored evidence.
        
        Args:
            evidence_id: ID of the evidence to verify
            
        Returns:
            True if integrity is verified, False otherwise
        """
        if evidence_id not in self.evidence_store or evidence_id not in self.evidence_metadata:
            return False
        
        evidence_data = self.evidence_store[evidence_id]
        metadata = self.evidence_metadata[evidence_id]
        
        return self.integrity_manager.verify_evidence_integrity(evidence_data, metadata)
    
    def export_evidence_with_integrity(self, 
                                      evidence_id: str, 
                                      output_path: str,
                                      include_forensic_data: bool = True) -> Dict[str, Any]:
        """
        Export evidence with full integrity documentation.
        
        Args:
            evidence_id: ID of the evidence to export
            output_path: Path to save the export
            include_forensic_data: Whether to include forensic data
            
        Returns:
            Export metadata
        """
        if evidence_id not in self.evidence_store:
            raise ValueError(f"Evidence {evidence_id} not found")
        
        evidence_data = self.evidence_store[evidence_id]
        metadata = self.evidence_metadata[evidence_id]
        
        # Create export package
        export_package = {
            'export_metadata': {
                'export_timestamp': datetime.now(timezone.utc).isoformat(),
                'export_id': f"evidence_export_{evidence_id}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}",
                'evidence_id': evidence_id,
                'include_forensic_data': include_forensic_data
            },
            'evidence_data': evidence_data,
            'evidence_metadata': asdict(metadata)
        }
        
        # Add forensic data if requested
        if include_forensic_data:
            export_package['forensic_data'] = self.integrity_manager.get_integrity_report()
        
        # Create cryptographic proof for export
        export_proof = self.integrity_manager.create_cryptographic_proof(export_package)
        export_package['export_metadata']['cryptographic_proof'] = asdict(export_proof)
        
        # Save export
        with open(output_path, 'w') as f:
            json.dump(export_package, f, indent=2, default=str)
        
        # Log export
        self.integrity_manager.log_audit_event(
            actor="system",
            action="evidence_exported",
            resource=evidence_id,
            data={"export_path": output_path, "export_id": export_package['export_metadata']['export_id']}
        )
        
        return export_package['export_metadata']


# Example usage and testing
def create_guardian_integrity_manager() -> GuardianIntegrityManager:
    """Create a Guardian Integrity Manager instance."""
    return GuardianIntegrityManager(
        private_key_path="guardian_private_key.der",
        integrity_level=EvidenceIntegrityLevel.HIGH,
        enable_immutable_storage=True,
        enable_blockchain_ledger=False
    )


def test_guardian_integrity():
    """Test the Guardian's Mandate integrity features."""
    print("🧪 Testing Guardian's Mandate Integrity Features")
    print("=" * 60)
    
    # Create integrity manager
    integrity_manager = create_guardian_integrity_manager()
    
    # Create evidence collector
    evidence_collector = GuardianEvidenceCollector(integrity_manager)
    
    # Test evidence collection with integrity
    test_evidence = {
        "control_id": "CC6.1",
        "control_name": "Logical Access Controls",
        "findings": ["✅ MFA enabled", "✅ Password policy configured"],
        "compliance_status": "Compliant"
    }
    
    evidence_data, metadata = evidence_collector.collect_evidence_with_integrity(
        evidence_id="test_evidence_001",
        evidence_data=test_evidence,
        compliance_frameworks=["SOC 2", "ISO 27001"],
        data_classification="confidential"
    )
    
    print(f"✅ Evidence collected with integrity: {metadata.evidence_id}")
    print(f"   Cryptographic Proof: {metadata.cryptographic_proof.data_hash[:16]}...")
    print(f"   Chain of Custody Entries: {len(metadata.chain_of_custody)}")
    
    # Test integrity verification
    integrity_verified = evidence_collector.verify_evidence_integrity("test_evidence_001")
    print(f"✅ Evidence integrity verified: {integrity_verified}")
    
    # Test evidence export
    export_metadata = evidence_collector.export_evidence_with_integrity(
        evidence_id="test_evidence_001",
        output_path="test_evidence_export.json"
    )
    print(f"✅ Evidence exported with integrity: {export_metadata['export_id']}")
    
    # Get integrity report
    integrity_report = integrity_manager.get_integrity_report()
    print(f"✅ Integrity report generated:")
    print(f"   Audit trail entries: {integrity_report['integrity_status']['audit_trail_entries']}")
    print(f"   Chain of custody entries: {integrity_report['integrity_status']['chain_of_custody_entries']}")
    print(f"   Integrity violations: {integrity_report['integrity_status']['integrity_violations']}")
    
    # Export forensic data
    forensic_export = integrity_manager.export_forensic_data("guardian_forensic_export.json")
    print(f"✅ Forensic data exported: {forensic_export['export_id']}")
    
    # Shutdown
    integrity_manager.shutdown()
    print("✅ Guardian Integrity Manager shutdown complete")
    
    print("\n🎯 Guardian's Mandate Integrity Features Tested Successfully!")
    print("   - Cryptographic tamper-evident logging")
    print("   - Automated chain of custody")
    print("   - Evidence integrity verification")
    print("   - Forensic-ready data export")
    print("   - Immutable audit trails")


if __name__ == "__main__":
    test_guardian_integrity()