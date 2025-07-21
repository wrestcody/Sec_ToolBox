#!/usr/bin/env python3
"""
The Guardian's Mandate: Digital Evidence Integrity Framework

This module implements the foundational principles for building systems with
unassailable digital evidence integrity and unbreakable chain of custody.

Core Principles:
- Cryptographic Tamper-Evident Logging & Data
- Automated & Granular Chain of Custody  
- Verifiable Ledger for Integrity
- Forensic Readiness & Auditability by Design
"""

import hashlib
import hmac
import json
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Union, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import base64
import struct
import threading
from pathlib import Path
import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets


class EvidenceLevel(Enum):
    """Evidence integrity levels for different types of data."""
    CRITICAL = "critical"      # Highest integrity - cryptographic proofs required
    HIGH = "high"             # High integrity - hashing and timestamping
    MEDIUM = "medium"         # Medium integrity - basic logging
    LOW = "low"              # Low integrity - informational only


class AuditEventType(Enum):
    """Types of audit events for categorization."""
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    CONFIGURATION_CHANGE = "configuration_change"
    SECURITY_EVENT = "security_event"
    SYSTEM_EVENT = "system_event"
    USER_ACTION = "user_action"
    INTEGRITY_CHECK = "integrity_check"
    CHAIN_OF_CUSTODY = "chain_of_custody"


@dataclass
class CryptographicProof:
    """Cryptographic proof for data integrity verification."""
    data_hash: str
    timestamp: str
    nonce: str
    signature: Optional[str] = None
    public_key_fingerprint: Optional[str] = None
    proof_type: str = "sha256_hmac"
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CryptographicProof':
        return cls(**data)


@dataclass
class AuditEvent:
    """Immutable audit event with cryptographic integrity."""
    event_id: str
    timestamp: str
    event_type: str
    user_id: str
    session_id: str
    source_ip: str
    user_agent: str
    action: str
    resource: str
    details: Dict[str, Any]
    evidence_level: str
    cryptographic_proof: CryptographicProof
    parent_event_id: Optional[str] = None
    chain_sequence: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data['cryptographic_proof'] = self.cryptographic_proof.to_dict()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AuditEvent':
        proof_data = data.pop('cryptographic_proof')
        data['cryptographic_proof'] = CryptographicProof.from_dict(proof_data)
        return cls(**data)


class GuardianLedger:
    """
    Immutable, cryptographically-secured audit ledger implementing
    The Guardian's Mandate principles.
    """
    
    def __init__(self, 
                 ledger_path: str = "guardian_ledger",
                 master_key: Optional[bytes] = None,
                 enable_blockchain_verification: bool = False):
        """
        Initialize the Guardian Ledger.
        
        Args:
            ledger_path: Path to store the immutable ledger
            master_key: Master encryption key (generated if None)
            enable_blockchain_verification: Enable blockchain-style verification
        """
        self.ledger_path = Path(ledger_path)
        self.ledger_path.mkdir(exist_ok=True)
        
        # Initialize cryptographic components
        self.master_key = master_key or self._generate_master_key()
        self.private_key = self._generate_private_key()
        self.public_key = self.private_key.public_key()
        
        # Ledger state
        self.current_chain_hash = self._initialize_chain()
        self.sequence_number = 0
        self.enable_blockchain_verification = enable_blockchain_verification
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Initialize logging
        self._setup_logging()
        
        # Create initial integrity checkpoint
        self._create_integrity_checkpoint("Guardian Ledger Initialized")
    
    def _generate_master_key(self) -> bytes:
        """Generate a cryptographically secure master key."""
        return secrets.token_bytes(32)
    
    def _generate_private_key(self) -> rsa.RSAPrivateKey:
        """Generate RSA private key for digital signatures."""
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
    
    def _initialize_chain(self) -> str:
        """Initialize the cryptographic chain with genesis block."""
        genesis_data = {
            "type": "genesis",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool_version": "1.0.0",
            "guardian_mandate_version": "1.0.0"
        }
        
        genesis_hash = self._compute_hash(json.dumps(genesis_data, sort_keys=True))
        
        # Store genesis block
        genesis_block = {
            "block_id": "genesis",
            "previous_hash": "0000000000000000000000000000000000000000000000000000000000000000",
            "current_hash": genesis_hash,
            "timestamp": genesis_data["timestamp"],
            "data": genesis_data,
            "proof": self._create_cryptographic_proof(genesis_data)
        }
        
        self._store_block(genesis_block)
        return genesis_hash
    
    def _setup_logging(self):
        """Setup secure logging for the Guardian Ledger."""
        log_path = self.ledger_path / "guardian.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_path),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger("GuardianLedger")
    
    def _compute_hash(self, data: str) -> str:
        """Compute SHA-256 hash of data."""
        return hashlib.sha256(data.encode('utf-8')).hexdigest()
    
    def _create_cryptographic_proof(self, data: Union[str, Dict[str, Any]]) -> CryptographicProof:
        """Create cryptographic proof for data integrity."""
        if isinstance(data, dict):
            data_str = json.dumps(data, sort_keys=True)
        else:
            data_str = str(data)
        
        # Generate nonce for additional entropy
        nonce = secrets.token_hex(16)
        
        # Create HMAC with master key
        hmac_obj = hmac.new(self.master_key, f"{data_str}:{nonce}".encode(), hashlib.sha256)
        data_hash = hmac_obj.hexdigest()
        
        # Create digital signature
        signature = self._sign_data(data_hash)
        
        # Get public key fingerprint
        public_key_fingerprint = self._get_public_key_fingerprint()
        
        return CryptographicProof(
            data_hash=data_hash,
            timestamp=datetime.now(timezone.utc).isoformat(),
            nonce=nonce,
            signature=signature,
            public_key_fingerprint=public_key_fingerprint,
            proof_type="sha256_hmac_rsa"
        )
    
    def _sign_data(self, data: str) -> str:
        """Sign data with private key."""
        signature = self.private_key.sign(
            data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()
    
    def _get_public_key_fingerprint(self) -> str:
        """Get fingerprint of public key."""
        public_bytes = self.public_key.public_bytes(
            encoding=Encoding.DER,
            format=PrivateFormat.PKCS8
        )
        return hashlib.sha256(public_bytes).hexdigest()
    
    def _store_block(self, block: Dict[str, Any]):
        """Store immutable block in the ledger."""
        block_id = block["block_id"]
        block_file = self.ledger_path / f"block_{block_id}.json"
        
        # Ensure atomic write
        temp_file = self.ledger_path / f"temp_{block_id}.json"
        with open(temp_file, 'w') as f:
            json.dump(block, f, indent=2, sort_keys=True)
        
        # Atomic move
        temp_file.rename(block_file)
    
    def record_event(self, 
                    event_type: str,
                    user_id: str,
                    session_id: str,
                    source_ip: str,
                    user_agent: str,
                    action: str,
                    resource: str,
                    details: Dict[str, Any],
                    evidence_level: EvidenceLevel = EvidenceLevel.HIGH,
                    parent_event_id: Optional[str] = None) -> str:
        """
        Record an immutable audit event with cryptographic integrity.
        
        Args:
            event_type: Type of audit event
            user_id: User identifier
            session_id: Session identifier
            source_ip: Source IP address
            user_agent: User agent string
            action: Action performed
            resource: Resource accessed/modified
            details: Additional event details
            evidence_level: Evidence integrity level
            parent_event_id: Parent event ID for chain of custody
            
        Returns:
            Event ID of the recorded event
        """
        with self._lock:
            # Generate unique event ID
            event_id = str(uuid.uuid4())
            
            # Create audit event
            audit_event = AuditEvent(
                event_id=event_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                event_type=event_type,
                user_id=user_id,
                session_id=session_id,
                source_ip=source_ip,
                user_agent=user_agent,
                action=action,
                resource=resource,
                details=details,
                evidence_level=evidence_level.value,
                cryptographic_proof=self._create_cryptographic_proof(details),
                parent_event_id=parent_event_id,
                chain_sequence=self.sequence_number
            )
            
            # Create block with event
            block_data = {
                "event": audit_event.to_dict(),
                "previous_chain_hash": self.current_chain_hash,
                "sequence_number": self.sequence_number
            }
            
            # Compute new chain hash
            new_chain_hash = self._compute_hash(json.dumps(block_data, sort_keys=True))
            
            # Create block
            block = {
                "block_id": f"block_{self.sequence_number:08d}",
                "previous_hash": self.current_chain_hash,
                "current_hash": new_chain_hash,
                "timestamp": audit_event.timestamp,
                "data": block_data,
                "proof": self._create_cryptographic_proof(block_data)
            }
            
            # Store block
            self._store_block(block)
            
            # Update chain state
            self.current_chain_hash = new_chain_hash
            self.sequence_number += 1
            
            # Log the event
            self.logger.info(f"Recorded event {event_id} with chain hash {new_chain_hash}")
            
            return event_id
    
    def verify_integrity(self, start_sequence: int = 0, end_sequence: Optional[int] = None) -> Dict[str, Any]:
        """
        Verify the integrity of the entire ledger or a range of blocks.
        
        Args:
            start_sequence: Starting sequence number
            end_sequence: Ending sequence number (None for all)
            
        Returns:
            Integrity verification results
        """
        verification_results = {
            "verified": True,
            "total_blocks": 0,
            "verified_blocks": 0,
            "errors": [],
            "chain_hashes": [],
            "timestamp_range": {"start": None, "end": None}
        }
        
        current_hash = None
        sequence = start_sequence
        
        while True:
            block_file = self.ledger_path / f"block_{sequence:08d}.json"
            
            if not block_file.exists():
                if end_sequence and sequence >= end_sequence:
                    break
                elif end_sequence is None:
                    break
                else:
                    verification_results["errors"].append(f"Missing block {sequence}")
                    verification_results["verified"] = False
                    break
            
            try:
                with open(block_file, 'r') as f:
                    block = json.load(f)
                
                # Verify block structure
                required_fields = ["block_id", "previous_hash", "current_hash", "timestamp", "data", "proof"]
                for field in required_fields:
                    if field not in block:
                        verification_results["errors"].append(f"Block {sequence} missing field: {field}")
                        verification_results["verified"] = False
                        break
                
                # Verify cryptographic proof
                if not self._verify_cryptographic_proof(block["data"], block["proof"]):
                    verification_results["errors"].append(f"Block {sequence} cryptographic proof verification failed")
                    verification_results["verified"] = False
                
                # Verify chain continuity
                if current_hash is not None and block["previous_hash"] != current_hash:
                    verification_results["errors"].append(f"Block {sequence} chain discontinuity")
                    verification_results["verified"] = False
                
                # Update verification state
                verification_results["total_blocks"] += 1
                verification_results["verified_blocks"] += 1
                verification_results["chain_hashes"].append(block["current_hash"])
                
                # Update timestamp range
                if verification_results["timestamp_range"]["start"] is None:
                    verification_results["timestamp_range"]["start"] = block["timestamp"]
                verification_results["timestamp_range"]["end"] = block["timestamp"]
                
                current_hash = block["current_hash"]
                sequence += 1
                
            except Exception as e:
                verification_results["errors"].append(f"Error processing block {sequence}: {str(e)}")
                verification_results["verified"] = False
                break
        
        return verification_results
    
    def _verify_cryptographic_proof(self, data: Dict[str, Any], proof: Dict[str, Any]) -> bool:
        """Verify cryptographic proof for data integrity."""
        try:
            # Recreate the data hash
            data_str = json.dumps(data, sort_keys=True)
            hmac_obj = hmac.new(self.master_key, f"{data_str}:{proof['nonce']}".encode(), hashlib.sha256)
            expected_hash = hmac_obj.hexdigest()
            
            # Verify hash
            if expected_hash != proof['data_hash']:
                return False
            
            # Verify signature if present
            if proof.get('signature') and proof.get('public_key_fingerprint'):
                try:
                    signature = base64.b64decode(proof['signature'])
                    self.public_key.verify(
                        signature,
                        proof['data_hash'].encode(),
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )
                except Exception:
                    return False
            
            return True
            
        except Exception:
            return False
    
    def _create_integrity_checkpoint(self, description: str):
        """Create an integrity checkpoint for forensic purposes."""
        checkpoint_data = {
            "type": "integrity_checkpoint",
            "description": description,
            "current_chain_hash": self.current_chain_hash,
            "sequence_number": self.sequence_number,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        
        checkpoint_id = f"checkpoint_{int(time.time())}"
        checkpoint_file = self.ledger_path / f"{checkpoint_id}.json"
        
        checkpoint = {
            "checkpoint_id": checkpoint_id,
            "data": checkpoint_data,
            "proof": self._create_cryptographic_proof(checkpoint_data)
        }
        
        with open(checkpoint_file, 'w') as f:
            json.dump(checkpoint, f, indent=2, sort_keys=True)
        
        self.logger.info(f"Created integrity checkpoint: {checkpoint_id}")
    
    def export_forensic_data(self, output_path: str, start_sequence: int = 0, end_sequence: Optional[int] = None) -> str:
        """
        Export forensic data in a standardized, machine-readable format.
        
        Args:
            output_path: Path to export forensic data
            start_sequence: Starting sequence number
            end_sequence: Ending sequence number
            
        Returns:
            Path to exported forensic data
        """
        export_data = {
            "export_metadata": {
                "export_timestamp": datetime.now(timezone.utc).isoformat(),
                "tool_version": "1.0.0",
                "guardian_mandate_version": "1.0.0",
                "start_sequence": start_sequence,
                "end_sequence": end_sequence,
                "export_format": "guardian_forensic_v1"
            },
            "integrity_verification": self.verify_integrity(start_sequence, end_sequence),
            "blocks": [],
            "events": []
        }
        
        sequence = start_sequence
        while True:
            block_file = self.ledger_path / f"block_{sequence:08d}.json"
            
            if not block_file.exists():
                if end_sequence and sequence >= end_sequence:
                    break
                elif end_sequence is None:
                    break
                else:
                    break
            
            with open(block_file, 'r') as f:
                block = json.load(f)
            
            export_data["blocks"].append(block)
            
            # Extract event data
            if "data" in block and "event" in block["data"]:
                export_data["events"].append(block["data"]["event"])
            
            sequence += 1
        
        # Create export file with integrity proof
        export_proof = self._create_cryptographic_proof(export_data)
        export_data["export_proof"] = export_proof.to_dict()
        
        with open(output_path, 'w') as f:
            json.dump(export_data, f, indent=2, sort_keys=True)
        
        self.logger.info(f"Exported forensic data to: {output_path}")
        return output_path
    
    def get_chain_of_custody(self, event_id: str) -> List[Dict[str, Any]]:
        """
        Get the complete chain of custody for a specific event.
        
        Args:
            event_id: Event ID to trace
            
        Returns:
            List of chain of custody events
        """
        chain = []
        
        # Find the event
        for block_file in sorted(self.ledger_path.glob("block_*.json")):
            with open(block_file, 'r') as f:
                block = json.load(f)
            
            if "data" in block and "event" in block["data"]:
                event = block["data"]["event"]
                if event["event_id"] == event_id:
                    chain.append({
                        "event": event,
                        "block": block,
                        "chain_position": block["data"]["sequence_number"]
                    })
                    
                    # Follow parent events
                    parent_id = event.get("parent_event_id")
                    while parent_id:
                        parent_event = self._find_event_by_id(parent_id)
                        if parent_event:
                            chain.append({
                                "event": parent_event,
                                "chain_position": "parent",
                                "relationship": "parent"
                            })
                            parent_id = parent_event.get("parent_event_id")
                        else:
                            break
                    break
        
        return chain
    
    def _find_event_by_id(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Find an event by its ID."""
        for block_file in self.ledger_path.glob("block_*.json"):
            with open(block_file, 'r') as f:
                block = json.load(f)
            
            if "data" in block and "event" in block["data"]:
                event = block["data"]["event"]
                if event["event_id"] == event_id:
                    return event
        
        return None


class GuardianIntegrityValidator:
    """Validator for verifying Guardian's Mandate compliance."""
    
    @staticmethod
    def validate_evidence_integrity(proof: CryptographicProof, data: Union[str, Dict[str, Any]]) -> bool:
        """Validate cryptographic proof for data integrity."""
        try:
            if isinstance(data, dict):
                data_str = json.dumps(data, sort_keys=True)
            else:
                data_str = str(data)
            
            # Recreate hash
            hmac_obj = hmac.new(b"placeholder_key", f"{data_str}:{proof.nonce}".encode(), hashlib.sha256)
            expected_hash = hmac_obj.hexdigest()
            
            return expected_hash == proof.data_hash
            
        except Exception:
            return False
    
    @staticmethod
    def validate_timestamp_accuracy(timestamp: str, tolerance_seconds: int = 30) -> bool:
        """Validate timestamp accuracy within tolerance."""
        try:
            event_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            current_time = datetime.now(timezone.utc)
            
            time_diff = abs((current_time - event_time).total_seconds())
            return time_diff <= tolerance_seconds
            
        except Exception:
            return False
    
    @staticmethod
    def validate_chain_continuity(blocks: List[Dict[str, Any]]) -> bool:
        """Validate chain continuity across blocks."""
        if not blocks:
            return True
        
        previous_hash = blocks[0]["previous_hash"]
        
        for block in blocks:
            if block["previous_hash"] != previous_hash:
                return False
            previous_hash = block["current_hash"]
        
        return True


# Global Guardian Ledger instance
_guardian_ledger: Optional[GuardianLedger] = None


def get_guardian_ledger() -> GuardianLedger:
    """Get the global Guardian Ledger instance."""
    global _guardian_ledger
    if _guardian_ledger is None:
        _guardian_ledger = GuardianLedger()
    return _guardian_ledger


def record_guardian_event(event_type: str,
                         user_id: str,
                         session_id: str,
                         source_ip: str,
                         user_agent: str,
                         action: str,
                         resource: str,
                         details: Dict[str, Any],
                         evidence_level: EvidenceLevel = EvidenceLevel.HIGH,
                         parent_event_id: Optional[str] = None) -> str:
    """
    Record an event in the Guardian Ledger with full integrity guarantees.
    
    This is the primary interface for recording events that require
    The Guardian's Mandate level of integrity.
    """
    ledger = get_guardian_ledger()
    return ledger.record_event(
        event_type=event_type,
        user_id=user_id,
        session_id=session_id,
        source_ip=source_ip,
        user_agent=user_agent,
        action=action,
        resource=resource,
        details=details,
        evidence_level=evidence_level,
        parent_event_id=parent_event_id
    )


def verify_guardian_integrity() -> Dict[str, Any]:
    """Verify the integrity of the entire Guardian Ledger."""
    ledger = get_guardian_ledger()
    return ledger.verify_integrity()


def export_guardian_forensic_data(output_path: str) -> str:
    """Export forensic data from the Guardian Ledger."""
    ledger = get_guardian_ledger()
    return ledger.export_forensic_data(output_path)


if __name__ == "__main__":
    # Example usage and testing
    print("The Guardian's Mandate: Digital Evidence Integrity Framework")
    print("=" * 60)
    
    # Initialize ledger
    ledger = GuardianLedger()
    
    # Record some test events
    event_id1 = ledger.record_event(
        event_type="data_access",
        user_id="test_user",
        session_id="session_123",
        source_ip="192.168.1.100",
        user_agent="GuardianTest/1.0",
        action="read",
        resource="/api/sensitive_data",
        details={"data_type": "PII", "access_method": "API"}
    )
    
    event_id2 = ledger.record_event(
        event_type="configuration_change",
        user_id="admin_user",
        session_id="session_456",
        source_ip="10.0.0.50",
        user_agent="GuardianAdmin/1.0",
        action="modify",
        resource="/config/security",
        details={"setting": "password_policy", "old_value": "weak", "new_value": "strong"},
        parent_event_id=event_id1
    )
    
    # Verify integrity
    integrity_result = ledger.verify_integrity()
    print(f"Integrity verification: {'PASSED' if integrity_result['verified'] else 'FAILED'}")
    print(f"Verified blocks: {integrity_result['verified_blocks']}/{integrity_result['total_blocks']}")
    
    # Export forensic data
    export_path = ledger.export_forensic_data("guardian_forensic_export.json")
    print(f"Forensic data exported to: {export_path}")
    
    # Get chain of custody
    chain = ledger.get_chain_of_custody(event_id2)
    print(f"Chain of custody for event {event_id2}: {len(chain)} events")