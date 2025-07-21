# The Guardian's Mandate: Digital Evidence Integrity Framework

## Overview

The Guardian's Mandate is a comprehensive framework for building systems with unassailable digital evidence integrity and unbreakable chain of custody. This framework ensures that all digital evidence, audit trails, and security events are cryptographically protected, immutable, and forensically sound.

## Core Principles

### 1. Cryptographic Tamper-Evident Logging & Data

- **Hashing**: Every critical event, data input, output, or state change generates cryptographic hashes (SHA-256+) that are linked to the data they protect
- **Timestamping**: All timestamps are accurate, verifiable, and cryptographically bound to the data/event
- **Immutability**: Append-only data structures and immutable storage solutions for all audit logs and security events

### 2. Automated & Granular Chain of Custody

- **Automated Audit Trails**: Every interaction with sensitive data is automatically logged with full context
- **Identity & Access Control**: Robust IAM policies with least privilege principle
- **Session Recording**: Technologies for recording privileged user sessions

### 3. Verifiable Ledger for Integrity

- **Blockchain-Style Verification**: Immutable, decentralized, and verifiable record of critical events
- **Cryptographic Chain**: Each event is cryptographically linked to the previous event
- **Integrity Checkpoints**: Regular integrity verification points for forensic purposes

### 4. Forensic Readiness & Auditability by Design

- **Exportability**: All logs, metadata, and cryptographic proofs can be exported in standardized formats
- **Validation Tools**: Independent verification tools for hashes, timestamps, and log sequences
- **Compliance Alignment**: Alignment with NIST, ISO 27001, SOC 2, and legal evidentiary standards

## Architecture

### GuardianLedger Class

The core component that implements the immutable, cryptographically-secured audit ledger:

```python
from guardians_mandate import GuardianLedger

# Initialize the ledger
ledger = GuardianLedger(
    ledger_path="guardian_ledger",
    master_key=None,  # Auto-generated if None
    enable_blockchain_verification=True
)

# Record an event with full integrity guarantees
event_id = ledger.record_event(
    event_type="data_access",
    user_id="user123",
    session_id="session456",
    source_ip="192.168.1.100",
    user_agent="GuardianApp/1.0",
    action="read",
    resource="/api/sensitive_data",
    details={"data_type": "PII", "access_method": "API"},
    evidence_level=EvidenceLevel.CRITICAL
)
```

### Evidence Levels

Different levels of evidence integrity based on the criticality of the data:

- **CRITICAL**: Highest integrity - cryptographic proofs required
- **HIGH**: High integrity - hashing and timestamping
- **MEDIUM**: Medium integrity - basic logging
- **LOW**: Low integrity - informational only

### Audit Event Types

Categorized event types for better organization and compliance:

- `DATA_ACCESS`: Access to sensitive data
- `DATA_MODIFICATION`: Changes to data
- `CONFIGURATION_CHANGE`: System configuration changes
- `SECURITY_EVENT`: Security-related events
- `SYSTEM_EVENT`: System-level events
- `USER_ACTION`: User-initiated actions
- `INTEGRITY_CHECK`: Integrity verification events
- `CHAIN_OF_CUSTODY`: Chain of custody events

## Implementation in IAM Anomaly Detector

The IAM Anomaly Detector has been enhanced with Guardian's Mandate integration:

### Features Added

1. **Cryptographic Integrity**: All analysis activities are cryptographically signed and verified
2. **Immutable Audit Trail**: Every anomaly detection event is recorded in the Guardian Ledger
3. **Chain of Custody**: Complete traceability of evidence from detection to reporting
4. **Forensic Export**: Standardized forensic data export with cryptographic proofs
5. **Compliance Alignment**: Enhanced compliance reporting for SOC2, ISO27001, NIST, and CIS

### Usage

```bash
# Run with Guardian's Mandate enabled (default)
python iam_anomaly_detector.py --log-file mock_cloudtrail_logs.json

# Run with Guardian's Mandate disabled
python iam_anomaly_detector.py --log-file mock_cloudtrail_logs.json --disable-guardian-mandate

# Export forensic data
python iam_anomaly_detector.py --log-file mock_cloudtrail_logs.json --output-format audit
```

### Output Features

When Guardian's Mandate is enabled, the tool provides:

1. **Integrity Verification**: Real-time verification of cryptographic integrity
2. **Chain of Custody Report**: Complete traceability of all findings
3. **Forensic Export**: Cryptographically signed forensic data export
4. **Compliance Status**: Clear indication of compliance readiness

## Cryptographic Implementation

### Hash Generation

```python
def _compute_hash(self, data: str) -> str:
    """Compute SHA-256 hash of data."""
    return hashlib.sha256(data.encode('utf-8')).hexdigest()
```

### Cryptographic Proof Creation

```python
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
    
    return CryptographicProof(
        data_hash=data_hash,
        timestamp=datetime.now(timezone.utc).isoformat(),
        nonce=nonce,
        signature=signature,
        public_key_fingerprint=self._get_public_key_fingerprint(),
        proof_type="sha256_hmac_rsa"
    )
```

### Integrity Verification

```python
def verify_integrity(self, start_sequence: int = 0, end_sequence: Optional[int] = None) -> Dict[str, Any]:
    """Verify the integrity of the entire ledger or a range of blocks."""
    verification_results = {
        "verified": True,
        "total_blocks": 0,
        "verified_blocks": 0,
        "errors": [],
        "chain_hashes": [],
        "timestamp_range": {"start": None, "end": None}
    }
    
    # Verify each block's cryptographic proof and chain continuity
    # ...
    
    return verification_results
```

## Forensic Export Format

The Guardian Ledger exports forensic data in a standardized format:

```json
{
  "export_metadata": {
    "export_timestamp": "2024-01-15T10:30:00Z",
    "tool_version": "1.0.0",
    "guardian_mandate_version": "1.0.0",
    "export_format": "guardian_forensic_v1"
  },
  "integrity_verification": {
    "verified": true,
    "total_blocks": 150,
    "verified_blocks": 150,
    "errors": [],
    "chain_hashes": ["hash1", "hash2", ...],
    "timestamp_range": {
      "start": "2024-01-01T00:00:00Z",
      "end": "2024-01-15T10:30:00Z"
    }
  },
  "blocks": [
    {
      "block_id": "block_00000001",
      "previous_hash": "0000000000000000000000000000000000000000000000000000000000000000",
      "current_hash": "abc123...",
      "timestamp": "2024-01-01T00:00:00Z",
      "data": {
        "event": {
          "event_id": "uuid-123",
          "timestamp": "2024-01-01T00:00:00Z",
          "event_type": "system_event",
          "user_id": "system",
          "session_id": "session-123",
          "source_ip": "127.0.0.1",
          "user_agent": "GuardianApp/1.0",
          "action": "analysis_session_start",
          "resource": "iam_anomaly_detector",
          "details": {...},
          "evidence_level": "critical",
          "cryptographic_proof": {...}
        }
      },
      "proof": {
        "data_hash": "def456...",
        "timestamp": "2024-01-01T00:00:00Z",
        "nonce": "nonce123",
        "signature": "signature123",
        "public_key_fingerprint": "fingerprint123",
        "proof_type": "sha256_hmac_rsa"
      }
    }
  ],
  "events": [...],
  "export_proof": {
    "data_hash": "ghi789...",
    "timestamp": "2024-01-15T10:30:00Z",
    "nonce": "nonce456",
    "signature": "signature456",
    "public_key_fingerprint": "fingerprint456",
    "proof_type": "sha256_hmac_rsa"
  }
}
```

## Compliance Integration

### SOC2 Compliance

The framework supports SOC2 compliance controls:

- **CC6.1**: Logical and physical access controls
- **CC6.2**: System access controls
- **CC6.3**: Data access controls
- **CC7.1**: System operation monitoring
- **CC7.2**: System change management
- **CC7.3**: System development and acquisition

### ISO27001 Compliance

ISO27001 controls supported:

- **A.9.2.1**: User registration and de-registration
- **A.9.2.2**: User access provisioning
- **A.9.2.3**: Access rights management
- **A.12.4.1**: Event logging
- **A.12.4.3**: Administrator and operator logs

### NIST Framework

NIST Cybersecurity Framework controls:

- **AC-2**: Account Management
- **AC-3**: Access Enforcement
- **AC-6**: Least Privilege
- **AU-2**: Audit Events
- **AU-3**: Content of Audit Records
- **AU-6**: Audit Review, Analysis, and Reporting

## Installation and Setup

### Prerequisites

```bash
# Install required dependencies
pip install -r guardians_mandate_requirements.txt
```

### Basic Usage

```python
from guardians_mandate import (
    GuardianLedger,
    EvidenceLevel,
    AuditEventType,
    record_guardian_event,
    verify_guardian_integrity,
    export_guardian_forensic_data
)

# Initialize the Guardian Ledger
ledger = GuardianLedger()

# Record an event
event_id = record_guardian_event(
    event_type="data_access",
    user_id="user123",
    session_id="session456",
    source_ip="192.168.1.100",
    user_agent="MyApp/1.0",
    action="read",
    resource="/api/data",
    details={"data_type": "sensitive"},
    evidence_level=EvidenceLevel.CRITICAL
)

# Verify integrity
integrity_result = verify_guardian_integrity()
print(f"Integrity verified: {integrity_result['verified']}")

# Export forensic data
export_path = export_guardian_forensic_data("forensic_export.json")
print(f"Forensic data exported to: {export_path}")
```

## Security Considerations

### Key Management

- Master keys are auto-generated using cryptographically secure random number generation
- Private keys are generated using RSA-2048 with proper padding
- Keys should be stored securely in production environments

### Data Protection

- All sensitive data is hashed and cryptographically signed
- Nonces are used to prevent replay attacks
- Timestamps are cryptographically bound to prevent tampering

### Audit Trail Protection

- Audit trails are immutable and append-only
- Each event is cryptographically linked to the previous event
- Integrity checkpoints are created regularly for forensic purposes

## Best Practices

### 1. Evidence Level Selection

Choose appropriate evidence levels based on data sensitivity:

- **CRITICAL**: Financial data, PII, security events
- **HIGH**: Configuration changes, access logs
- **MEDIUM**: System events, performance metrics
- **LOW**: Informational logs, debug data

### 2. Regular Integrity Verification

```python
# Verify integrity regularly
integrity_result = ledger.verify_integrity()
if not integrity_result['verified']:
    # Handle integrity failure
    raise SecurityException("Ledger integrity compromised")
```

### 3. Forensic Export Scheduling

```python
# Export forensic data regularly for compliance
export_path = ledger.export_forensic_data(f"forensic_export_{datetime.now().strftime('%Y%m%d')}.json")
```

### 4. Chain of Custody Maintenance

```python
# Maintain chain of custody for critical events
parent_event_id = ledger.record_event(...)
child_event_id = ledger.record_event(
    ...,
    parent_event_id=parent_event_id
)
```

## Troubleshooting

### Common Issues

1. **Import Error**: Guardian's Mandate framework not available
   - Solution: Install dependencies with `pip install -r guardians_mandate_requirements.txt`

2. **Integrity Verification Failed**
   - Check for file corruption or unauthorized modifications
   - Verify that the ledger files haven't been tampered with

3. **Performance Issues**
   - Consider using database backends for large-scale deployments
   - Implement batch processing for high-volume events

### Debug Mode

Enable debug logging for troubleshooting:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

ledger = GuardianLedger()
# Debug information will be logged
```

## Future Enhancements

### Planned Features

1. **Distributed Ledger**: Integration with blockchain networks for decentralized verification
2. **Trusted Timestamping**: RFC 3161 compliant timestamping authority integration
3. **Advanced Cryptography**: Post-quantum cryptography support
4. **Cloud Integration**: Native integration with AWS, Azure, and GCP services
5. **Real-time Monitoring**: Real-time integrity monitoring and alerting

### Extensibility

The framework is designed to be extensible:

```python
class CustomGuardianLedger(GuardianLedger):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Add custom functionality
    
    def custom_verification_method(self):
        # Implement custom verification logic
        pass
```

## Conclusion

The Guardian's Mandate framework provides a robust foundation for building systems with unassailable digital evidence integrity. By implementing cryptographic tamper-evident logging, automated chain of custody, and forensic-ready export capabilities, organizations can ensure their security tools meet the most stringent compliance and legal requirements.

The integration with the IAM Anomaly Detector demonstrates how existing security tools can be enhanced with these capabilities, providing a clear path for implementing The Guardian's Mandate across an organization's security infrastructure.