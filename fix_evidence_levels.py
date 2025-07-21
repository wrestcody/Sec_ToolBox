#!/usr/bin/env python3
"""
Fix EvidenceLevel.value issues in Guardian's Mandate tools.
"""

import os
import re

def fix_evidence_levels_in_file(file_path):
    """Fix EvidenceLevel.value issues in a file."""
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Fix AuditEventType.value
    content = re.sub(
        r'(\w+EventType\.\w+)\.value',
        r'\1.value if hasattr(\1, \'value\') else \1',
        content
    )
    
    # Fix EvidenceLevel.value
    content = re.sub(
        r'(EvidenceLevel\.\w+)\.value',
        r'\1.value if hasattr(\1, \'value\') else \1',
        content
    )
    
    # Fix EvidenceLevel without .value
    content = re.sub(
        r'evidence_level=EvidenceLevel\.(\w+)(?!\.value)',
        r'evidence_level=EvidenceLevel.\1.value if hasattr(EvidenceLevel.\1, \'value\') else EvidenceLevel.\1',
        content
    )
    
    with open(file_path, 'w') as f:
        f.write(content)
    
    print(f"Fixed {file_path}")

# Fix all tool files
tool_files = [
    "tools/network_security_scanner/network_security_scanner.py",
    "tools/file_integrity_monitor/file_integrity_monitor.py",
    "tools/security/log_analysis_tool/log_analysis_tool.py"
]

for file_path in tool_files:
    if os.path.exists(file_path):
        fix_evidence_levels_in_file(file_path)
    else:
        print(f"File not found: {file_path}")

print("Evidence level fixes completed!")