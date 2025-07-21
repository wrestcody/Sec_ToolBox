#!/usr/bin/env python3
"""
Guardian's Mandate Integration Framework

This module provides automated integration of The Guardian's Mandate principles
into any security tool, ensuring unassailable digital evidence integrity and
unbreakable chain of custody at scale.

Usage:
    from guardians_mandate_integration import GuardianTool, GuardianDecorator
    
    # Option 1: Inherit from GuardianTool
    class MySecurityTool(GuardianTool):
        def run_analysis(self, data):
            # Your tool logic here
            result = self.analyze_data(data)
            
            # Automatically records events with full integrity
            self.record_guardian_event(
                event_type="analysis_complete",
                action="data_analysis",
                resource="/analysis/data",
                details={"result": result}
            )
            return result
    
    # Option 2: Use decorator for existing tools
    @GuardianDecorator
    def existing_security_function(data):
        # Your existing function logic
        return analyze_data(data)
"""

import os
import sys
import inspect
import functools
from typing import Dict, List, Any, Optional, Callable, Union
from pathlib import Path
import importlib.util
import logging

# Import The Guardian's Mandate framework
try:
    from guardians_mandate import (
        GuardianLedger,
        EvidenceLevel,
        AuditEventType,
        record_guardian_event,
        verify_guardian_integrity,
        export_guardian_forensic_data
    )
    GUARDIAN_MANDATE_AVAILABLE = True
except ImportError:
    print("Warning: Guardian's Mandate framework not available.")
    GUARDIAN_MANDATE_AVAILABLE = False
    # Define fallback classes for when the framework is not available
    class EvidenceLevel:
        LOW = "low"
        MEDIUM = "medium"
        HIGH = "high"
        CRITICAL = "critical"
    
    class AuditEventType:
        USER_ACTION = "user_action"
        SYSTEM_EVENT = "system_event"
        SECURITY_EVENT = "security_event"
        DATA_ACCESS = "data_access"
        CONFIGURATION_CHANGE = "configuration_change"


class GuardianTool:
    """
    Base class for security tools that automatically implements
    The Guardian's Mandate principles.
    
    Any tool that inherits from this class automatically gets:
    - Cryptographic integrity for all operations
    - Immutable audit trails
    - Chain of custody tracking
    - Forensic export capabilities
    - Compliance alignment
    """
    
    def __init__(self, 
                 tool_name: str,
                 tool_version: str,
                 enable_guardian_mandate: bool = True,
                 ledger_path: Optional[str] = None,
                 evidence_level = None):
        # Set default evidence level if not provided
        if evidence_level is None:
            evidence_level = EvidenceLevel.HIGH if GUARDIAN_MANDATE_AVAILABLE else "high"
        """
        Initialize a Guardian Tool with automatic integrity guarantees.
        
        Args:
            tool_name: Name of the security tool
            tool_version: Version of the tool
            enable_guardian_mandate: Enable Guardian's Mandate features
            ledger_path: Custom path for the Guardian Ledger
            evidence_level: Default evidence level for this tool
        """
        self.tool_name = tool_name
        self.tool_version = tool_version
        self.enable_guardian_mandate = enable_guardian_mandate and GUARDIAN_MANDATE_AVAILABLE
        self.evidence_level = evidence_level
        
        # Initialize Guardian's Mandate components
        if self.enable_guardian_mandate:
            ledger_path = ledger_path or f"{tool_name.lower().replace(' ', '_')}_guardian_ledger"
            self.guardian_ledger = GuardianLedger(ledger_path=ledger_path)
            self.session_id = self._generate_session_id()
            
            # Record tool initialization
            self._record_tool_init()
        else:
            self.guardian_ledger = None
            self.session_id = None
        
        # Setup logging
        self._setup_logging()
    
    def _generate_session_id(self) -> str:
        """Generate a unique session ID for this tool run."""
        import uuid
        return str(uuid.uuid4())
    
    def _setup_logging(self):
        """Setup secure logging for the tool."""
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler(f"{self.tool_name.lower().replace(' ', '_')}.log")
            ]
        )
        self.logger = logging.getLogger(self.tool_name)
    
    def _record_tool_init(self):
        """Record tool initialization in Guardian Ledger."""
        if not self.enable_guardian_mandate:
            return
        
        self.record_guardian_event(
            event_type=AuditEventType.SYSTEM_EVENT.value,
            action="tool_initialization",
            resource=f"/tools/{self.tool_name}",
            details={
                "tool_name": self.tool_name,
                "tool_version": self.tool_version,
                "session_id": self.session_id,
                "evidence_level": self.evidence_level.value,
                "guardian_mandate_enabled": True
            },
            evidence_level=EvidenceLevel.CRITICAL
        )
    
    def record_guardian_event(self,
                            event_type: str,
                            action: str,
                            resource: str,
                            details: Dict[str, Any],
                            evidence_level: Optional[EvidenceLevel] = None,
                            parent_event_id: Optional[str] = None) -> Optional[str]:
        """
        Record an event in the Guardian Ledger with full integrity guarantees.
        
        Args:
            event_type: Type of audit event
            action: Action performed
            resource: Resource accessed/modified
            details: Event details
            evidence_level: Evidence integrity level (uses tool default if None)
            parent_event_id: Parent event ID for chain of custody
            
        Returns:
            Event ID if recorded, None otherwise
        """
        if not self.enable_guardian_mandate or not self.guardian_ledger:
            return None
        
        try:
            # Use tool's default evidence level if not specified
            if evidence_level is None:
                evidence_level = self.evidence_level
            
            # Extract user information from details or use defaults
            user_id = details.get('user_id', 'system')
            session_id = details.get('session_id', self.session_id)
            source_ip = details.get('source_ip', '127.0.0.1')
            user_agent = details.get('user_agent', f"{self.tool_name}/{self.tool_version}")
            
            # Add tool context to details
            details.update({
                'tool_name': self.tool_name,
                'tool_version': self.tool_version,
                'session_id': self.session_id,
                'guardian_mandate_enabled': True
            })
            
            event_id = self.guardian_ledger.record_event(
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
            
            self.logger.info(f"Recorded Guardian event: {event_id}")
            return event_id
            
        except Exception as e:
            self.logger.error(f"Failed to record Guardian event: {e}")
            return None
    
    def verify_integrity(self) -> Dict[str, Any]:
        """Verify the integrity of the Guardian Ledger."""
        if not self.enable_guardian_mandate or not self.guardian_ledger:
            return {"verified": False, "error": "Guardian's Mandate not enabled"}
        
        return self.guardian_ledger.verify_integrity()
    
    def export_forensic_data(self, output_path: Optional[str] = None) -> Optional[str]:
        """Export forensic data from the Guardian Ledger."""
        if not self.enable_guardian_mandate or not self.guardian_ledger:
            return None
        
        if output_path is None:
            output_path = f"guardian_forensic_{self.tool_name.lower().replace(' ', '_')}_{self.session_id}.json"
        
        return self.guardian_ledger.export_forensic_data(output_path)
    
    def get_chain_of_custody(self, event_id: str) -> List[Dict[str, Any]]:
        """Get the complete chain of custody for a specific event."""
        if not self.enable_guardian_mandate or not self.guardian_ledger:
            return []
        
        return self.guardian_ledger.get_chain_of_custody(event_id)
    
    def cleanup(self):
        """Cleanup resources and record tool completion."""
        if self.enable_guardian_mandate:
            self.record_guardian_event(
                event_type=AuditEventType.SYSTEM_EVENT.value,
                action="tool_completion",
                resource=f"/tools/{self.tool_name}",
                details={
                    "tool_name": self.tool_name,
                    "session_id": self.session_id,
                    "completion_status": "success"
                },
                evidence_level=EvidenceLevel.HIGH
            )


class GuardianDecorator:
    """
    Decorator that automatically applies The Guardian's Mandate to existing functions.
    
    Usage:
        @GuardianDecorator
        def my_security_function(data):
            return analyze_data(data)
    """
    
    def __init__(self, 
                 tool_name: Optional[str] = None,
                 evidence_level = None):
        # Set default evidence level if not provided
        if evidence_level is None:
            evidence_level = EvidenceLevel.HIGH if GUARDIAN_MANDATE_AVAILABLE else "high"
        """
        Initialize the Guardian Decorator.
        
        Args:
            tool_name: Name of the tool (auto-detected if None)
            evidence_level: Evidence integrity level
        """
        self.tool_name = tool_name
        self.evidence_level = evidence_level
    
    def __call__(self, func: Callable) -> Callable:
        """Apply Guardian's Mandate to the decorated function."""
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Get tool name from function if not provided
            tool_name = self.tool_name or func.__name__
            
            # Create Guardian Tool instance for this function call
            guardian_tool = GuardianTool(
                tool_name=tool_name,
                tool_version="1.0.0",
                evidence_level=self.evidence_level
            )
            
            try:
                # Record function call
                guardian_tool.record_guardian_event(
                    event_type=AuditEventType.USER_ACTION.value,
                    action="function_call",
                    resource=f"/functions/{func.__name__}",
                    details={
                        "function_name": func.__name__,
                        "args": str(args),
                        "kwargs": str(kwargs),
                        "call_timestamp": guardian_tool.session_id
                    },
                    evidence_level=self.evidence_level
                )
                
                # Execute the function
                result = func(*args, **kwargs)
                
                # Record successful completion
                guardian_tool.record_guardian_event(
                    event_type=AuditEventType.SYSTEM_EVENT.value,
                    action="function_completion",
                    resource=f"/functions/{func.__name__}",
                    details={
                        "function_name": func.__name__,
                        "result_type": type(result).__name__,
                        "success": True
                    },
                    evidence_level=self.evidence_level
                )
                
                return result
                
            except Exception as e:
                # Record error
                guardian_tool.record_guardian_event(
                    event_type=AuditEventType.SECURITY_EVENT.value,
                    action="function_error",
                    resource=f"/functions/{func.__name__}",
                    details={
                        "function_name": func.__name__,
                        "error": str(e),
                        "error_type": type(e).__name__,
                        "success": False
                    },
                    evidence_level=EvidenceLevel.CRITICAL
                )
                raise
            finally:
                guardian_tool.cleanup()
        
        return wrapper


class GuardianToolGenerator:
    """
    Generator for creating new security tools with Guardian's Mandate integration.
    """
    
    @staticmethod
    def create_tool_template(tool_name: str, 
                           tool_description: str,
                           output_dir: str = "tools") -> str:
        """
        Create a new security tool template with Guardian's Mandate integration.
        
        Args:
            tool_name: Name of the security tool
            tool_description: Description of the tool's purpose
            output_dir: Directory to create the tool in
            
        Returns:
            Path to the created tool
        """
        # Create tool directory
        tool_dir = Path(output_dir) / tool_name.lower().replace(' ', '_')
        tool_dir.mkdir(parents=True, exist_ok=True)
        
        # Create tool file
        tool_file = tool_dir / f"{tool_name.lower().replace(' ', '_')}.py"
        
        template = f'''#!/usr/bin/env python3
"""
{tool_name}

{tool_description}

This tool implements The Guardian's Mandate for unassailable digital evidence
integrity and unbreakable chain of custody.
"""

import argparse
import sys
from typing import Dict, List, Any, Optional

# Import Guardian's Mandate integration
from guardians_mandate_integration import GuardianTool, EvidenceLevel, AuditEventType


class {tool_name.replace(' ', '')}(GuardianTool):
    """
    {tool_name} with Guardian's Mandate integration.
    """
    
    def __init__(self, **kwargs):
        """Initialize the {tool_name}."""
        super().__init__(
            tool_name="{tool_name}",
            tool_version="1.0.0",
            evidence_level=EvidenceLevel.HIGH,
            **kwargs
        )
    
    def run_analysis(self, input_data: Any) -> Dict[str, Any]:
        """
        Run the main analysis with Guardian's Mandate integrity guarantees.
        
        Args:
            input_data: Input data for analysis
            
        Returns:
            Analysis results with integrity proofs
        """
        # Record analysis start
        self.record_guardian_event(
            event_type=AuditEventType.SYSTEM_EVENT.value,
            action="analysis_start",
            resource="/analysis/main",
            details={{
                "input_data_type": type(input_data).__name__,
                "analysis_type": "main_analysis"
            }},
            evidence_level=EvidenceLevel.CRITICAL
        )
        
        try:
            # TODO: Implement your analysis logic here
            result = self._perform_analysis(input_data)
            
            # Record successful completion
            self.record_guardian_event(
                event_type=AuditEventType.SYSTEM_EVENT.value,
                action="analysis_complete",
                resource="/analysis/main",
                details={{
                    "result_type": type(result).__name__,
                    "success": True
                }},
                evidence_level=EvidenceLevel.CRITICAL
            )
            
            return result
            
        except Exception as e:
            # Record error
            self.record_guardian_event(
                event_type=AuditEventType.SECURITY_EVENT.value,
                action="analysis_error",
                resource="/analysis/main",
                details={{
                    "error": str(e),
                    "error_type": type(e).__name__,
                    "success": False
                }},
                evidence_level=EvidenceLevel.CRITICAL
            )
            raise
    
    def _perform_analysis(self, input_data: Any) -> Dict[str, Any]:
        """
        Perform the actual analysis logic.
        
        Args:
            input_data: Input data for analysis
            
        Returns:
            Analysis results
        """
        # TODO: Implement your analysis logic here
        return {{
            "status": "success",
            "message": "Analysis completed",
            "data": input_data
        }}


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="{tool_description}",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--input',
        required=True,
        help='Input data for analysis'
    )
    
    parser.add_argument(
        '--output',
        help='Output file path'
    )
    
    parser.add_argument(
        '--disable-guardian-mandate',
        action='store_true',
        help='Disable Guardian\'s Mandate features'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s 1.0.0 (with Guardian\'s Mandate)'
    )
    
    args = parser.parse_args()
    
    # Initialize tool
    tool = {tool_name.replace(' ', '')}(
        enable_guardian_mandate=not args.disable_guardian_mandate
    )
    
    try:
        # Run analysis
        result = tool.run_analysis(args.input)
        
        # Output results
        if args.output:
            import json
            with open(args.output, 'w') as f:
                json.dump(result, f, indent=2)
            print(f"Results saved to {{args.output}}")
        else:
            print(json.dumps(result, indent=2))
        
        # Export forensic data if Guardian's Mandate is enabled
        if tool.enable_guardian_mandate:
            print("\\n🛡️  Guardian's Mandate: Digital Evidence Integrity")
            print("=" * 50)
            
            # Verify integrity
            integrity_result = tool.verify_integrity()
            if integrity_result['verified']:
                print("✅ Integrity verification: PASSED")
            else:
                print("❌ Integrity verification: FAILED")
            
            # Export forensic data
            export_path = tool.export_forensic_data()
            if export_path:
                print(f"✅ Forensic data exported to: {{export_path}}")
        
    finally:
        tool.cleanup()


if __name__ == '__main__':
    main()
'''
        
        with open(tool_file, 'w') as f:
            f.write(template)
        
        # Create requirements file
        requirements_file = tool_dir / "requirements.txt"
        with open(requirements_file, 'w') as f:
            f.write("# Guardian's Mandate requirements\n")
            f.write("cryptography>=41.0.0\n")
            f.write("pycryptodome>=3.19.0\n")
            f.write("\n# Tool-specific requirements\n")
            f.write("# Add your tool's dependencies here\n")
        
        # Create README
        readme_file = tool_dir / "README.md"
        with open(readme_file, 'w') as f:
            f.write(f"# {tool_name}\n\n")
            f.write(f"{tool_description}\n\n")
            f.write("## Guardian's Mandate Integration\n\n")
            f.write("This tool implements The Guardian's Mandate for unassailable digital evidence integrity.\n\n")
            f.write("## Usage\n\n")
            f.write(f"```bash\npython {tool_name.lower().replace(' ', '_')}.py --input <data> --output <file>\n```\n\n")
            f.write("## Features\n\n")
            f.write("- Cryptographic integrity for all operations\n")
            f.write("- Immutable audit trails\n")
            f.write("- Chain of custody tracking\n")
            f.write("- Forensic export capabilities\n")
            f.write("- Compliance alignment\n")
        
        return str(tool_file)


class GuardianComplianceChecker:
    """
    Checker for ensuring all tools in the repository comply with Guardian's Mandate.
    """
    
    @staticmethod
    def check_tool_compliance(tool_path: str) -> Dict[str, Any]:
        """
        Check if a tool complies with Guardian's Mandate requirements.
        
        Args:
            tool_path: Path to the tool to check
            
        Returns:
            Compliance check results
        """
        results = {
            "tool_path": tool_path,
            "compliant": False,
            "issues": [],
            "recommendations": []
        }
        
        try:
            with open(tool_path, 'r') as f:
                content = f.read()
            
            # Check for Guardian's Mandate integration
            if "GuardianTool" in content:
                results["compliant"] = True
                results["recommendations"].append("✅ Guardian's Mandate integration found")
            else:
                results["issues"].append("❌ No Guardian's Mandate integration found")
                results["recommendations"].append("Inherit from GuardianTool class")
            
            # Check for evidence recording
            if "record_guardian_event" in content:
                results["recommendations"].append("✅ Evidence recording found")
            else:
                results["issues"].append("❌ No evidence recording found")
                results["recommendations"].append("Add record_guardian_event calls")
            
            # Check for integrity verification
            if "verify_integrity" in content:
                results["recommendations"].append("✅ Integrity verification found")
            else:
                results["issues"].append("❌ No integrity verification found")
                results["recommendations"].append("Add verify_integrity calls")
            
            # Check for forensic export
            if "export_forensic_data" in content:
                results["recommendations"].append("✅ Forensic export found")
            else:
                results["issues"].append("❌ No forensic export found")
                results["recommendations"].append("Add export_forensic_data calls")
            
        except Exception as e:
            results["issues"].append(f"❌ Error checking tool: {e}")
        
        return results
    
    @staticmethod
    def check_repository_compliance(repo_path: str = ".") -> Dict[str, Any]:
        """
        Check compliance of all tools in the repository.
        
        Args:
            repo_path: Path to the repository root
            
        Returns:
            Repository compliance results
        """
        results = {
            "repository_path": repo_path,
            "total_tools": 0,
            "compliant_tools": 0,
            "non_compliant_tools": 0,
            "tool_results": []
        }
        
        # Find all Python files that might be tools
        tools_path = Path(repo_path) / "tools"
        if tools_path.exists():
            for py_file in tools_path.rglob("*.py"):
                if py_file.name != "__init__.py":
                    tool_result = GuardianComplianceChecker.check_tool_compliance(str(py_file))
                    results["tool_results"].append(tool_result)
                    results["total_tools"] += 1
                    
                    if tool_result["compliant"]:
                        results["compliant_tools"] += 1
                    else:
                        results["non_compliant_tools"] += 1
        
        return results


# Convenience functions for easy integration
def guardian_tool(tool_name: str, tool_version: str = "1.0.0"):
    """Decorator for creating Guardian Tools from existing classes."""
    def decorator(cls):
        # Add Guardian's Mandate methods to the class
        cls.guardian_ledger = None
        cls.session_id = None
        cls.enable_guardian_mandate = True
        
        # Store original __init__
        original_init = cls.__init__
        
        def guardian_init(self, *args, **kwargs):
            # Call original __init__
            original_init(self, *args, **kwargs)
            
            # Initialize Guardian's Mandate
            if self.enable_guardian_mandate and GUARDIAN_MANDATE_AVAILABLE:
                self.guardian_ledger = GuardianLedger(
                    ledger_path=f"{tool_name.lower().replace(' ', '_')}_guardian_ledger"
                )
                self.session_id = str(uuid.uuid4())
                
                # Record tool initialization
                self.record_guardian_event(
                    event_type=AuditEventType.SYSTEM_EVENT.value,
                    action="tool_initialization",
                    resource=f"/tools/{tool_name}",
                    details={
                        "tool_name": tool_name,
                        "tool_version": tool_version,
                        "session_id": self.session_id
                    },
                    evidence_level=EvidenceLevel.CRITICAL
                )
        
        cls.__init__ = guardian_init
        
        # Add Guardian's Mandate methods
        cls.record_guardian_event = GuardianTool.record_guardian_event
        cls.verify_integrity = GuardianTool.verify_integrity
        cls.export_forensic_data = GuardianTool.export_forensic_data
        cls.get_chain_of_custody = GuardianTool.get_chain_of_custody
        cls.cleanup = GuardianTool.cleanup
        
        return cls
    
    return decorator


if __name__ == "__main__":
    # Example usage and testing
    print("Guardian's Mandate Integration Framework")
    print("=" * 50)
    
    # Test tool generation
    print("\n1. Testing tool generation...")
    tool_path = GuardianToolGenerator.create_tool_template(
        "Network Security Scanner",
        "Scans network for security vulnerabilities with Guardian's Mandate integration"
    )
    print(f"✅ Tool template created: {tool_path}")
    
    # Test compliance checking
    print("\n2. Testing compliance checking...")
    compliance_results = GuardianComplianceChecker.check_repository_compliance()
    print(f"✅ Repository compliance check completed:")
    print(f"   Total tools: {compliance_results['total_tools']}")
    print(f"   Compliant: {compliance_results['compliant_tools']}")
    print(f"   Non-compliant: {compliance_results['non_compliant_tools']}")
    
    # Show detailed results
    for tool_result in compliance_results['tool_results']:
        print(f"\n   Tool: {tool_result['tool_path']}")
        print(f"   Compliant: {tool_result['compliant']}")
        if tool_result['issues']:
            print(f"   Issues: {', '.join(tool_result['issues'])}")
        if tool_result['recommendations']:
            print(f"   Recommendations: {', '.join(tool_result['recommendations'])}")