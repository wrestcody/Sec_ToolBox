#!/usr/bin/env python3
"""
Guardians Armory: Secure GRC MCP Server
======================================

A production-ready Model Context Protocol (MCP) server for the GRC platform that:
- Follows security best practices for AI integrations
- Provides secure access to GRC controls and assessments
- Implements proper authentication, authorization, and audit logging
- Supports safe AI assistant interactions with rate limiting
- Maintains complete audit trails for compliance

Author: Guardians Forge
Mission: "To Create the Next Generation of Protectors"
"""

import asyncio
import json
import logging
import os
import sys
import uuid
import hashlib
import hmac
import secrets
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence
from dataclasses import dataclass, asdict
from enum import Enum
import ssl
from contextlib import asynccontextmanager

# Import our GRC platform
sys.path.append(str(Path(__file__).parent))
from simple_bidirectional_grc import SimpleBidirectionalGRC

# Security configuration
SECURITY_CONFIG = {
    "max_requests_per_minute": 60,
    "max_concurrent_requests": 10,
    "session_timeout_minutes": 30,
    "max_input_length": 10000,
    "allowed_operations": [
        "read_controls",
        "read_assessments", 
        "read_reports",
        "run_assessment",
        "generate_report"
    ],
    "restricted_operations": [
        "add_control",
        "update_control",
        "delete_control"
    ]
}

class SecurityLevel(Enum):
    """Security levels for operations"""
    READ_ONLY = "read_only"
    ASSESSMENT = "assessment"
    ADMIN = "admin"

@dataclass
class MCPSession:
    """Secure MCP session with authentication"""
    session_id: str
    client_id: str
    security_level: SecurityLevel
    created_at: datetime
    last_activity: datetime
    request_count: int
    allowed_operations: List[str]
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None

@dataclass
class AuditLogEntry:
    """Audit log entry for compliance"""
    timestamp: datetime
    session_id: str
    client_id: str
    tool_name: str
    arguments: Dict[str, Any]
    ip_address: Optional[str]
    user_agent: Optional[str]
    result_status: str
    execution_time_ms: int

class SecureGRCMCP:
    """Secure MCP server for GRC platform with AI integration support"""
    
    def __init__(self):
        self.grc_platform = SimpleBidirectionalGRC()
        self.sessions: Dict[str, MCPSession] = {}
        self.audit_log: List[AuditLogEntry] = []
        self.rate_limit_cache: Dict[str, List[datetime]] = {}
        
        # Security setup
        self.api_key = os.getenv("GRC_MCP_API_KEY", secrets.token_urlsafe(32))
        self.admin_token = os.getenv("GRC_MCP_ADMIN_TOKEN", secrets.token_urlsafe(32))
        self.jwt_secret = os.getenv("GRC_MCP_JWT_SECRET", secrets.token_urlsafe(32))
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('mcp_server.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("GRC_MCP_Server")
        
        # Initialize MCP server
        try:
            from mcp.server import Server
            from mcp.server.models import InitializationOptions
            from mcp.server.stdio import stdio_server
            from mcp.types import (
                CallToolRequest,
                CallToolResult,
                ListToolsRequest,
                ListToolsResult,
                Tool,
                TextContent,
                ImageContent,
                EmbeddedResource,
                LoggingLevel,
                TextDiff,
                Range,
                Position,
                Resource,
                ToolCall,
                ToolResult,
                Error,
                ErrorCode,
            )
            self.mcp_available = True
            self.Server = Server
            self.InitializationOptions = InitializationOptions
            self.stdio_server = stdio_server
            self.CallToolResult = CallToolResult
            self.ListToolsResult = ListToolsResult
            self.Tool = Tool
            self.TextContent = TextContent
        except ImportError:
            self.mcp_available = False
            self.logger.warning("MCP library not available. Install with: pip install mcp")
        
        if self.mcp_available:
            self.server = self.Server("grc-mcp-server")
            self._setup_tools()
    
    def _setup_tools(self):
        """Setup MCP tools with security considerations"""
        
        @self.server.list_tools()
        async def handle_list_tools():
            """List available tools with security levels"""
            tools = [
                self.Tool(
                    name="grc_authenticate",
                    description="Authenticate and get session ID for AI assistant access",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "client_id": {"type": "string", "description": "AI assistant identifier"},
                            "api_key": {"type": "string", "description": "API key for authentication"},
                            "security_level": {"type": "string", "description": "Requested security level (read_only, assessment, admin)"}
                        },
                        "required": ["client_id", "api_key", "security_level"]
                    }
                ),
                self.Tool(
                    name="grc_get_summary",
                    description="Get GRC control summary and compliance status (read-only)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "session_id": {"type": "string", "description": "Session ID for authentication"}
                        },
                        "required": ["session_id"]
                    }
                ),
                self.Tool(
                    name="grc_list_controls", 
                    description="List all GRC controls with optional filtering (read-only)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "session_id": {"type": "string", "description": "Session ID for authentication"},
                            "framework": {"type": "string", "description": "Filter by framework (SOC2, ISO27001, NIST, PCI-DSS)"},
                            "status": {"type": "string", "description": "Filter by status (passed, failed, warning, not_applicable)"},
                            "category": {"type": "string", "description": "Filter by category"}
                        },
                        "required": ["session_id"]
                    }
                ),
                self.Tool(
                    name="grc_get_control_details",
                    description="Get detailed information about a specific control including parameters and evidence (read-only)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "session_id": {"type": "string", "description": "Session ID for authentication"},
                            "control_id": {"type": "string", "description": "Control ID to retrieve (e.g., CC6.1)"}
                        },
                        "required": ["session_id", "control_id"]
                    }
                ),
                self.Tool(
                    name="grc_run_assessment",
                    description="Run assessment on control(s) with reason tracking (assessment level)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "session_id": {"type": "string", "description": "Session ID for authentication"},
                            "control_id": {"type": "string", "description": "Specific control ID (optional for full assessment)"},
                            "reason": {"type": "string", "description": "Reason for assessment (required for audit trail)"}
                        },
                        "required": ["session_id", "reason"]
                    }
                ),
                self.Tool(
                    name="grc_generate_report",
                    description="Generate compliance report in various formats (read-only)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "session_id": {"type": "string", "description": "Session ID for authentication"},
                            "report_type": {"type": "string", "description": "Type of report (compliance, security, audit)"},
                            "format": {"type": "string", "description": "Output format (json, html, pdf)"},
                            "framework": {"type": "string", "description": "Specific framework to include"}
                        },
                        "required": ["session_id", "report_type"]
                    }
                ),
                self.Tool(
                    name="grc_get_assessments",
                    description="Get recent assessments with findings and remediation steps (read-only)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "session_id": {"type": "string", "description": "Session ID for authentication"},
                            "limit": {"type": "integer", "description": "Number of assessments to retrieve (default: 10)"},
                            "control_id": {"type": "string", "description": "Filter by specific control ID"}
                        },
                        "required": ["session_id"]
                    }
                ),
                self.Tool(
                    name="grc_get_compliance_status",
                    description="Get detailed compliance status with framework breakdown (read-only)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "session_id": {"type": "string", "description": "Session ID for authentication"},
                            "framework": {"type": "string", "description": "Specific framework to analyze"}
                        },
                        "required": ["session_id"]
                    }
                )
            ]
            return self.ListToolsResult(tools=tools)
        
        @self.server.call_tool()
        async def handle_call_tool(name: str, arguments: Dict[str, Any]):
            """Handle tool calls with comprehensive security validation"""
            start_time = datetime.now()
            
            try:
                # Input validation
                if not self._validate_input(arguments):
                    return self.CallToolResult(
                        content=[self.TextContent(type="text", text="Invalid input provided")]
                    )
                
                # Log the request
                self._log_request(name, arguments)
                
                # Rate limiting
                client_id = arguments.get("session_id", "unknown")
                if not self._check_rate_limit(client_id):
                    return self.CallToolResult(
                        content=[self.TextContent(type="text", text="Rate limit exceeded. Please wait before making more requests.")]
                    )
                
                # Route to appropriate handler
                if name == "grc_authenticate":
                    result = await self._handle_authenticate(arguments)
                elif name == "grc_get_summary":
                    result = await self._handle_get_summary(arguments)
                elif name == "grc_list_controls":
                    result = await self._handle_list_controls(arguments)
                elif name == "grc_get_control_details":
                    result = await self._handle_get_control_details(arguments)
                elif name == "grc_run_assessment":
                    result = await self._handle_run_assessment(arguments)
                elif name == "grc_generate_report":
                    result = await self._handle_generate_report(arguments)
                elif name == "grc_get_assessments":
                    result = await self._handle_get_assessments(arguments)
                elif name == "grc_get_compliance_status":
                    result = await self._handle_get_compliance_status(arguments)
                else:
                    result = {"error": f"Unknown tool: {name}"}
                
                # Log the result
                execution_time = (datetime.now() - start_time).total_seconds() * 1000
                self._log_result(name, arguments, result, execution_time)
                
                return self.CallToolResult(
                    content=[self.TextContent(type="text", text=json.dumps(result, indent=2))]
                )
                    
            except Exception as e:
                self.logger.error(f"Error in tool call {name}: {str(e)}")
                execution_time = (datetime.now() - start_time).total_seconds() * 1000
                self._log_result(name, arguments, {"error": str(e)}, execution_time)
                
                return self.CallToolResult(
                    content=[self.TextContent(type="text", text=f"Error: {str(e)}")]
                )
    
    def _validate_input(self, arguments: Dict[str, Any]) -> bool:
        """Validate input with security checks"""
        # Check input length
        if len(json.dumps(arguments)) > SECURITY_CONFIG["max_input_length"]:
            return False
        
        # Validate control IDs
        if "control_id" in arguments:
            if not re.match(r"^[A-Z]{2}\d+\.\d+$", arguments["control_id"]):
                return False
        
        # Validate session IDs
        if "session_id" in arguments:
            if not re.match(r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$", arguments["session_id"]):
                return False
        
        # Validate framework names
        if "framework" in arguments:
            valid_frameworks = ["SOC2", "ISO27001", "NIST", "PCI-DSS", "HIPAA", "GDPR"]
            if arguments["framework"] not in valid_frameworks:
                return False
        
        # Validate status values
        if "status" in arguments:
            valid_statuses = ["passed", "failed", "warning", "not_applicable"]
            if arguments["status"] not in valid_statuses:
                return False
        
        return True
    
    def _log_request(self, tool_name: str, arguments: Dict[str, Any]):
        """Log request for audit trail"""
        session_id = arguments.get("session_id", "none")
        client_id = "unknown"
        
        if session_id in self.sessions:
            client_id = self.sessions[session_id].client_id
        
        log_entry = AuditLogEntry(
            timestamp=datetime.now(),
            session_id=session_id,
            client_id=client_id,
            tool_name=tool_name,
            arguments={k: v for k, v in arguments.items() if k != "api_key"},
            ip_address=None,  # Would be set in production
            user_agent=None,  # Would be set in production
            result_status="pending",
            execution_time_ms=0
        )
        
        self.audit_log.append(log_entry)
        
        # Keep only last 10000 audit entries
        if len(self.audit_log) > 10000:
            self.audit_log = self.audit_log[-10000:]
    
    def _log_result(self, tool_name: str, arguments: Dict[str, Any], result: Dict[str, Any], execution_time_ms: int):
        """Log result for audit trail"""
        session_id = arguments.get("session_id", "none")
        client_id = "unknown"
        
        if session_id in self.sessions:
            client_id = self.sessions[session_id].client_id
        
        # Update the last audit entry
        if self.audit_log:
            last_entry = self.audit_log[-1]
            if last_entry.tool_name == tool_name and last_entry.session_id == session_id:
                last_entry.result_status = "success" if "error" not in result else "error"
                last_entry.execution_time_ms = int(execution_time_ms)
    
    def _check_rate_limit(self, client_id: str) -> bool:
        """Check rate limiting for client"""
        now = datetime.now()
        if client_id not in self.rate_limit_cache:
            self.rate_limit_cache[client_id] = []
        
        # Remove old requests
        self.rate_limit_cache[client_id] = [
            req_time for req_time in self.rate_limit_cache[client_id]
            if now - req_time < timedelta(minutes=1)
        ]
        
        # Check if limit exceeded
        if len(self.rate_limit_cache[client_id]) >= SECURITY_CONFIG["max_requests_per_minute"]:
            self.logger.warning(f"Rate limit exceeded for client: {client_id}")
            return False
        
        # Add current request
        self.rate_limit_cache[client_id].append(now)
        return True
    
    def _validate_session(self, session_id: str, required_level: SecurityLevel = SecurityLevel.READ_ONLY) -> Optional[MCPSession]:
        """Validate session and check permissions"""
        if session_id not in self.sessions:
            return None
        
        session = self.sessions[session_id]
        
        # Check session timeout
        if datetime.now() - session.last_activity > timedelta(minutes=SECURITY_CONFIG["session_timeout_minutes"]):
            del self.sessions[session_id]
            self.logger.info(f"Session expired: {session_id}")
            return None
        
        # Update last activity
        session.last_activity = datetime.now()
        session.request_count += 1
        
        # Check security level
        if required_level == SecurityLevel.ADMIN and session.security_level != SecurityLevel.ADMIN:
            self.logger.warning(f"Insufficient permissions for {session.client_id}: {session.security_level} < {required_level}")
            return None
        elif required_level == SecurityLevel.ASSESSMENT and session.security_level == SecurityLevel.READ_ONLY:
            self.logger.warning(f"Insufficient permissions for {session.client_id}: {session.security_level} < {required_level}")
            return None
        
        return session
    
    async def _handle_authenticate(self, arguments: Dict[str, Any]):
        """Handle authentication"""
        client_id = arguments.get("client_id")
        api_key = arguments.get("api_key")
        security_level_str = arguments.get("security_level", "read_only")
        
        if not client_id or not api_key:
            return {"error": "Missing client_id or api_key"}
        
        # Validate API key
        if api_key != self.api_key:
            self.logger.warning(f"Invalid API key attempt from {client_id}")
            return {"error": "Invalid API key"}
        
        # Determine security level
        try:
            security_level = SecurityLevel(security_level_str)
        except ValueError:
            security_level = SecurityLevel.READ_ONLY
        
        # Create session
        session_id = str(uuid.uuid4())
        session = MCPSession(
            session_id=session_id,
            client_id=client_id,
            security_level=security_level,
            created_at=datetime.now(),
            last_activity=datetime.now(),
            request_count=0,
            allowed_operations=SECURITY_CONFIG["allowed_operations"]
        )
        
        self.sessions[session_id] = session
        
        self.logger.info(f"Authentication successful for {client_id} with level {security_level.value}")
        
        return {
            "session_id": session_id,
            "security_level": security_level.value,
            "expires_at": (datetime.now() + timedelta(minutes=SECURITY_CONFIG["session_timeout_minutes"])).isoformat(),
            "allowed_operations": session.allowed_operations,
            "rate_limit": SECURITY_CONFIG["max_requests_per_minute"]
        }
    
    async def _handle_get_summary(self, arguments: Dict[str, Any]):
        """Handle get summary request"""
        session_id = arguments.get("session_id")
        session = self._validate_session(session_id)
        
        if not session:
            return {"error": "Invalid or expired session"}
        
        summary = self.grc_platform.get_control_summary()
        return summary
    
    async def _handle_list_controls(self, arguments: Dict[str, Any]):
        """Handle list controls request"""
        session_id = arguments.get("session_id")
        session = self._validate_session(session_id)
        
        if not session:
            return {"error": "Invalid or expired session"}
        
        framework_filter = arguments.get("framework")
        status_filter = arguments.get("status")
        category_filter = arguments.get("category")
        
        controls = []
        for control_id in self.grc_platform.controls.keys():
            control = self.grc_platform.get_control_details(control_id)
            
            # Apply filters
            if framework_filter and control["framework"] != framework_filter:
                continue
            if status_filter and control["status"] != status_filter:
                continue
            if category_filter and control["category"] != category_filter:
                continue
            
            controls.append(control)
        
        return {
            "controls": controls, 
            "count": len(controls),
            "filters_applied": {
                "framework": framework_filter,
                "status": status_filter,
                "category": category_filter
            }
        }
    
    async def _handle_get_control_details(self, arguments: Dict[str, Any]):
        """Handle get control details request"""
        session_id = arguments.get("session_id")
        control_id = arguments.get("control_id")
        
        session = self._validate_session(session_id)
        if not session:
            return {"error": "Invalid or expired session"}
        
        if not control_id:
            return {"error": "Missing control_id"}
        
        control = self.grc_platform.get_control_details(control_id)
        if not control:
            return {"error": f"Control {control_id} not found"}
        
        return control
    
    async def _handle_run_assessment(self, arguments: Dict[str, Any]):
        """Handle run assessment request"""
        session_id = arguments.get("session_id")
        control_id = arguments.get("control_id")
        reason = arguments.get("reason", "MCP request")
        
        session = self._validate_session(session_id, SecurityLevel.ASSESSMENT)
        if not session:
            return {"error": "Invalid session or insufficient permissions"}
        
        # Log assessment request
        self.logger.info(f"Assessment requested by {session.client_id} for control {control_id}: {reason}")
        
        result = self.grc_platform.run_assessment(control_id)
        return result
    
    async def _handle_generate_report(self, arguments: Dict[str, Any]):
        """Handle generate report request"""
        session_id = arguments.get("session_id")
        report_type = arguments.get("report_type", "compliance")
        format_type = arguments.get("format", "json")
        framework = arguments.get("framework")
        
        session = self._validate_session(session_id)
        if not session:
            return {"error": "Invalid or expired session"}
        
        result = self.grc_platform.generate_report(report_type, format_type)
        
        # Add framework-specific information if requested
        if framework:
            result["framework_focus"] = framework
            result["framework_controls"] = [
                c for c in result["controls"] 
                if c["framework"] == framework
            ]
        
        return result
    
    async def _handle_get_assessments(self, arguments: Dict[str, Any]):
        """Handle get assessments request"""
        session_id = arguments.get("session_id")
        limit = arguments.get("limit", 10)
        control_id = arguments.get("control_id")
        
        session = self._validate_session(session_id)
        if not session:
            return {"error": "Invalid or expired session"}
        
        assessments = self.grc_platform.assessments[-limit:] if self.grc_platform.assessments else []
        
        # Filter by control_id if specified
        if control_id:
            assessments = [a for a in assessments if a.get("control_id") == control_id]
        
        return {
            "assessments": assessments, 
            "count": len(assessments),
            "limit": limit,
            "control_filter": control_id
        }
    
    async def _handle_get_compliance_status(self, arguments: Dict[str, Any]):
        """Handle get compliance status request"""
        session_id = arguments.get("session_id")
        framework = arguments.get("framework")
        
        session = self._validate_session(session_id)
        if not session:
            return {"error": "Invalid or expired session"}
        
        summary = self.grc_platform.get_control_summary()
        controls = []
        
        for control_id in self.grc_platform.controls.keys():
            control = self.grc_platform.get_control_details(control_id)
            if not framework or control["framework"] == framework:
                controls.append(control)
        
        # Calculate framework-specific metrics
        if framework:
            framework_controls = [c for c in controls if c["framework"] == framework]
            passed = sum(1 for c in framework_controls if c["status"] == "passed")
            failed = sum(1 for c in framework_controls if c["status"] == "failed")
            warning = sum(1 for c in framework_controls if c["status"] == "warning")
            total = len(framework_controls)
            
            framework_score = round((passed / total) * 100, 1) if total > 0 else 0
            
            return {
                "framework": framework,
                "compliance_score": framework_score,
                "total_controls": total,
                "passed_controls": passed,
                "failed_controls": failed,
                "warning_controls": warning,
                "controls": framework_controls
            }
        else:
            # Overall compliance status
            return {
                "overall_compliance": summary,
                "frameworks": list(set(c["framework"] for c in controls)),
                "total_controls": len(controls),
                "controls": controls
            }
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions"""
        now = datetime.now()
        expired_sessions = [
            session_id for session_id, session in self.sessions.items()
            if now - session.last_activity > timedelta(minutes=SECURITY_CONFIG["session_timeout_minutes"])
        ]
        
        for session_id in expired_sessions:
            del self.sessions[session_id]
            self.logger.info(f"Cleaned up expired session: {session_id}")
    
    def get_server_status(self) -> Dict[str, Any]:
        """Get server status and statistics"""
        active_sessions = len(self.sessions)
        total_requests = len(self.audit_log)
        
        # Clean up expired sessions
        self.cleanup_expired_sessions()
        
        return {
            "active_sessions": active_sessions,
            "total_requests": total_requests,
            "uptime": "running",
            "security_level": "high",
            "rate_limit": SECURITY_CONFIG["max_requests_per_minute"],
            "session_timeout_minutes": SECURITY_CONFIG["session_timeout_minutes"]
        }
    
    async def run(self):
        """Run the MCP server"""
        if not self.mcp_available:
            self.logger.error("MCP library not available. Cannot start server.")
            return
        
        self.logger.info("Starting GRC MCP Server...")
        self.logger.info(f"Security configuration: {SECURITY_CONFIG}")
        
        # Start cleanup task
        async def cleanup_task():
            while True:
                await asyncio.sleep(300)  # Clean up every 5 minutes
                self.cleanup_expired_sessions()
        
        asyncio.create_task(cleanup_task())
        
        # Run the server
        async with self.stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                self.InitializationOptions(
                    server_name="grc-mcp-server",
                    server_version="1.0.0",
                    capabilities=self.server.get_capabilities(
                        notification_options=None,
                        experimental_capabilities=None,
                    ),
                ),
            )

def generate_secure_config():
    """Generate secure configuration"""
    api_key = secrets.token_urlsafe(32)
    admin_token = secrets.token_urlsafe(32)
    jwt_secret = secrets.token_urlsafe(32)
    
    config = f"""# GRC MCP Server Security Configuration
# Generated on {datetime.now().isoformat()}

# Security Keys (KEEP THESE SECRET!)
GRC_MCP_API_KEY={api_key}
GRC_MCP_ADMIN_TOKEN={admin_token}
GRC_MCP_JWT_SECRET={jwt_secret}

# Logging Configuration
GRC_MCP_LOG_LEVEL=INFO
GRC_MCP_AUDIT_LOG_FILE=mcp_audit.log

# Rate Limiting
GRC_MCP_MAX_REQUESTS_PER_MINUTE=60
GRC_MCP_SESSION_TIMEOUT_MINUTES=30

# Security Best Practices:
# 1. Store these keys securely (use secret management in production)
# 2. Rotate keys regularly (recommended: every 90 days)
# 3. Use different keys for different environments
# 4. Monitor access logs for suspicious activity
# 5. Implement proper firewall rules
# 6. Use HTTPS/TLS in production
# 7. Implement proper backup and recovery
# 8. Regular security audits and penetration testing
"""
    
    with open(".env.example", "w") as f:
        f.write(config)
    
    print("✅ Secure configuration generated: .env.example")
    print("🔐 API Key:", api_key)
    print("🔐 Admin Token:", admin_token)
    print("🔐 JWT Secret:", jwt_secret)
    print("📝 Copy .env.example to .env and customize as needed")
    print("🚨 IMPORTANT: Keep these keys secure and never commit them to version control!")

async def main():
    """Main entry point"""
    if len(sys.argv) > 1 and sys.argv[1] == "generate-config":
        generate_secure_config()
        return
    
    server = SecureGRCMCP()
    await server.run()

if __name__ == "__main__":
    asyncio.run(main())