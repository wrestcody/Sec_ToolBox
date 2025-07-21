#!/usr/bin/env python3
"""
Guardians Armory: Secure GRC MCP Server
======================================

A secure Model Context Protocol (MCP) server for the GRC platform that:
- Follows security best practices
- Provides secure access to GRC controls and assessments
- Implements proper authentication and authorization
- Supports safe AI assistant interactions
- Maintains audit trails for all operations

Author: Guardians Forge
Mission: "To Create the Next Generation of Protectors"
"""

import asyncio
import json
import logging
import os
import sys
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib
import hmac
import secrets
import ssl
from contextlib import asynccontextmanager

# MCP imports
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
except ImportError:
    print("MCP library not found. Install with: pip install mcp")
    sys.exit(1)

# Import our GRC platform
sys.path.append(str(Path(__file__).parent.parent))
from simple_bidirectional_grc import SimpleBidirectionalGRC, SecurityControl

# Security configuration
SECURITY_CONFIG = {
    "max_requests_per_minute": 60,
    "max_concurrent_requests": 10,
    "session_timeout_minutes": 30,
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

class SecureGRCMCP:
    """Secure MCP server for GRC platform"""
    
    def __init__(self):
        self.grc_platform = SimpleBidirectionalGRC()
        self.sessions: Dict[str, MCPSession] = {}
        self.request_log: List[Dict[str, Any]] = []
        self.rate_limit_cache: Dict[str, List[datetime]] = {}
        
        # Security setup
        self.api_key = os.getenv("GRC_MCP_API_KEY", secrets.token_urlsafe(32))
        self.admin_token = os.getenv("GRC_MCP_ADMIN_TOKEN", secrets.token_urlsafe(32))
        
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
        self.server = Server("grc-mcp-server")
        self._setup_tools()
    
    def _setup_tools(self):
        """Setup MCP tools with security considerations"""
        
        @self.server.list_tools()
        async def handle_list_tools() -> ListToolsResult:
            """List available tools with security levels"""
            tools = [
                Tool(
                    name="grc_get_summary",
                    description="Get GRC control summary (read-only)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "session_id": {"type": "string", "description": "Session ID for authentication"}
                        },
                        "required": ["session_id"]
                    }
                ),
                Tool(
                    name="grc_list_controls", 
                    description="List all GRC controls (read-only)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "session_id": {"type": "string", "description": "Session ID for authentication"},
                            "framework": {"type": "string", "description": "Filter by framework (optional)"},
                            "status": {"type": "string", "description": "Filter by status (optional)"}
                        },
                        "required": ["session_id"]
                    }
                ),
                Tool(
                    name="grc_get_control_details",
                    description="Get detailed information about a specific control (read-only)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "session_id": {"type": "string", "description": "Session ID for authentication"},
                            "control_id": {"type": "string", "description": "Control ID to retrieve"}
                        },
                        "required": ["session_id", "control_id"]
                    }
                ),
                Tool(
                    name="grc_run_assessment",
                    description="Run assessment on control(s) (assessment level)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "session_id": {"type": "string", "description": "Session ID for authentication"},
                            "control_id": {"type": "string", "description": "Specific control ID (optional)"},
                            "reason": {"type": "string", "description": "Reason for assessment"}
                        },
                        "required": ["session_id", "reason"]
                    }
                ),
                Tool(
                    name="grc_generate_report",
                    description="Generate compliance report (read-only)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "session_id": {"type": "string", "description": "Session ID for authentication"},
                            "report_type": {"type": "string", "description": "Type of report to generate"},
                            "format": {"type": "string", "description": "Output format (json, html, pdf)"}
                        },
                        "required": ["session_id", "report_type"]
                    }
                ),
                Tool(
                    name="grc_authenticate",
                    description="Authenticate and get session ID",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "client_id": {"type": "string", "description": "Client identifier"},
                            "api_key": {"type": "string", "description": "API key for authentication"},
                            "security_level": {"type": "string", "description": "Requested security level"}
                        },
                        "required": ["client_id", "api_key", "security_level"]
                    }
                ),
                Tool(
                    name="grc_get_assessments",
                    description="Get recent assessments (read-only)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "session_id": {"type": "string", "description": "Session ID for authentication"},
                            "limit": {"type": "integer", "description": "Number of assessments to retrieve"}
                        },
                        "required": ["session_id"]
                    }
                )
            ]
            return ListToolsResult(tools=tools)
        
        @self.server.call_tool()
        async def handle_call_tool(name: str, arguments: Dict[str, Any]) -> CallToolResult:
            """Handle tool calls with security validation"""
            try:
                # Log the request
                self._log_request(name, arguments)
                
                # Rate limiting
                client_id = arguments.get("session_id", "unknown")
                if not self._check_rate_limit(client_id):
                    return CallToolResult(
                        content=[TextContent(type="text", text="Rate limit exceeded. Please wait before making more requests.")]
                    )
                
                # Route to appropriate handler
                if name == "grc_authenticate":
                    return await self._handle_authenticate(arguments)
                elif name == "grc_get_summary":
                    return await self._handle_get_summary(arguments)
                elif name == "grc_list_controls":
                    return await self._handle_list_controls(arguments)
                elif name == "grc_get_control_details":
                    return await self._handle_get_control_details(arguments)
                elif name == "grc_run_assessment":
                    return await self._handle_run_assessment(arguments)
                elif name == "grc_generate_report":
                    return await self._handle_generate_report(arguments)
                elif name == "grc_get_assessments":
                    return await self._handle_get_assessments(arguments)
                else:
                    return CallToolResult(
                        content=[TextContent(type="text", text=f"Unknown tool: {name}")]
                    )
                    
            except Exception as e:
                self.logger.error(f"Error in tool call {name}: {str(e)}")
                return CallToolResult(
                    content=[TextContent(type="text", text=f"Error: {str(e)}")]
                )
    
    def _log_request(self, tool_name: str, arguments: Dict[str, Any]):
        """Log request for audit trail"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "tool": tool_name,
            "arguments": {k: v for k, v in arguments.items() if k != "api_key"},
            "session_id": arguments.get("session_id", "none")
        }
        self.request_log.append(log_entry)
        
        # Keep only last 1000 requests
        if len(self.request_log) > 1000:
            self.request_log = self.request_log[-1000:]
    
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
            return None
        
        # Update last activity
        session.last_activity = datetime.now()
        session.request_count += 1
        
        # Check security level
        if required_level == SecurityLevel.ADMIN and session.security_level != SecurityLevel.ADMIN:
            return None
        elif required_level == SecurityLevel.ASSESSMENT and session.security_level == SecurityLevel.READ_ONLY:
            return None
        
        return session
    
    async def _handle_authenticate(self, arguments: Dict[str, Any]) -> CallToolResult:
        """Handle authentication"""
        client_id = arguments.get("client_id")
        api_key = arguments.get("api_key")
        security_level_str = arguments.get("security_level", "read_only")
        
        if not client_id or not api_key:
            return CallToolResult(
                content=[TextContent(type="text", text="Missing client_id or api_key")]
            )
        
        # Validate API key
        if api_key != self.api_key:
            return CallToolResult(
                content=[TextContent(type="text", text="Invalid API key")]
            )
        
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
        
        result = {
            "session_id": session_id,
            "security_level": security_level.value,
            "expires_at": (datetime.now() + timedelta(minutes=SECURITY_CONFIG["session_timeout_minutes"])).isoformat(),
            "allowed_operations": session.allowed_operations
        }
        
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(result, indent=2))]
        )
    
    async def _handle_get_summary(self, arguments: Dict[str, Any]) -> CallToolResult:
        """Handle get summary request"""
        session_id = arguments.get("session_id")
        session = self._validate_session(session_id)
        
        if not session:
            return CallToolResult(
                content=[TextContent(type="text", text="Invalid or expired session")]
            )
        
        summary = self.grc_platform.get_control_summary()
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(summary, indent=2))]
        )
    
    async def _handle_list_controls(self, arguments: Dict[str, Any]) -> CallToolResult:
        """Handle list controls request"""
        session_id = arguments.get("session_id")
        session = self._validate_session(session_id)
        
        if not session:
            return CallToolResult(
                content=[TextContent(type="text", text="Invalid or expired session")]
            )
        
        framework_filter = arguments.get("framework")
        status_filter = arguments.get("status")
        
        controls = []
        for control_id in self.grc_platform.controls.keys():
            control = self.grc_platform.get_control_details(control_id)
            
            # Apply filters
            if framework_filter and control["framework"] != framework_filter:
                continue
            if status_filter and control["status"] != status_filter:
                continue
            
            controls.append(control)
        
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(controls, indent=2))]
        )
    
    async def _handle_get_control_details(self, arguments: Dict[str, Any]) -> CallToolResult:
        """Handle get control details request"""
        session_id = arguments.get("session_id")
        control_id = arguments.get("control_id")
        
        session = self._validate_session(session_id)
        if not session:
            return CallToolResult(
                content=[TextContent(type="text", text="Invalid or expired session")]
            )
        
        if not control_id:
            return CallToolResult(
                content=[TextContent(type="text", text="Missing control_id")]
            )
        
        control = self.grc_platform.get_control_details(control_id)
        if not control:
            return CallToolResult(
                content=[TextContent(type="text", text=f"Control {control_id} not found")]
            )
        
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(control, indent=2))]
        )
    
    async def _handle_run_assessment(self, arguments: Dict[str, Any]) -> CallToolResult:
        """Handle run assessment request"""
        session_id = arguments.get("session_id")
        control_id = arguments.get("control_id")
        reason = arguments.get("reason", "MCP request")
        
        session = self._validate_session(session_id, SecurityLevel.ASSESSMENT)
        if not session:
            return CallToolResult(
                content=[TextContent(type="text", text="Invalid session or insufficient permissions")]
            )
        
        # Log assessment request
        self.logger.info(f"Assessment requested by {session.client_id} for control {control_id}: {reason}")
        
        result = self.grc_platform.run_assessment(control_id)
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(result, indent=2))]
        )
    
    async def _handle_generate_report(self, arguments: Dict[str, Any]) -> CallToolResult:
        """Handle generate report request"""
        session_id = arguments.get("session_id")
        report_type = arguments.get("report_type", "compliance")
        format_type = arguments.get("format", "json")
        
        session = self._validate_session(session_id)
        if not session:
            return CallToolResult(
                content=[TextContent(type="text", text="Invalid or expired session")]
            )
        
        result = self.grc_platform.generate_report(report_type, format_type)
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(result, indent=2))]
        )
    
    async def _handle_get_assessments(self, arguments: Dict[str, Any]) -> CallToolResult:
        """Handle get assessments request"""
        session_id = arguments.get("session_id")
        limit = arguments.get("limit", 10)
        
        session = self._validate_session(session_id)
        if not session:
            return CallToolResult(
                content=[TextContent(type="text", text="Invalid or expired session")]
            )
        
        assessments = self.grc_platform.assessments[-limit:] if self.grc_platform.assessments else []
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(assessments, indent=2))]
        )
    
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
    
    async def run(self):
        """Run the MCP server"""
        self.logger.info("Starting GRC MCP Server...")
        self.logger.info(f"Security level: {SECURITY_CONFIG}")
        
        # Start cleanup task
        async def cleanup_task():
            while True:
                await asyncio.sleep(300)  # Clean up every 5 minutes
                self.cleanup_expired_sessions()
        
        asyncio.create_task(cleanup_task())
        
        # Run the server
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                InitializationOptions(
                    server_name="grc-mcp-server",
                    server_version="1.0.0",
                    capabilities=self.server.get_capabilities(
                        notification_options=None,
                        experimental_capabilities=None,
                    ),
                ),
            )

async def main():
    """Main entry point"""
    server = SecureGRCMCP()
    await server.run()

if __name__ == "__main__":
    asyncio.run(main())