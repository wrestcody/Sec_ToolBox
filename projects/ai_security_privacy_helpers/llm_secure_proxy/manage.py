#!/usr/bin/env python3
"""
Management Script for Secure LLM Proxy
Enterprise Authentication and Administration

This script provides command-line tools for managing users, API keys,
and system administration tasks.
"""

import os
import sys
import argparse
import getpass
from datetime import datetime, timezone
from typing import Optional

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from authentication import (
    auth_service, UserRole, Permission, AuthenticationError, AuthorizationError
)

def create_admin(args):
    """Create an admin user."""
    print("Creating admin user...")
    
    username = args.username or input("Username: ")
    email = args.email or input("Email: ")
    
    # Get password securely
    while True:
        password = getpass.getpass("Password: ")
        confirm_password = getpass.getpass("Confirm password: ")
        
        if password == confirm_password:
            break
        else:
            print("Passwords do not match. Please try again.")
    
    try:
        user = auth_service.create_admin_user(username, email, password)
        print(f"✅ Admin user '{username}' created successfully!")
        print(f"   User ID: {user.id}")
        print(f"   Email: {user.email}")
        print(f"   Role: {user.role.value}")
        print(f"   Created: {user.created_at}")
        return True
    except AuthenticationError as e:
        print(f"❌ Error creating admin user: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

def create_user(args):
    """Create a regular user."""
    print("Creating user...")
    
    username = args.username or input("Username: ")
    email = args.email or input("Email: ")
    
    # Get role
    role_choices = [role.value for role in UserRole]
    role = args.role or input(f"Role ({', '.join(role_choices)}): ")
    
    if role not in role_choices:
        print(f"❌ Invalid role. Must be one of: {', '.join(role_choices)}")
        return False
    
    # Get password securely
    while True:
        password = getpass.getpass("Password: ")
        confirm_password = getpass.getpass("Confirm password: ")
        
        if password == confirm_password:
            break
        else:
            print("Passwords do not match. Please try again.")
    
    # MFA setup
    mfa_enabled = args.mfa if args.mfa is not None else input("Enable MFA? (y/n): ").lower() == 'y'
    
    try:
        user = auth_service.user_manager.create_user(
            username, email, password, UserRole(role), mfa_enabled
        )
        print(f"✅ User '{username}' created successfully!")
        print(f"   User ID: {user.id}")
        print(f"   Email: {user.email}")
        print(f"   Role: {user.role.value}")
        print(f"   MFA Enabled: {user.mfa_enabled}")
        if user.mfa_enabled and user.mfa_secret:
            print(f"   MFA Secret: {user.mfa_secret}")
        print(f"   Created: {user.created_at}")
        return True
    except AuthenticationError as e:
        print(f"❌ Error creating user: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

def list_users(args):
    """List all users."""
    try:
        # Get all users from database
        rows = auth_service.db_manager.execute_query("SELECT * FROM users ORDER BY created_at DESC")
        
        if not rows:
            print("No users found.")
            return True
        
        print(f"Found {len(rows)} users:")
        print("-" * 80)
        print(f"{'Username':<15} {'Email':<25} {'Role':<10} {'Status':<8} {'MFA':<5} {'Created':<20}")
        print("-" * 80)
        
        for row in rows:
            status = "Active" if row['is_active'] else "Inactive"
            if row['is_locked']:
                status = "Locked"
            
            mfa_status = "Yes" if row['mfa_enabled'] else "No"
            created = datetime.fromisoformat(row['created_at']).strftime("%Y-%m-%d %H:%M")
            
            print(f"{row['username']:<15} {row['email']:<25} {row['role']:<10} {status:<8} {mfa_status:<5} {created:<20}")
        
        return True
    except Exception as e:
        print(f"❌ Error listing users: {e}")
        return False

def create_api_key(args):
    """Create an API key for a user."""
    print("Creating API key...")
    
    username = args.username or input("Username: ")
    name = args.name or input("API Key Name: ")
    
    # Get user
    user = auth_service.user_manager.get_user_by_username(username)
    if not user:
        print(f"❌ User '{username}' not found")
        return False
    
    # Get permissions
    if args.permissions:
        permissions = [Permission(p) for p in args.permissions.split(',')]
    else:
        # Use default permissions for user role
        permissions = None
    
    try:
        api_key, api_key_obj = auth_service.api_key_manager.create_api_key(
            user.id, name, permissions
        )
        
        print(f"✅ API key created successfully!")
        print(f"   Name: {api_key_obj.name}")
        print(f"   User: {username}")
        print(f"   Key: {api_key}")
        print(f"   Permissions: {[p.value for p in api_key_obj.permissions]}")
        print(f"   Expires: {api_key_obj.expires_at}")
        print(f"   Created: {api_key_obj.created_at}")
        
        print("\n⚠️  IMPORTANT: Save this API key securely. It won't be shown again!")
        
        return True
    except AuthenticationError as e:
        print(f"❌ Error creating API key: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

def list_api_keys(args):
    """List API keys for a user."""
    username = args.username or input("Username: ")
    
    # Get user
    user = auth_service.user_manager.get_user_by_username(username)
    if not user:
        print(f"❌ User '{username}' not found")
        return False
    
    try:
        api_keys = auth_service.api_key_manager.get_user_api_keys(user.id)
        
        if not api_keys:
            print(f"No API keys found for user '{username}'")
            return True
        
        print(f"API keys for user '{username}':")
        print("-" * 80)
        print(f"{'Name':<20} {'Status':<8} {'Created':<20} {'Expires':<20} {'Usage':<8}")
        print("-" * 80)
        
        for key in api_keys:
            status = "Active" if key.is_active else "Revoked"
            created = datetime.fromisoformat(key.created_at).strftime("%Y-%m-%d %H:%M")
            expires = datetime.fromisoformat(key.expires_at).strftime("%Y-%m-%d %H:%M") if key.expires_at else "Never"
            
            print(f"{key.name:<20} {status:<8} {created:<20} {expires:<20} {key.usage_count:<8}")
        
        return True
    except Exception as e:
        print(f"❌ Error listing API keys: {e}")
        return False

def revoke_api_key(args):
    """Revoke an API key."""
    username = args.username or input("Username: ")
    key_id = args.key_id or input("API Key ID: ")
    
    # Get user
    user = auth_service.user_manager.get_user_by_username(username)
    if not user:
        print(f"❌ User '{username}' not found")
        return False
    
    try:
        success = auth_service.api_key_manager.revoke_api_key(key_id, user.id)
        if success:
            print(f"✅ API key '{key_id}' revoked successfully!")
            return True
        else:
            print(f"❌ Failed to revoke API key '{key_id}'")
            return False
    except AuthenticationError as e:
        print(f"❌ Error revoking API key: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

def change_password(args):
    """Change user password."""
    username = args.username or input("Username: ")
    
    # Get user
    user = auth_service.user_manager.get_user_by_username(username)
    if not user:
        print(f"❌ User '{username}' not found")
        return False
    
    # Get old password
    old_password = getpass.getpass("Current password: ")
    
    # Get new password
    while True:
        new_password = getpass.getpass("New password: ")
        confirm_password = getpass.getpass("Confirm new password: ")
        
        if new_password == confirm_password:
            break
        else:
            print("Passwords do not match. Please try again.")
    
    try:
        success = auth_service.user_manager.change_password(user.id, old_password, new_password)
        if success:
            print(f"✅ Password changed successfully for user '{username}'!")
            return True
        else:
            print(f"❌ Failed to change password for user '{username}'")
            return False
    except AuthenticationError as e:
        print(f"❌ Error changing password: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

def reset_password(args):
    """Reset user password (admin only)."""
    username = args.username or input("Username: ")
    
    # Get user
    user = auth_service.user_manager.get_user_by_username(username)
    if not user:
        print(f"❌ User '{username}' not found")
        return False
    
    # Get new password
    while True:
        new_password = getpass.getpass("New password: ")
        confirm_password = getpass.getpass("Confirm new password: ")
        
        if new_password == confirm_password:
            break
        else:
            print("Passwords do not match. Please try again.")
    
    try:
        # Hash new password directly (bypass old password check)
        import bcrypt
        new_password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Update password
        auth_service.db_manager.execute_update(
            "UPDATE users SET password_hash = ?, updated_at = ?, failed_attempts = 0, is_locked = FALSE WHERE id = ?",
            (new_password_hash, datetime.now(timezone.utc).isoformat(), user.id)
        )
        
        print(f"✅ Password reset successfully for user '{username}'!")
        return True
    except Exception as e:
        print(f"❌ Error resetting password: {e}")
        return False

def lock_user(args):
    """Lock a user account."""
    username = args.username or input("Username: ")
    
    # Get user
    user = auth_service.user_manager.get_user_by_username(username)
    if not user:
        print(f"❌ User '{username}' not found")
        return False
    
    try:
        auth_service.db_manager.execute_update(
            "UPDATE users SET is_locked = TRUE, updated_at = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), user.id)
        )
        
        print(f"✅ User '{username}' locked successfully!")
        return True
    except Exception as e:
        print(f"❌ Error locking user: {e}")
        return False

def unlock_user(args):
    """Unlock a user account."""
    username = args.username or input("Username: ")
    
    # Get user
    user = auth_service.user_manager.get_user_by_username(username)
    if not user:
        print(f"❌ User '{username}' not found")
        return False
    
    try:
        auth_service.db_manager.execute_update(
            "UPDATE users SET is_locked = FALSE, failed_attempts = 0, updated_at = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), user.id)
        )
        
        print(f"✅ User '{username}' unlocked successfully!")
        return True
    except Exception as e:
        print(f"❌ Error unlocking user: {e}")
        return False

def show_auth_events(args):
    """Show recent authentication events."""
    try:
        limit = args.limit or 50
        events = auth_service.event_manager.get_recent_events(limit)
        
        if not events:
            print("No authentication events found.")
            return True
        
        print(f"Recent authentication events (last {len(events)}):")
        print("-" * 100)
        print(f"{'Timestamp':<20} {'Event':<20} {'User':<15} {'Success':<8} {'IP':<15} {'Details':<20}")
        print("-" * 100)
        
        for event in events:
            timestamp = datetime.fromisoformat(event.timestamp).strftime("%Y-%m-%d %H:%M:%S")
            user = event.user_id[:15] if event.user_id else "N/A"
            success = "Yes" if event.success else "No"
            ip = event.ip_address[:15]
            details = str(event.details)[:20] + "..." if len(str(event.details)) > 20 else str(event.details)
            
            print(f"{timestamp:<20} {event.event_type:<20} {user:<15} {success:<8} {ip:<15} {details:<20}")
        
        return True
    except Exception as e:
        print(f"❌ Error showing auth events: {e}")
        return False

def cleanup_sessions(args):
    """Clean up expired sessions."""
    try:
        auth_service.cleanup_sessions()
        print("✅ Expired sessions cleaned up successfully!")
        return True
    except Exception as e:
        print(f"❌ Error cleaning up sessions: {e}")
        return False

def show_system_status(args):
    """Show system status and statistics."""
    try:
        # Get user count
        user_rows = auth_service.db_manager.execute_query("SELECT COUNT(*) as count FROM users")
        total_users = user_rows[0]['count'] if user_rows else 0
        
        active_users = auth_service.db_manager.execute_query("SELECT COUNT(*) as count FROM users WHERE is_active = TRUE")
        active_user_count = active_users[0]['count'] if active_users else 0
        
        locked_users = auth_service.db_manager.execute_query("SELECT COUNT(*) as count FROM users WHERE is_locked = TRUE")
        locked_user_count = locked_users[0]['count'] if locked_users else 0
        
        # Get API key count
        api_key_rows = auth_service.db_manager.execute_query("SELECT COUNT(*) as count FROM api_keys")
        total_api_keys = api_key_rows[0]['count'] if api_key_rows else 0
        
        active_api_keys = auth_service.db_manager.execute_query("SELECT COUNT(*) as count FROM api_keys WHERE is_active = TRUE")
        active_api_key_count = active_api_keys[0]['count'] if active_api_keys else 0
        
        # Get session count
        session_rows = auth_service.db_manager.execute_query("SELECT COUNT(*) as count FROM sessions WHERE is_active = TRUE")
        active_sessions = session_rows[0]['count'] if session_rows else 0
        
        # Get event count
        event_rows = auth_service.db_manager.execute_query("SELECT COUNT(*) as count FROM auth_events")
        total_events = event_rows[0]['count'] if event_rows else 0
        
        recent_events = auth_service.db_manager.execute_query(
            "SELECT COUNT(*) as count FROM auth_events WHERE timestamp > datetime('now', '-24 hours')"
        )
        recent_event_count = recent_events[0]['count'] if recent_events else 0
        
        print("System Status:")
        print("=" * 50)
        print(f"Total Users: {total_users}")
        print(f"Active Users: {active_user_count}")
        print(f"Locked Users: {locked_user_count}")
        print(f"Total API Keys: {total_api_keys}")
        print(f"Active API Keys: {active_api_key_count}")
        print(f"Active Sessions: {active_sessions}")
        print(f"Total Auth Events: {total_events}")
        print(f"Events (24h): {recent_event_count}")
        
        return True
    except Exception as e:
        print(f"❌ Error showing system status: {e}")
        return False

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Secure LLM Proxy Management Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s create-admin --username admin --email admin@company.com
  %(prog)s create-user --username john --email john@company.com --role user
  %(prog)s create-api-key --username john --name "Production Key"
  %(prog)s list-users
  %(prog)s show-status
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Create admin command
    admin_parser = subparsers.add_parser('create-admin', help='Create an admin user')
    admin_parser.add_argument('--username', help='Admin username')
    admin_parser.add_argument('--email', help='Admin email')
    admin_parser.set_defaults(func=create_admin)
    
    # Create user command
    user_parser = subparsers.add_parser('create-user', help='Create a regular user')
    user_parser.add_argument('--username', help='Username')
    user_parser.add_argument('--email', help='Email')
    user_parser.add_argument('--role', choices=[role.value for role in UserRole], help='User role')
    user_parser.add_argument('--mfa', action='store_true', help='Enable MFA')
    user_parser.add_argument('--no-mfa', action='store_false', dest='mfa', help='Disable MFA')
    user_parser.set_defaults(func=create_user)
    
    # List users command
    list_users_parser = subparsers.add_parser('list-users', help='List all users')
    list_users_parser.set_defaults(func=list_users)
    
    # Create API key command
    api_key_parser = subparsers.add_parser('create-api-key', help='Create an API key')
    api_key_parser.add_argument('--username', help='Username')
    api_key_parser.add_argument('--name', help='API key name')
    api_key_parser.add_argument('--permissions', help='Comma-separated permissions')
    api_key_parser.set_defaults(func=create_api_key)
    
    # List API keys command
    list_keys_parser = subparsers.add_parser('list-api-keys', help='List API keys for a user')
    list_keys_parser.add_argument('--username', help='Username')
    list_keys_parser.set_defaults(func=list_api_keys)
    
    # Revoke API key command
    revoke_key_parser = subparsers.add_parser('revoke-api-key', help='Revoke an API key')
    revoke_key_parser.add_argument('--username', help='Username')
    revoke_key_parser.add_argument('--key-id', help='API key ID')
    revoke_key_parser.set_defaults(func=revoke_api_key)
    
    # Change password command
    change_pwd_parser = subparsers.add_parser('change-password', help='Change user password')
    change_pwd_parser.add_argument('--username', help='Username')
    change_pwd_parser.set_defaults(func=change_password)
    
    # Reset password command
    reset_pwd_parser = subparsers.add_parser('reset-password', help='Reset user password (admin only)')
    reset_pwd_parser.add_argument('--username', help='Username')
    reset_pwd_parser.set_defaults(func=reset_password)
    
    # Lock user command
    lock_user_parser = subparsers.add_parser('lock-user', help='Lock a user account')
    lock_user_parser.add_argument('--username', help='Username')
    lock_user_parser.set_defaults(func=lock_user)
    
    # Unlock user command
    unlock_user_parser = subparsers.add_parser('unlock-user', help='Unlock a user account')
    unlock_user_parser.add_argument('--username', help='Username')
    unlock_user_parser.set_defaults(func=unlock_user)
    
    # Show auth events command
    events_parser = subparsers.add_parser('show-events', help='Show recent authentication events')
    events_parser.add_argument('--limit', type=int, help='Number of events to show')
    events_parser.set_defaults(func=show_auth_events)
    
    # Cleanup sessions command
    cleanup_parser = subparsers.add_parser('cleanup-sessions', help='Clean up expired sessions')
    cleanup_parser.set_defaults(func=cleanup_sessions)
    
    # Show status command
    status_parser = subparsers.add_parser('show-status', help='Show system status')
    status_parser.set_defaults(func=show_system_status)
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    try:
        success = args.func(args)
        return 0 if success else 1
    except KeyboardInterrupt:
        print("\n❌ Operation cancelled by user")
        return 1
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return 1

if __name__ == '__main__':
    sys.exit(main())