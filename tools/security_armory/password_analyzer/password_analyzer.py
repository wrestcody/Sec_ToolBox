#!/usr/bin/env python3
"""
Password Strength Analyzer with Guardian's Mandate Integration

A comprehensive password analysis tool that demonstrates:
- Password security best practices
- Common attack vectors and defenses
- Clean, educational code structure
- Integration with Guardian's Mandate for audit trails

This tool helps security professionals and users understand password security.
"""

import argparse
import re
import hashlib
import time
from datetime import datetime
from typing import Dict, List, Tuple
import json
import sys
import os

# Add parent directory to path for Guardian's Mandate integration
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))
try:
    from guardians_mandate_integration import GuardianTool, EvidenceLevel, AuditEventType
    GUARDIAN_MANDATE_AVAILABLE = True
except ImportError:
    GUARDIAN_MANDATE_AVAILABLE = False
    print("Warning: Guardian's Mandate not available. Running in basic mode.")


class PasswordAnalyzer(GuardianTool if GUARDIAN_MANDATE_AVAILABLE else object):
    """
    Comprehensive password strength analyzer.
    
    Features:
    - Length and complexity analysis
    - Common password detection
    - Entropy calculation
    - Attack time estimation
    - Security recommendations
    - Guardian's Mandate integration for audit trails
    """
    
    def __init__(self, enable_guardian_mandate: bool = True):
        """Initialize the password analyzer."""
        self.enable_guardian_mandate = enable_guardian_mandate and GUARDIAN_MANDATE_AVAILABLE
        
        # Initialize Guardian's Mandate if available
        if self.enable_guardian_mandate and GUARDIAN_MANDATE_AVAILABLE:
            try:
                super().__init__(
                    tool_name="PasswordAnalyzer",
                    tool_version="1.0.0",
                    evidence_level=EvidenceLevel.HIGH
                )
            except Exception as e:
                print(f"Warning: Guardian's Mandate initialization failed: {e}")
                self.enable_guardian_mandate = False
        
        # Common weak passwords (top 100 from various breaches)
        self.common_passwords = {
            'password', '123456', '123456789', 'qwerty', 'abc123', 'password123',
            'admin', 'letmein', 'welcome', 'monkey', 'dragon', 'master', 'hello',
            'freedom', 'whatever', 'qazwsx', 'trustno1', 'jordan', 'harley',
            'ranger', 'buster', 'thomas', 'tigger', 'robert', 'soccer', 'batman',
            'test', 'pass', 'killer', 'hunter', 'jennifer', 'joshua', 'maggie',
            'hockey', 'shadow', 'michelle', 'diamond', 'nascar', 'jackson',
            'cowboy', 'eagles', 'charlie', 'andrew', 'angel', 'johnson', 'london',
            'midnight', 'michael', 'yankees', 'dallas', 'anthony', 'thunder',
            'taylor', 'matrix', 'mobilemail', 'mom', 'monitor', 'montana',
            'moon', 'moscow', 'mother', 'movie', 'mozilla', 'music', 'naomi',
            'nelson', 'network', 'news', 'newton', 'nextel', 'nicole', 'nintendo',
            'november', 'ocean', 'oliver', 'orange', 'oregon', 'pacific', 'pamela',
            'panama', 'paris', 'parker', 'password', 'paul', 'penguin', 'peter',
            'philip', 'phoenix', 'picture', 'pierre', 'pilot', 'pizza', 'planet',
            'pluto', 'poker', 'polaris', 'popcorn', 'princess', 'purple', 'qazwsx',
            'queen', 'raider', 'rainbow', 'ranger', 'rebecca', 'red123', 'redsox',
            'redwing', 'remember', 'robert', 'rocket', 'rose', 'runner', 'russia'
        }
        
        # Character sets for entropy calculation
        self.char_sets = {
            'lowercase': 'abcdefghijklmnopqrstuvwxyz',
            'uppercase': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            'digits': '0123456789',
            'symbols': '!@#$%^&*()_+-=[]{}|;:,.<>?'
        }
        
        if self.enable_guardian_mandate:
            self.record_guardian_event(
                event_type=AuditEventType.TOOL_STARTUP.value,
                action="password_analyzer_initialized",
                details={"common_passwords_count": len(self.common_passwords)}
            )
    
    def analyze_length(self, password: str) -> Dict:
        """Analyze password length characteristics."""
        return {
            'length': len(password),
            'is_short': len(password) < 8,
            'is_medium': 8 <= len(password) < 12,
            'is_long': 12 <= len(password) < 16,
            'is_very_long': len(password) >= 16
        }
    
    def analyze_complexity(self, password: str) -> Dict:
        """Analyze password complexity and character diversity."""
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_symbol = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password))
        
        # Count unique character types
        char_types = sum([has_lower, has_upper, has_digit, has_symbol])
        
        # Check for patterns
        has_sequence = bool(re.search(r'(?:abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|123|234|345|456|567|678|789|890)', password.lower()))
        has_repeated = bool(re.search(r'(.)\1{2,}', password))
        
        return {
            'has_lowercase': has_lower,
            'has_uppercase': has_upper,
            'has_digits': has_digit,
            'has_symbols': has_symbol,
            'char_types': char_types,
            'has_sequence': has_sequence,
            'has_repeated': has_repeated,
            'complexity_score': char_types * 25  # 0-100 scale
        }
    
    def calculate_entropy(self, password: str) -> float:
        """Calculate password entropy (bits of randomness)."""
        char_set_size = 0

        if re.search(r'[a-z]', password):
            char_set_size += 26
        if re.search(r'[A-Z]', password):
            char_set_size += 26
        if re.search(r'\d', password):
            char_set_size += 10
        if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
            char_set_size += 32

        if char_set_size == 0:
            return 0

        # Calculate entropy using log2
        import math
        return len(password) * math.log2(char_set_size)
    
    def estimate_crack_time(self, entropy: float) -> Dict:
        """Estimate time to crack password with different attack methods."""
        # Assumptions: 1 billion guesses per second for offline attacks
        guesses_per_second = 1_000_000_000
        
        # Calculate total possible combinations
        total_combinations = 2 ** entropy
        
        # Time estimates for different attack scenarios
        offline_attack = total_combinations / guesses_per_second
        online_attack = total_combinations / 10  # 10 guesses per second
        
        def format_time(seconds: float) -> str:
            if seconds < 1:
                return "instant"
            elif seconds < 60:
                return f"{seconds:.1f} seconds"
            elif seconds < 3600:
                return f"{seconds/60:.1f} minutes"
            elif seconds < 86400:
                return f"{seconds/3600:.1f} hours"
            elif seconds < 31536000:
                return f"{seconds/86400:.1f} days"
            else:
                return f"{seconds/31536000:.1f} years"
        
        return {
            'entropy_bits': entropy,
            'total_combinations': total_combinations,
            'offline_attack': format_time(offline_attack),
            'online_attack': format_time(online_attack),
            'is_strong': entropy >= 64,
            'is_very_strong': entropy >= 80
        }
    
    def check_common_password(self, password: str) -> Dict:
        """Check if password is in common password lists."""
        is_common = password.lower() in self.common_passwords
        is_variation = False
        
        # Check for common variations
        variations = [
            password.lower(),
            password.lower() + '123',
            password.lower() + '!',
            password.lower() + '1',
            '1' + password.lower(),
            password.lower().replace('a', '@').replace('e', '3').replace('i', '1').replace('o', '0')
        ]
        
        for variation in variations:
            if variation in self.common_passwords:
                is_variation = True
                break
        
        return {
            'is_common': is_common,
            'is_variation': is_variation,
            'risk_level': 'high' if is_common else 'medium' if is_variation else 'low'
        }
    
    def analyze_password(self, password: str) -> Dict:
        """Perform comprehensive password analysis."""
        length_analysis = self.analyze_length(password)
        complexity_analysis = self.analyze_complexity(password)
        entropy = self.calculate_entropy(password)
        crack_time = self.estimate_crack_time(entropy)
        common_check = self.check_common_password(password)
        
        # Calculate overall strength score (0-100)
        strength_score = 0
        
        # Length contribution (30 points)
        if length_analysis['is_very_long']:
            strength_score += 30
        elif length_analysis['is_long']:
            strength_score += 25
        elif length_analysis['is_medium']:
            strength_score += 20
        elif length_analysis['is_short']:
            strength_score += 10
        
        # Complexity contribution (40 points)
        strength_score += complexity_analysis['complexity_score'] * 0.4
        
        # Entropy contribution (30 points)
        if entropy >= 80:
            strength_score += 30
        elif entropy >= 64:
            strength_score += 25
        elif entropy >= 48:
            strength_score += 20
        elif entropy >= 32:
            strength_score += 15
        else:
            strength_score += entropy / 32 * 15
        
        # Penalties
        if common_check['is_common']:
            strength_score -= 50
        elif common_check['is_variation']:
            strength_score -= 25
        
        if complexity_analysis['has_sequence']:
            strength_score -= 15
        
        if complexity_analysis['has_repeated']:
            strength_score -= 10
        
        strength_score = max(0, min(100, strength_score))
        
        # Determine strength level
        if strength_score >= 80:
            strength_level = "Very Strong"
        elif strength_score >= 60:
            strength_level = "Strong"
        elif strength_score >= 40:
            strength_level = "Moderate"
        elif strength_score >= 20:
            strength_level = "Weak"
        else:
            strength_level = "Very Weak"
        
        analysis_result = {
            'password': '*' * len(password),  # Don't expose the actual password
            'length_analysis': length_analysis,
            'complexity_analysis': complexity_analysis,
            'entropy_analysis': crack_time,
            'common_password_check': common_check,
            'strength_score': round(strength_score, 1),
            'strength_level': strength_level,
            'analysis_time': datetime.now().isoformat()
        }
        
        if self.enable_guardian_mandate:
            self.record_guardian_event(
                event_type=AuditEventType.SECURITY_ANALYSIS.value,
                action="password_analysis_completed",
                details={
                    'password_length': len(password),
                    'strength_score': strength_score,
                    'strength_level': strength_level,
                    'is_common_password': common_check['is_common']
                }
            )
        
        return analysis_result
    
    def generate_recommendations(self, analysis: Dict) -> List[str]:
        """Generate security recommendations based on analysis."""
        recommendations = []
        
        # Length recommendations
        if analysis['length_analysis']['is_short']:
            recommendations.append("🔴 Increase password length to at least 8 characters")
        elif analysis['length_analysis']['is_medium']:
            recommendations.append("🟡 Consider increasing password length to 12+ characters for better security")
        
        # Complexity recommendations
        if not analysis['complexity_analysis']['has_uppercase']:
            recommendations.append("🔴 Add uppercase letters (A-Z)")
        if not analysis['complexity_analysis']['has_digits']:
            recommendations.append("🔴 Add numbers (0-9)")
        if not analysis['complexity_analysis']['has_symbols']:
            recommendations.append("🔴 Add special characters (!@#$%^&*)")
        
        # Pattern recommendations
        if analysis['complexity_analysis']['has_sequence']:
            recommendations.append("🟡 Avoid common sequences (abc, 123, etc.)")
        if analysis['complexity_analysis']['has_repeated']:
            recommendations.append("🟡 Avoid repeated characters (aaa, 111, etc.)")
        
        # Common password recommendations
        if analysis['common_password_check']['is_common']:
            recommendations.append("🔴 This is a very common password - choose something unique")
        elif analysis['common_password_check']['is_variation']:
            recommendations.append("🟡 This is similar to common passwords - choose something more unique")
        
        # Entropy recommendations
        if analysis['entropy_analysis']['entropy_bits'] < 32:
            recommendations.append("🔴 Password is too predictable - increase complexity")
        elif analysis['entropy_analysis']['entropy_bits'] < 48:
            recommendations.append("🟡 Consider increasing password complexity for better security")
        
        # General recommendations
        if analysis['strength_score'] < 40:
            recommendations.append("🔴 This password is too weak for most security requirements")
        elif analysis['strength_score'] < 60:
            recommendations.append("🟡 This password meets basic requirements but could be stronger")
        
        return recommendations
    
    def print_analysis(self, analysis: Dict, show_recommendations: bool = True):
        """Print analysis results in a clean, professional format."""
        print("\n" + "=" * 60)
        print("🔐 PASSWORD STRENGTH ANALYSIS")
        print("=" * 60)
        
        print(f"📊 Overall Strength: {analysis['strength_level']} ({analysis['strength_score']}/100)")
        print(f"🔢 Length: {analysis['length_analysis']['length']} characters")
        print(f"🎯 Entropy: {analysis['entropy_analysis']['entropy_bits']:.1f} bits")
        print()
        
        print("📋 Complexity Analysis:")
        print(f"   ├─ Lowercase letters: {'✅' if analysis['complexity_analysis']['has_lowercase'] else '❌'}")
        print(f"   ├─ Uppercase letters: {'✅' if analysis['complexity_analysis']['has_uppercase'] else '❌'}")
        print(f"   ├─ Numbers: {'✅' if analysis['complexity_analysis']['has_digits'] else '❌'}")
        print(f"   ├─ Special characters: {'✅' if analysis['complexity_analysis']['has_symbols'] else '❌'}")
        print(f"   └─ Character types: {analysis['complexity_analysis']['char_types']}/4")
        print()
        
        print("⏱️  Security Estimates:")
        print(f"   ├─ Offline attack: {analysis['entropy_analysis']['offline_attack']}")
        print(f"   ├─ Online attack: {analysis['entropy_analysis']['online_attack']}")
        print(f"   └─ Total combinations: {analysis['entropy_analysis']['total_combinations']:,}")
        print()
        
        print("🚨 Risk Assessment:")
        common_status = "High Risk" if analysis['common_password_check']['is_common'] else \
                       "Medium Risk" if analysis['common_password_check']['is_variation'] else "Low Risk"
        print(f"   └─ Common password: {common_status}")
        
        if show_recommendations:
            recommendations = self.generate_recommendations(analysis)
            if recommendations:
                print("\n💡 Recommendations:")
                for rec in recommendations:
                    print(f"   {rec}")


def main():
    """Main function with command-line interface."""
    parser = argparse.ArgumentParser(
        description="Password Strength Analyzer with Guardian's Mandate Integration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s "mypassword123"                    # Analyze single password
  %(prog)s -f passwords.txt                   # Analyze passwords from file
  %(prog)s "mypassword123" -o results.json    # Save results to file
  %(prog)s "mypassword123" --no-recommendations # Skip recommendations
        """
    )
    
    parser.add_argument(
        'password',
        nargs='?',
        help='Password to analyze (use quotes for special characters)'
    )
    
    parser.add_argument(
        '-f', '--file',
        help='File containing passwords to analyze (one per line)'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Output file for results (JSON format)'
    )
    
    parser.add_argument(
        '--no-recommendations',
        action='store_true',
        help='Skip security recommendations'
    )
    
    parser.add_argument(
        '--disable-guardian-mandate',
        action='store_true',
        help='Disable Guardian\'s Mandate integration'
    )
    
    args = parser.parse_args()
    
    # Validate input
    if not args.password and not args.file:
        print("❌ Error: Please provide either a password or a file to analyze")
        parser.print_help()
        sys.exit(1)
    
    # Initialize analyzer
    analyzer = PasswordAnalyzer(enable_guardian_mandate=not args.disable_guardian_mandate)
    
    results = []
    
    try:
        if args.password:
            # Analyze single password
            result = analyzer.analyze_password(args.password)
            results.append(result)
            analyzer.print_analysis(result, not args.no_recommendations)
        
        elif args.file:
            # Analyze passwords from file
            try:
                with open(args.file, 'r') as f:
                    passwords = [line.strip() for line in f if line.strip()]
                
                print(f"📁 Analyzing {len(passwords)} passwords from {args.file}")
                print("-" * 50)
                
                for i, password in enumerate(passwords, 1):
                    print(f"🔍 Analyzing password {i}/{len(passwords)}...")
                    result = analyzer.analyze_password(password)
                    results.append(result)
                    
                    if not args.no_recommendations:
                        analyzer.print_analysis(result, True)
                        print("-" * 30)
                
                # Summary statistics
                avg_strength = sum(r['strength_score'] for r in results) / len(results)
                weak_count = sum(1 for r in results if r['strength_score'] < 40)
                strong_count = sum(1 for r in results if r['strength_score'] >= 60)
                
                print(f"\n📊 Summary: {len(results)} passwords analyzed")
                print(f"   ├─ Average strength: {avg_strength:.1f}/100")
                print(f"   ├─ Weak passwords: {weak_count}")
                print(f"   └─ Strong passwords: {strong_count}")
                
            except FileNotFoundError:
                print(f"❌ Error: File '{args.file}' not found")
                sys.exit(1)
            except Exception as e:
                print(f"❌ Error reading file: {e}")
                sys.exit(1)
        
        # Save results if requested
        if args.output and results:
            try:
                with open(args.output, 'w') as f:
                    json.dump(results, f, indent=2)
                print(f"\n💾 Results saved to: {args.output}")
            except Exception as e:
                print(f"❌ Error saving results: {e}")
        
        if analyzer.enable_guardian_mandate:
            print("\n🛡️  Guardian's Mandate: Audit trail recorded")
            print("   - All password analysis activities logged")
            print("   - No actual passwords stored in audit logs")
    
    except KeyboardInterrupt:
        print("\n⚠️  Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error during analysis: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()