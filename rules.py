#!/usr/bin/env python3
"""
Threat Detection Rules Engine
============================

This module implements rule-based threat detection for system logs.
It identifies various security threats including break-in attempts,
unauthorized access, suspicious network activity, and potential malware.

Features:
- Real-time threat detection from log entries
- Configurable threat rules and thresholds
- IP-based threat tracking and banned IP detection
- Behavioral analysis for anomalous user activities
- Automated threat scoring and classification
- Integration with log monitoring systems

Author: OS Log Analyzer - Security Edition
Date: October 3, 2025
"""

import re
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field
from collections import defaultdict, Counter
import json


# Data Structures
# ===============

@dataclass
class ThreatIndicator:
    """Structure for storing threat detection results."""
    threat_type: str
    severity: str  # 'low', 'medium', 'high', 'critical'
    confidence: float  # 0.0 to 1.0
    description: str
    source_ip: Optional[str] = None
    target_system: Optional[str] = None
    event_count: int = 1
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    raw_evidence: List[str] = field(default_factory=list)


@dataclass
class SecurityEvent:
    """Structure for security-related log events."""
    timestamp: datetime
    source: str
    event_id: str
    level: str
    message: str
    source_ip: Optional[str] = None
    target_ip: Optional[str] = None
    username: Optional[str] = None
    process_name: Optional[str] = None
    file_path: Optional[str] = None


# Configuration and Known Threats
# ===============================

class ThreatConfig:
    """Configuration for threat detection rules."""
    
    # Known bad IP addresses/ranges (example entries)
    BANNED_IPS = {
        '192.168.1.100',  # Example internal threat
        '10.0.0.50',      # Example compromised host
        # Add real threat intelligence IPs here
    }
    
    BANNED_RANGES = [
        '192.168.100.0/24',  # Example quarantine network
        # Add real banned network ranges here
    ]
    
    # Suspicious user accounts
    SUSPICIOUS_ACCOUNTS = {
        'administrator', 'admin', 'root', 'guest', 'test',
        'service', 'system', 'network', 'sql', 'web'
    }
    
    # High-risk event IDs by platform
    WINDOWS_THREAT_EVENTS = {
        4625: 'Failed logon attempt',
        4648: 'Logon with explicit credentials',
        4720: 'User account created',
        4722: 'User account enabled',
        4724: 'Password reset attempt',
        4728: 'User added to security group',
        4732: 'User added to local group',
        4756: 'User added to universal group',
        5140: 'Network share accessed',
        5145: 'Shared folder access check',
        1102: 'Audit log cleared',
        7045: 'Service installed',
        104: 'Event log cleared'
    }
    
    # Suspicious processes
    SUSPICIOUS_PROCESSES = {
        'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe',
        'regsvr32.exe', 'rundll32.exe', 'mshta.exe', 'certutil.exe',
        'bitsadmin.exe', 'psexec.exe', 'net.exe', 'netsh.exe'
    }
    
    # Malware indicators in file paths
    MALWARE_PATHS = {
        'temp', 'tmp', 'appdata\\roaming', 'programdata',
        'users\\public', 'windows\\temp', '%temp%'
    }
    
    # Brute force thresholds
    BRUTE_FORCE_THRESHOLD = 5  # Failed attempts
    BRUTE_FORCE_WINDOW = 300   # 5 minutes
    
    # Anomaly thresholds
    LOGIN_FREQUENCY_THRESHOLD = 10  # Logins per hour
    PROCESS_SPAWN_THRESHOLD = 50    # Process creations per minute


# Core Threat Detection Engine
# ============================

class ThreatDetectionEngine:
    """Main engine for threat detection using rule-based analysis."""
    
    def __init__(self):
        self.config = ThreatConfig()
        self.threat_indicators = []
        self.event_history = defaultdict(list)
        self.ip_activity = defaultdict(list)
        self.user_activity = defaultdict(list)
        self.process_activity = defaultdict(list)
        self.failed_logins = defaultdict(list)
        
    def extract_ip_from_message(self, message: str) -> Optional[str]:
        """Extract IP address from log message."""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        matches = re.findall(ip_pattern, message)
        return matches[0] if matches else None
    
    def extract_username_from_message(self, message: str) -> Optional[str]:
        """Extract username from log message."""
        # Common patterns for usernames in Windows logs
        patterns = [
            r'Account Name:\s*([^\s,]+)',
            r'User Name:\s*([^\s,]+)',
            r'Account:\s*([^\s,]+)',
            r'User:\s*([^\s,]+)',
            r'Logon Name:\s*([^\s,]+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                username = match.group(1).strip()
                # Filter out system accounts and empty values
                if username and username not in ['-', 'N/A', 'NULL', '$']:
                    return username.lower()
        return None
    
    def extract_process_from_message(self, message: str) -> Optional[str]:
        """Extract process name from log message."""
        patterns = [
            r'Process Name:\s*([^\s,]+\.exe)',
            r'Image:\s*([^\s,]+\.exe)',
            r'ProcessName:\s*([^\s,]+\.exe)',
            r'([a-zA-Z0-9_-]+\.exe)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                return match.group(1).lower()
        return None
    
    def is_banned_ip(self, ip: str) -> bool:
        """Check if IP is in banned list or range."""
        if ip in self.config.BANNED_IPS:
            return True
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            for banned_range in self.config.BANNED_RANGES:
                if ip_obj in ipaddress.ip_network(banned_range):
                    return True
        except ValueError:
            pass
        
        return False
    
    def analyze_log_entry(self, log_entry: Dict[str, Any]) -> List[ThreatIndicator]:
        """Analyze a single log entry for threats."""
        threats = []
        
        # Convert log entry to SecurityEvent
        try:
            timestamp = pd.to_datetime(log_entry.get('Timestamp', datetime.now()))
            if isinstance(timestamp, str):
                timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            elif hasattr(timestamp, 'to_pydatetime'):
                timestamp = timestamp.to_pydatetime()
        except:
            timestamp = datetime.now()
        
        event = SecurityEvent(
            timestamp=timestamp,
            source=log_entry.get('Source', ''),
            event_id=str(log_entry.get('Event_ID', '')),
            level=log_entry.get('Level', ''),
            message=log_entry.get('Message', ''),
            source_ip=self.extract_ip_from_message(log_entry.get('Message', '')),
            username=self.extract_username_from_message(log_entry.get('Message', '')),
            process_name=self.extract_process_from_message(log_entry.get('Message', ''))
        )
        
        # Apply threat detection rules
        threats.extend(self._detect_brute_force_attacks(event))
        threats.extend(self._detect_banned_ip_activity(event))
        threats.extend(self._detect_suspicious_logons(event))
        threats.extend(self._detect_privilege_escalation(event))
        threats.extend(self._detect_malicious_processes(event))
        threats.extend(self._detect_log_tampering(event))
        threats.extend(self._detect_network_reconnaissance(event))
        threats.extend(self._detect_persistence_mechanisms(event))
        
        # Update tracking data
        self._update_tracking_data(event)
        
        return threats
    
    def _detect_brute_force_attacks(self, event: SecurityEvent) -> List[ThreatIndicator]:
        """Detect brute force login attempts."""
        threats = []
        
        # Windows failed logon event
        if event.event_id in ['4625', '529', '530', '531', '532', '533', '534', '535', '536', '537', '538', '539']:
            source_key = event.source_ip or event.username or 'unknown'
            self.failed_logins[source_key].append(event.timestamp)
            
            # Clean old entries
            cutoff_time = event.timestamp - timedelta(seconds=self.config.BRUTE_FORCE_WINDOW)
            self.failed_logins[source_key] = [
                t for t in self.failed_logins[source_key] if t > cutoff_time
            ]
            
            # Check threshold
            if len(self.failed_logins[source_key]) >= self.config.BRUTE_FORCE_THRESHOLD:
                threats.append(ThreatIndicator(
                    threat_type='brute_force_attack',
                    severity='high',
                    confidence=0.9,
                    description=f'Brute force attack detected: {len(self.failed_logins[source_key])} failed attempts',
                    source_ip=event.source_ip,
                    target_system=event.source,
                    event_count=len(self.failed_logins[source_key]),
                    first_seen=min(self.failed_logins[source_key]),
                    last_seen=max(self.failed_logins[source_key]),
                    raw_evidence=[event.message]
                ))
        
        return threats
    
    def _detect_banned_ip_activity(self, event: SecurityEvent) -> List[ThreatIndicator]:
        """Detect activity from banned IP addresses."""
        threats = []
        
        if event.source_ip and self.is_banned_ip(event.source_ip):
            threats.append(ThreatIndicator(
                threat_type='banned_ip_activity',
                severity='critical',
                confidence=1.0,
                description=f'Activity detected from banned IP: {event.source_ip}',
                source_ip=event.source_ip,
                target_system=event.source,
                raw_evidence=[event.message]
            ))
        
        return threats
    
    def _detect_suspicious_logons(self, event: SecurityEvent) -> List[ThreatIndicator]:
        """Detect suspicious logon activities."""
        threats = []
        
        # Successful logon events
        if event.event_id in ['4624', '528']:
            if event.username and event.username in self.config.SUSPICIOUS_ACCOUNTS:
                threats.append(ThreatIndicator(
                    threat_type='suspicious_account_logon',
                    severity='medium',
                    confidence=0.7,
                    description=f'Logon detected for suspicious account: {event.username}',
                    source_ip=event.source_ip,
                    target_system=event.source,
                    raw_evidence=[event.message]
                ))
            
            # Logon outside business hours (example: 6 PM to 6 AM)
            if event.timestamp.hour < 6 or event.timestamp.hour >= 18:
                threats.append(ThreatIndicator(
                    threat_type='after_hours_logon',
                    severity='low',
                    confidence=0.5,
                    description=f'After-hours logon detected: {event.username} at {event.timestamp.strftime("%H:%M")}',
                    source_ip=event.source_ip,
                    target_system=event.source,
                    raw_evidence=[event.message]
                ))
        
        return threats
    
    def _detect_privilege_escalation(self, event: SecurityEvent) -> List[ThreatIndicator]:
        """Detect privilege escalation attempts."""
        threats = []
        
        # User added to privileged groups
        if event.event_id in ['4728', '4732', '4756']:
            if any(group in event.message.lower() for group in ['admin', 'domain admin', 'enterprise admin']):
                threats.append(ThreatIndicator(
                    threat_type='privilege_escalation',
                    severity='high',
                    confidence=0.8,
                    description='User added to privileged group',
                    target_system=event.source,
                    raw_evidence=[event.message]
                ))
        
        # Service installation (potential persistence)
        if event.event_id == '7045':
            threats.append(ThreatIndicator(
                threat_type='service_installation',
                severity='medium',
                confidence=0.6,
                description='New service installed on system',
                target_system=event.source,
                raw_evidence=[event.message]
            ))
        
        return threats
    
    def _detect_malicious_processes(self, event: SecurityEvent) -> List[ThreatIndicator]:
        """Detect potentially malicious process activities."""
        threats = []
        
        if event.process_name:
            # Suspicious process execution
            if event.process_name in self.config.SUSPICIOUS_PROCESSES:
                threats.append(ThreatIndicator(
                    threat_type='suspicious_process',
                    severity='medium',
                    confidence=0.6,
                    description=f'Suspicious process detected: {event.process_name}',
                    target_system=event.source,
                    raw_evidence=[event.message]
                ))
            
            # Process in suspicious location
            for suspicious_path in self.config.MALWARE_PATHS:
                if suspicious_path in event.message.lower():
                    threats.append(ThreatIndicator(
                        threat_type='malware_path',
                        severity='high',
                        confidence=0.7,
                        description=f'Process in suspicious location: {suspicious_path}',
                        target_system=event.source,
                        raw_evidence=[event.message]
                    ))
                    break
        
        return threats
    
    def _detect_log_tampering(self, event: SecurityEvent) -> List[ThreatIndicator]:
        """Detect log tampering and audit evasion."""
        threats = []
        
        # Event log cleared
        if event.event_id in ['1102', '104']:
            threats.append(ThreatIndicator(
                threat_type='log_tampering',
                severity='critical',
                confidence=0.95,
                description='Event log cleared - possible evidence destruction',
                target_system=event.source,
                raw_evidence=[event.message]
            ))
        
        # Audit policy changes
        if event.event_id == '4719':
            threats.append(ThreatIndicator(
                threat_type='audit_policy_change',
                severity='high',
                confidence=0.8,
                description='System audit policy modified',
                target_system=event.source,
                raw_evidence=[event.message]
            ))
        
        return threats
    
    def _detect_network_reconnaissance(self, event: SecurityEvent) -> List[ThreatIndicator]:
        """Detect network reconnaissance activities."""
        threats = []
        
        # Multiple network share accesses
        if event.event_id in ['5140', '5145']:
            source_key = event.source_ip or 'unknown'
            self.ip_activity[source_key].append(event.timestamp)
            
            # Check for rapid share access (potential reconnaissance)
            recent_accesses = [
                t for t in self.ip_activity[source_key] 
                if t > event.timestamp - timedelta(minutes=5)
            ]
            
            if len(recent_accesses) > 10:  # More than 10 accesses in 5 minutes
                threats.append(ThreatIndicator(
                    threat_type='network_reconnaissance',
                    severity='medium',
                    confidence=0.7,
                    description=f'Rapid network share scanning detected from {event.source_ip}',
                    source_ip=event.source_ip,
                    target_system=event.source,
                    event_count=len(recent_accesses),
                    raw_evidence=[event.message]
                ))
        
        return threats
    
    def _detect_persistence_mechanisms(self, event: SecurityEvent) -> List[ThreatIndicator]:
        """Detect persistence mechanism installation."""
        threats = []
        
        # Registry modifications (if available in logs)
        if 'registry' in event.message.lower() and any(
            key in event.message.lower() for key in ['run', 'runonce', 'startup', 'service']
        ):
            threats.append(ThreatIndicator(
                threat_type='persistence_mechanism',
                severity='medium',
                confidence=0.6,
                description='Potential persistence mechanism via registry modification',
                target_system=event.source,
                raw_evidence=[event.message]
            ))
        
        # Scheduled task creation
        if 'task scheduler' in event.source.lower() or 'schtasks' in event.message.lower():
            threats.append(ThreatIndicator(
                threat_type='scheduled_task_creation',
                severity='medium',
                confidence=0.6,
                description='Scheduled task created - potential persistence',
                target_system=event.source,
                raw_evidence=[event.message]
            ))
        
        return threats
    
    def _update_tracking_data(self, event: SecurityEvent):
        """Update internal tracking data structures."""
        # Update IP activity tracking
        if event.source_ip:
            self.ip_activity[event.source_ip].append(event.timestamp)
            # Keep only recent entries
            cutoff = event.timestamp - timedelta(hours=24)
            self.ip_activity[event.source_ip] = [
                t for t in self.ip_activity[event.source_ip] if t > cutoff
            ]
        
        # Update user activity tracking
        if event.username:
            self.user_activity[event.username].append(event.timestamp)
            cutoff = event.timestamp - timedelta(hours=24)
            self.user_activity[event.username] = [
                t for t in self.user_activity[event.username] if t > cutoff
            ]
        
        # Update process activity tracking
        if event.process_name:
            self.process_activity[event.process_name].append(event.timestamp)
            cutoff = event.timestamp - timedelta(hours=1)
            self.process_activity[event.process_name] = [
                t for t in self.process_activity[event.process_name] if t > cutoff
            ]
    
    def analyze_dataset(self, dataset_path: str) -> Dict[str, Any]:
        """Analyze an entire dataset for threats."""
        try:
            import pandas as pd
            
            # Read the dataset
            df = pd.read_excel(dataset_path, sheet_name='Raw_Logs')
            
            all_threats = []
            threat_summary = defaultdict(int)
            
            print(f"Analyzing {len(df)} log entries for threats...")
            
            for index, row in df.iterrows():
                threats = self.analyze_log_entry(row.to_dict())
                all_threats.extend(threats)
                
                for threat in threats:
                    threat_summary[threat.threat_type] += 1
            
            # Generate analysis report
            report = {
                'total_logs_analyzed': len(df),
                'total_threats_detected': len(all_threats),
                'threat_summary': dict(threat_summary),
                'threats_by_severity': self._categorize_by_severity(all_threats),
                'top_threat_sources': self._get_top_threat_sources(all_threats),
                'timeline': self._generate_threat_timeline(all_threats),
                'detailed_threats': all_threats[:50]  # Top 50 for display
            }
            
            return report
            
        except Exception as e:
            return {'error': f'Failed to analyze dataset: {str(e)}'}
    
    def _categorize_by_severity(self, threats: List[ThreatIndicator]) -> Dict[str, int]:
        """Categorize threats by severity level."""
        severity_counts = defaultdict(int)
        for threat in threats:
            severity_counts[threat.severity] += 1
        return dict(severity_counts)
    
    def _get_top_threat_sources(self, threats: List[ThreatIndicator]) -> List[Tuple[str, int]]:
        """Get top sources of threats."""
        source_counts = Counter()
        for threat in threats:
            if threat.source_ip:
                source_counts[threat.source_ip] += 1
            elif threat.target_system:
                source_counts[threat.target_system] += 1
        
        return source_counts.most_common(10)
    
    def _generate_threat_timeline(self, threats: List[ThreatIndicator]) -> List[Dict[str, Any]]:
        """Generate timeline of threat activities."""
        timeline = []
        for threat in sorted(threats, key=lambda x: x.last_seen or datetime.now())[:20]:
            timeline.append({
                'timestamp': (threat.last_seen or datetime.now()).isoformat(),
                'threat_type': threat.threat_type,
                'severity': threat.severity,
                'description': threat.description
            })
        return timeline
    
    def export_threats_to_json(self, threats: List[ThreatIndicator], filename: str):
        """Export detected threats to JSON file."""
        threat_data = []
        for threat in threats:
            threat_data.append({
                'threat_type': threat.threat_type,
                'severity': threat.severity,
                'confidence': threat.confidence,
                'description': threat.description,
                'source_ip': threat.source_ip,
                'target_system': threat.target_system,
                'event_count': threat.event_count,
                'first_seen': threat.first_seen.isoformat() if threat.first_seen else None,
                'last_seen': threat.last_seen.isoformat() if threat.last_seen else None,
                'raw_evidence': threat.raw_evidence
            })
        
        with open(filename, 'w') as f:
            json.dump(threat_data, f, indent=2)


# Utility Functions
# =================

def analyze_log_file(dataset_path: str) -> Dict[str, Any]:
    """Main function to analyze a log dataset for threats."""
    engine = ThreatDetectionEngine()
    return engine.analyze_dataset(dataset_path)


def print_threat_report(report: Dict[str, Any]):
    """Print a formatted threat analysis report."""
    if 'error' in report:
        print(f"❌ Error: {report['error']}")
        return
    
    print("🔒 THREAT ANALYSIS REPORT")
    print("=" * 60)
    print(f"📊 Total logs analyzed: {report['total_logs_analyzed']}")
    print(f"⚠️  Total threats detected: {report['total_threats_detected']}")
    
    if report['threat_summary']:
        print("\n🎯 Threat Types Detected:")
        for threat_type, count in report['threat_summary'].items():
            print(f"   • {threat_type.replace('_', ' ').title()}: {count}")
    
    if report['threats_by_severity']:
        print("\n📈 Threats by Severity:")
        for severity, count in report['threats_by_severity'].items():
            emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(severity, '⚪')
            print(f"   {emoji} {severity.title()}: {count}")
    
    if report['top_threat_sources']:
        print("\n🌐 Top Threat Sources:")
        for source, count in report['top_threat_sources'][:5]:
            print(f"   • {source}: {count} incidents")
    
    print("\n⏰ Recent Threat Timeline:")
    for event in report['timeline'][:5]:
        timestamp = event['timestamp'][:19]  # Remove microseconds
        print(f"   {timestamp} - {event['threat_type']} ({event['severity']})")
        print(f"      {event['description']}")


# Main execution
# ==============

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python rules.py <path_to_excel_dataset>")
        sys.exit(1)
    
    dataset_path = sys.argv[1]
    
    print("🔍 Starting threat analysis...")
    report = analyze_log_file(dataset_path)
    
    print_threat_report(report)
    
    # Export detailed results
    if 'detailed_threats' in report:
        engine = ThreatDetectionEngine()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"threat_analysis_{timestamp}.json"
        engine.export_threats_to_json(report['detailed_threats'], output_file)
        print(f"\n💾 Detailed results exported to: {output_file}")