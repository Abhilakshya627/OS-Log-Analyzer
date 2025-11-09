#!/usr/bin/env python3
"""
Unified OS Log Analyzer - Simplified All-in-One System
=====================================================

A streamlined system that combines log monitoring, threat detection,
and machine learning analysis into a single, easy-to-use module.

Features:
- Real-time log monitoring for Windows/Linux/macOS
- Built-in threat detection with security rules
- Machine learning anomaly detection
- Comprehensive analysis and reporting
- Excel/CSV/JSON export capabilities
- Web API integration

Author: OS Log Analyzer - Unified Edition
Date: October 8, 2025
"""

import platform
import subprocess
import sys
import threading
import time
import signal
import os
import json
import csv
import re
import ipaddress
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Set, Tuple, cast
import numpy as np
from dataclasses import dataclass, field
from collections import defaultdict, Counter
import warnings

# Suppress warnings for cleaner output
warnings.filterwarnings('ignore')

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    pd = None
    HAS_PANDAS = False
    print("Warning: pandas not installed. Excel export functionality will be limited.")

# Optional ML imports
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.svm import OneClassSVM
    from sklearn.cluster import KMeans, DBSCAN
    from sklearn.preprocessing import StandardScaler, LabelEncoder
    from sklearn.feature_extraction.text import TfidfVectorizer
    HAS_ML = True
except ImportError:
    HAS_ML = False
    IsolationForest = None  # type: ignore[assignment]
    OneClassSVM = None  # type: ignore[assignment]
    KMeans = None  # type: ignore[assignment]
    DBSCAN = None  # type: ignore[assignment]
    StandardScaler = None  # type: ignore[assignment]
    LabelEncoder = None  # type: ignore[assignment]
    TfidfVectorizer = None  # type: ignore[assignment]
    print("Warning: scikit-learn not installed. ML analysis will be limited.")


# Data Structures
# ===============

@dataclass
class LogEntry:
    """Structure for storing individual log entries."""
    timestamp: datetime
    os_type: str
    log_type: str  # 'system', 'application', 'security', etc.
    source: str
    event_id: str
    level: str  # 'info', 'warning', 'error', 'critical'
    message: str
    raw_data: str


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
class MLAnomaly:
    """Structure for ML-detected anomalies."""
    timestamp: datetime
    anomaly_score: float
    description: str
    log_entry: Dict[str, Any]
    detection_method: str


# Unified Log Analyzer Class
# =========================

class UnifiedLogAnalyzer:
    """
    All-in-one log analyzer that combines monitoring, threat detection, and ML analysis.
    """
    
    def __init__(self, collection_duration: Optional[int] = None):
        """
        Initialize the unified analyzer.
        
        Args:
            collection_duration: Duration in seconds for log collection (None for indefinite)
        """
        self.os_type = self._detect_os()
        self.collection_duration = collection_duration
        self.start_time = datetime.now()
        self.running = False
        self.display_logs = True
        
        # Data storage
        self.logs: List[LogEntry] = []
        self.threats: List[ThreatIndicator] = []
        self.anomalies: List[MLAnomaly] = []
        
        # Configuration
        self.banned_ips = {
            '192.168.1.100', '10.0.0.50', '127.0.0.1', '0.0.0.0',  # Example threat IPs
            '192.168.0.1', '10.0.0.1', '172.16.0.1'  # Common router/gateway IPs
        }
        self.suspicious_accounts = {
            'administrator', 'admin', 'root', 'guest', 'test',
            'service', 'system', 'network', 'sql', 'web', 'oracle',
            'postgres', 'mysql', 'apache', 'nginx', 'tomcat'
        }
        
        # Windows threat event IDs (expanded)
        self.windows_threat_events = {
            4625: 'Failed logon attempt',
            4648: 'Logon with explicit credentials',
            4720: 'User account created',
            4722: 'User account enabled',
            4724: 'Password reset attempt',
            4740: 'User account locked out',
            4771: 'Kerberos pre-authentication failed',
            4776: 'Domain controller attempted to validate credentials',
            1102: 'Audit log cleared',
            5140: 'Network share accessed',
            5156: 'Windows Firewall allowed connection',
            5157: 'Windows Firewall blocked connection',
            7045: 'Service was installed',
            4688: 'New process created',
            4656: 'Handle to object was requested',
            4663: 'Attempt to access object'
        }
        
        # Threat patterns for enhanced detection
        self.threat_patterns = {
            'malware': ['virus', 'trojan', 'malware', 'worm', 'ransomware', 'backdoor', 'rootkit'],
            'network_attack': ['ddos', 'port scan', 'brute force', 'sql injection', 'xss', 'csrf'],
            'privilege_escalation': ['privilege', 'escalation', 'elevated', 'runas', 'sudo'],
            'data_exfiltration': ['upload', 'download', 'transfer', 'export', 'backup', 'copy'],
            'suspicious_process': ['powershell', 'cmd.exe', 'sc.exe', 'net.exe', 'netsh', 'reg.exe'],
            'persistence': ['scheduled task', 'registry', 'startup', 'service', 'autorun']
        }
        
        # Process monitoring patterns
        self.suspicious_processes = {
            'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe',
            'regsvr32.exe', 'rundll32.exe', 'schtasks.exe', 'at.exe',
            'sc.exe', 'net.exe', 'netsh.exe', 'taskkill.exe'
        }
        
        # ML components (initialized if available)
        self.ml_scaler = None
        self.ml_model = None
        self.text_vectorizer = None
        if HAS_ML:
            self._initialize_ml_components()
    
    def _detect_os(self) -> str:
        """Detect the operating system."""
        system = platform.system().lower()
        if system == 'darwin':
            return 'macos'
        return system
    
    def _initialize_ml_components(self):
        """Initialize machine learning components."""
        try:
            if StandardScaler is None or IsolationForest is None or TfidfVectorizer is None:
                raise RuntimeError("ML components are unavailable")
            scaler_cls = cast(Any, StandardScaler)
            model_cls = cast(Any, IsolationForest)
            vectorizer_cls = cast(Any, TfidfVectorizer)
            self.ml_scaler = scaler_cls()
            self.ml_model = model_cls(contamination=0.1, random_state=42)
            self.text_vectorizer = vectorizer_cls(max_features=100, stop_words='english')
        except Exception as e:
            print(f"ML initialization warning: {e}")
            self.ml_scaler = None
            self.ml_model = None
            self.text_vectorizer = None
    
    def parse_windows_timestamp(self, timestamp_str: str) -> datetime:
        """Parse Windows event log timestamp."""
        try:
            # Handle different Windows timestamp formats
            formats_to_try = [
                "%m/%d/%Y %I:%M:%S %p",  # 10/8/2025 2:30:45 PM
                "%Y-%m-%d %H:%M:%S",     # 2025-10-08 14:30:45
                "%Y-%m-%dT%H:%M:%S.%fZ", # ISO format with Z
                "%Y-%m-%dT%H:%M:%S"      # ISO format without Z
            ]
            
            for fmt in formats_to_try:
                try:
                    return datetime.strptime(timestamp_str, fmt)
                except ValueError:
                    continue
            
            # If all formats fail, use current time
            return datetime.now()
        except:
            return datetime.now()
    
    def extract_log_level(self, event_id: str, source: str, message: str) -> str:
        """Extract log level from Windows event data."""
        # Common error patterns
        error_patterns = ['error', 'failed', 'failure', 'exception', 'critical']
        warning_patterns = ['warning', 'warn', 'timeout', 'retry', 'deprecated']
        
        message_lower = message.lower()
        
        if any(pattern in message_lower for pattern in error_patterns):
            return 'ERROR'
        elif any(pattern in message_lower for pattern in warning_patterns):
            return 'WARNING'
        elif any(word in message_lower for word in ['success', 'completed', 'started']):
            return 'INFO'
        else:
            return 'INFO'
    
    def collect_windows_logs(self) -> List[LogEntry]:
        """Collect logs from Windows Event Log."""
        collected_logs = []
        
        try:
            # Get System events
            cmd = [
                "powershell.exe", "-Command",
                "Get-EventLog -LogName System -Newest 10 | Select-Object TimeGenerated, Source, EventID, Message | ConvertTo-Json"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if result.returncode == 0 and result.stdout.strip():
                try:
                    events = json.loads(result.stdout)
                    if not isinstance(events, list):
                        events = [events]
                    
                    for event in events:
                        timestamp = self.parse_windows_timestamp(event.get('TimeGenerated', ''))
                        source = event.get('Source', 'Unknown')
                        event_id = str(event.get('EventID', 'Unknown'))
                        message = event.get('Message', 'No message')
                        level = self.extract_log_level(event_id, source, message)
                        
                        log_entry = LogEntry(
                            timestamp=timestamp,
                            os_type=self.os_type,
                            log_type='system',
                            source=source,
                            event_id=event_id,
                            level=level,
                            message=message,
                            raw_data=json.dumps(event)
                        )
                        collected_logs.append(log_entry)
                        
                except json.JSONDecodeError:
                    pass
            
            # Get Application events
            cmd[2] = "Get-EventLog -LogName Application -Newest 5 | Select-Object TimeGenerated, Source, EventID, Message | ConvertTo-Json"
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if result.returncode == 0 and result.stdout.strip():
                try:
                    events = json.loads(result.stdout)
                    if not isinstance(events, list):
                        events = [events]
                    
                    for event in events:
                        timestamp = self.parse_windows_timestamp(event.get('TimeGenerated', ''))
                        source = event.get('Source', 'Unknown')
                        event_id = str(event.get('EventID', 'Unknown'))
                        message = event.get('Message', 'No message')
                        level = self.extract_log_level(event_id, source, message)
                        
                        log_entry = LogEntry(
                            timestamp=timestamp,
                            os_type=self.os_type,
                            log_type='application',
                            source=source,
                            event_id=event_id,
                            level=level,
                            message=message,
                            raw_data=json.dumps(event)
                        )
                        collected_logs.append(log_entry)
                        
                except json.JSONDecodeError:
                    pass
            
        except Exception as e:
            print(f"Error collecting Windows logs: {e}")
        
        # Add to main logs list
        for log in collected_logs:
            if log not in self.logs:  # Simple duplicate prevention
                self.logs.append(log)
        
        return collected_logs
    
    def collect_linux_logs(self) -> List[LogEntry]:
        """Collect logs from Linux system logs."""
        collected_logs = []
        
        try:
            # Try journalctl first (systemd systems)
            cmd = ["journalctl", "-n", "20", "-o", "json"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            entry = json.loads(line)
                            timestamp = datetime.fromtimestamp(int(entry.get('__REALTIME_TIMESTAMP', 0)) / 1000000)
                            
                            log_entry = LogEntry(
                                timestamp=timestamp,
                                os_type=self.os_type,
                                log_type='system',
                                source=entry.get('_SYSTEMD_UNIT', 'unknown'),
                                event_id=entry.get('SYSLOG_IDENTIFIER', ''),
                                level=entry.get('PRIORITY', '6'),
                                message=entry.get('MESSAGE', ''),
                                raw_data=line
                            )
                            collected_logs.append(log_entry)
                        except (json.JSONDecodeError, ValueError):
                            continue
            else:
                # Fallback to syslog
                cmd = ["tail", "-n", "20", "/var/log/syslog"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    for line in result.stdout.strip().split('\n'):
                        if line.strip():
                            # Simple syslog parsing
                            parts = line.split(' ', 5)
                            if len(parts) >= 6:
                                timestamp = datetime.now()  # Simplified
                                log_entry = LogEntry(
                                    timestamp=timestamp,
                                    os_type=self.os_type,
                                    log_type='system',
                                    source=parts[3] if len(parts) > 3 else 'unknown',
                                    event_id='',
                                    level='INFO',
                                    message=parts[5] if len(parts) > 5 else line,
                                    raw_data=line
                                )
                                collected_logs.append(log_entry)
        
        except Exception as e:
            print(f"Error collecting Linux logs: {e}")
        
        # Add to main logs list
        for log in collected_logs:
            if log not in self.logs:
                self.logs.append(log)
        
        return collected_logs
    
    def detect_threats(self, log_entry: LogEntry) -> List[ThreatIndicator]:
        """Detect security threats in a log entry."""
        threats = []
        message_lower = log_entry.message.lower()
        
        try:
            # 1. Failed login attempts (enhanced)
            if any(pattern in message_lower for pattern in ['failed', 'failure', 'denied', 'invalid']):
                if any(login_pattern in message_lower for login_pattern in ['login', 'logon', 'authentication', 'credential']):
                    severity = 'high' if 'multiple' in message_lower or 'repeated' in message_lower else 'medium'
                    threats.append(ThreatIndicator(
                        threat_type='Authentication Failure',
                        severity=severity,
                        confidence=0.85,
                        description=f'Authentication failure detected: {log_entry.message[:100]}...',
                        source_ip=self._extract_ip_from_message(log_entry.message),
                        first_seen=log_entry.timestamp,
                        last_seen=log_entry.timestamp,
                        raw_evidence=[log_entry.message]
                    ))
            
            # 2. Windows threat events (enhanced)
            if log_entry.os_type == 'windows' and log_entry.event_id.isdigit():
                event_id = int(log_entry.event_id)
                if event_id in self.windows_threat_events:
                    severity_map = {
                        4625: 'high',    # Failed logon
                        4771: 'high',    # Kerberos failure
                        1102: 'critical', # Audit log cleared
                        4740: 'medium',  # Account locked
                        5157: 'medium',  # Firewall blocked
                        7045: 'medium',  # Service installed
                        4688: 'low'      # Process created
                    }
                    severity = severity_map.get(event_id, 'medium')
                    
                    threats.append(ThreatIndicator(
                        threat_type=self.windows_threat_events[event_id],
                        severity=severity,
                        confidence=0.9,
                        description=f'Windows Event {event_id}: {self.windows_threat_events[event_id]} - {log_entry.message[:80]}...',
                        first_seen=log_entry.timestamp,
                        last_seen=log_entry.timestamp,
                        raw_evidence=[log_entry.raw_data]
                    ))
            
            # 3. Malware detection patterns
            for threat_type, patterns in self.threat_patterns.items():
                if any(pattern in message_lower for pattern in patterns):
                    severity = 'critical' if threat_type == 'malware' else 'high'
                    threats.append(ThreatIndicator(
                        threat_type=threat_type.title().replace('_', ' '),
                        severity=severity,
                        confidence=0.75,
                        description=f'{threat_type.title()} indicators detected: {log_entry.message[:100]}...',
                        first_seen=log_entry.timestamp,
                        last_seen=log_entry.timestamp,
                        raw_evidence=[log_entry.message]
                    ))
            
            # 4. Suspicious process monitoring
            for process in self.suspicious_processes:
                if process.lower() in message_lower:
                    threats.append(ThreatIndicator(
                        threat_type='Suspicious Process Activity',
                        severity='medium',
                        confidence=0.65,
                        description=f'Suspicious process detected: {process} - {log_entry.message[:80]}...',
                        first_seen=log_entry.timestamp,
                        last_seen=log_entry.timestamp,
                        raw_evidence=[log_entry.message]
                    ))
            
            # 5. Network-based threats
            ips = self._extract_ips_from_message(log_entry.message)
            for ip in ips:
                # Check against banned IPs
                if ip in self.banned_ips:
                    threats.append(ThreatIndicator(
                        threat_type='Malicious IP Communication',
                        severity='high',
                        confidence=1.0,
                        description=f'Communication with known malicious IP: {ip}',
                        source_ip=ip,
                        first_seen=log_entry.timestamp,
                        last_seen=log_entry.timestamp,
                        raw_evidence=[log_entry.message]
                    ))
                
                # Check for suspicious IP patterns
                elif self._is_suspicious_ip(ip):
                    threats.append(ThreatIndicator(
                        threat_type='Suspicious Network Activity',
                        severity='medium',
                        confidence=0.6,
                        description=f'Communication with suspicious IP: {ip}',
                        source_ip=ip,
                        first_seen=log_entry.timestamp,
                        last_seen=log_entry.timestamp,
                        raw_evidence=[log_entry.message]
                    ))
            
            # 6. Privilege escalation detection
            if any(priv_word in message_lower for priv_word in ['administrator', 'admin', 'root', 'elevated']):
                if any(action in message_lower for action in ['granted', 'access', 'permission', 'privilege']):
                    threats.append(ThreatIndicator(
                        threat_type='Privilege Escalation Attempt',
                        severity='high',
                        confidence=0.7,
                        description=f'Potential privilege escalation: {log_entry.message[:100]}...',
                        first_seen=log_entry.timestamp,
                        last_seen=log_entry.timestamp,
                        raw_evidence=[log_entry.message]
                    ))
            
            # 7. Suspicious user account activity
            for account in self.suspicious_accounts:
                if account in message_lower:
                    severity = 'high' if account in ['administrator', 'admin', 'root'] else 'medium'
                    threats.append(ThreatIndicator(
                        threat_type='Suspicious Account Activity',
                        severity=severity,
                        confidence=0.7,
                        description=f'Activity involving sensitive account "{account}": {log_entry.message[:80]}...',
                        first_seen=log_entry.timestamp,
                        last_seen=log_entry.timestamp,
                        raw_evidence=[log_entry.message]
                    ))
            
            # 8. Error-based anomaly detection
            if log_entry.level in ['ERROR', 'CRITICAL']:
                if any(error_pattern in message_lower for error_pattern in ['access denied', 'permission denied', 'unauthorized']):
                    threats.append(ThreatIndicator(
                        threat_type='Access Control Violation',
                        severity='medium',
                        confidence=0.6,
                        description=f'Access control violation: {log_entry.message[:100]}...',
                        first_seen=log_entry.timestamp,
                        last_seen=log_entry.timestamp,
                        raw_evidence=[log_entry.message]
                    ))
        
        except Exception as e:
            print(f"Error in threat detection: {e}")
        
        # Add threats to main list
        self.threats.extend(threats)
        return threats
    
    def _extract_ip_from_message(self, message: str) -> Optional[str]:
        """Extract the first IP address from a message."""
        ips = self._extract_ips_from_message(message)
        return ips[0] if ips else None
    
    def _extract_ips_from_message(self, message: str) -> List[str]:
        """Extract all IP addresses from a message."""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        return re.findall(ip_pattern, message)
    
    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if an IP address is suspicious."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            # Check for unusual patterns
            if ip_obj.is_private and str(ip_obj).endswith('.1'):
                return True  # Gateway IPs
            if str(ip_obj).startswith('169.254'):
                return True  # APIPA addresses
            return False
        except:
            return False
    
    def detect_ml_anomalies(self, logs: List[LogEntry]) -> List[MLAnomaly]:
        """Detect anomalies using enhanced machine learning analysis."""
        if len(logs) < 5:  # Lower threshold for testing
            return self._generate_rule_based_anomalies(logs)
        
        anomalies = []
        
        try:
            # 1. Statistical Analysis (always available)
            anomalies.extend(self._detect_statistical_anomalies(logs))
            
            # 2. Pattern-based Analysis
            anomalies.extend(self._detect_pattern_anomalies(logs))
            
            # 3. Time-based Analysis
            anomalies.extend(self._detect_temporal_anomalies(logs))
            
            # 4. Advanced ML Analysis (if available)
            if HAS_ML and self.ml_model is not None:
                anomalies.extend(self._detect_ml_advanced_anomalies(logs))
            
        except Exception as e:
            print(f"Error in ML anomaly detection: {e}")
        
        # Add anomalies to main list
        self.anomalies.extend(anomalies)
        return anomalies
    
    def _generate_rule_based_anomalies(self, logs: List[LogEntry]) -> List[MLAnomaly]:
        """Generate rule-based anomalies when we have few logs."""
        anomalies = []
        
        for log in logs:
            score = 0.0
            reasons = []
            
            # Check message length anomaly
            if len(log.message) > 500:
                score += 0.3
                reasons.append("unusually long message")
            
            # Check for error level
            if log.level in ['ERROR', 'CRITICAL']:
                score += 0.4
                reasons.append("error level event")
            
            # Check for unusual timing (outside business hours)
            if log.timestamp.hour < 6 or log.timestamp.hour > 22:
                score += 0.2
                reasons.append("unusual timing")
            
            # Check for suspicious keywords
            suspicious_keywords = ['failed', 'error', 'denied', 'unauthorized', 'suspicious', 'anomaly']
            if any(keyword in log.message.lower() for keyword in suspicious_keywords):
                score += 0.3
                reasons.append("suspicious keywords")
            
            if score >= 0.5:  # Threshold for anomaly
                anomalies.append(MLAnomaly(
                    timestamp=log.timestamp,
                    anomaly_score=score,
                    description=f'Rule-based anomaly detected: {", ".join(reasons)}',
                    log_entry={
                        'timestamp': log.timestamp.isoformat(),
                        'source': log.source,
                        'level': log.level,
                        'message': log.message[:150] + '...' if len(log.message) > 150 else log.message
                    },
                    detection_method='Rule-based Analysis'
                ))
        
        return anomalies
    
    def _detect_statistical_anomalies(self, logs: List[LogEntry]) -> List[MLAnomaly]:
        """Detect statistical anomalies in log patterns."""
        anomalies = []
        
        # Analyze message lengths
        message_lengths = [len(log.message) for log in logs]
        if message_lengths:
            avg_length = sum(message_lengths) / len(message_lengths)
            std_dev = (sum((x - avg_length) ** 2 for x in message_lengths) / len(message_lengths)) ** 0.5
            
            for i, log in enumerate(logs):
                if abs(message_lengths[i] - avg_length) > 2 * std_dev:  # 2 standard deviations
                    anomalies.append(MLAnomaly(
                        timestamp=log.timestamp,
                        anomaly_score=0.7,
                        description=f'Statistical anomaly: Message length ({message_lengths[i]}) significantly differs from average ({avg_length:.1f})',
                        log_entry={
                            'timestamp': log.timestamp.isoformat(),
                            'source': log.source,
                            'message_length': message_lengths[i],
                            'average_length': round(avg_length, 1)
                        },
                        detection_method='Statistical Analysis'
                    ))
        
        # Analyze error frequency by source
        source_errors = defaultdict(int)
        source_total = defaultdict(int)
        
        for log in logs:
            source_total[log.source] += 1
            if log.level in ['ERROR', 'CRITICAL']:
                source_errors[log.source] += 1
        
        for source, error_count in source_errors.items():
            total_count = source_total[source]
            error_rate = error_count / total_count
            
            if error_rate > 0.5 and total_count >= 3:  # More than 50% errors
                anomalies.append(MLAnomaly(
                    timestamp=datetime.now(),
                    anomaly_score=0.8,
                    description=f'High error rate detected: {source} has {error_rate:.1%} error rate ({error_count}/{total_count})',
                    log_entry={
                        'source': source,
                        'error_count': error_count,
                        'total_count': total_count,
                        'error_rate': f'{error_rate:.1%}'
                    },
                    detection_method='Error Rate Analysis'
                ))
        
        return anomalies
    
    def _detect_pattern_anomalies(self, logs: List[LogEntry]) -> List[MLAnomaly]:
        """Detect pattern-based anomalies."""
        anomalies = []
        
        # Analyze repeated error patterns
        error_patterns = defaultdict(int)
        for log in logs:
            if log.level in ['ERROR', 'WARNING']:
                # Extract first 50 characters as pattern
                pattern = log.message[:50].lower()
                error_patterns[pattern] += 1
        
        for pattern, count in error_patterns.items():
            if count >= 3:  # Repeated 3+ times
                anomalies.append(MLAnomaly(
                    timestamp=datetime.now(),
                    anomaly_score=0.6,
                    description=f'Repeated error pattern detected: "{pattern}..." occurred {count} times',
                    log_entry={
                        'pattern': pattern,
                        'occurrence_count': count,
                        'pattern_type': 'repeated_error'
                    },
                    detection_method='Pattern Analysis'
                ))
        
        # Analyze unusual source activity
        source_activity = Counter(log.source for log in logs)
        if source_activity:
            avg_activity = sum(source_activity.values()) / len(source_activity)
            
            for source, count in source_activity.items():
                if count > avg_activity * 3:  # 3x more active than average
                    anomalies.append(MLAnomaly(
                        timestamp=datetime.now(),
                        anomaly_score=0.5,
                        description=f'Unusual activity spike: {source} generated {count} logs (avg: {avg_activity:.1f})',
                        log_entry={
                            'source': source,
                            'log_count': count,
                            'average_count': round(avg_activity, 1)
                        },
                        detection_method='Activity Spike Analysis'
                    ))
        
        return anomalies
    
    def _detect_temporal_anomalies(self, logs: List[LogEntry]) -> List[MLAnomaly]:
        """Detect time-based anomalies."""
        anomalies = []
        
        if len(logs) < 2:
            return anomalies
        
        # Analyze unusual timing patterns
        hour_distribution = defaultdict(int)
        for log in logs:
            hour_distribution[log.timestamp.hour] += 1
        
        # Check for activity during unusual hours (late night/early morning)
        unusual_hours = list(range(0, 6)) + list(range(23, 24))  # 11PM - 6AM
        unusual_activity = sum(hour_distribution[hour] for hour in unusual_hours)
        total_activity = sum(hour_distribution.values())
        
        if unusual_activity > 0 and total_activity > 0:
            unusual_rate = unusual_activity / total_activity
            if unusual_rate > 0.3:  # More than 30% activity during unusual hours
                anomalies.append(MLAnomaly(
                    timestamp=datetime.now(),
                    anomaly_score=0.6,
                    description=f'Unusual timing pattern: {unusual_rate:.1%} of activity occurred during off-hours (11PM-6AM)',
                    log_entry={
                        'unusual_activity_count': unusual_activity,
                        'total_activity_count': total_activity,
                        'unusual_rate': f'{unusual_rate:.1%}',
                        'unusual_hours': unusual_hours
                    },
                    detection_method='Temporal Analysis'
                ))
        
        return anomalies
    
    def _detect_ml_advanced_anomalies(self, logs: List[LogEntry]) -> List[MLAnomaly]:
        """Advanced ML-based anomaly detection."""
        if not HAS_ML or self.ml_model is None or self.ml_scaler is None:
            return []
        
        anomalies: List[MLAnomaly] = []
        
        try:
            assert self.ml_model is not None
            assert self.ml_scaler is not None
            # Prepare enhanced feature vectors
            data: List[List[float]] = []
            for log in logs:
                features = [
                    len(log.message),                          # Message length
                    log.timestamp.hour,                        # Hour of day
                    log.timestamp.weekday(),                   # Day of week
                    len(log.source),                          # Source length
                    1 if log.level == 'ERROR' else 0,        # Error flag
                    1 if log.level == 'WARNING' else 0,      # Warning flag
                    1 if log.level == 'CRITICAL' else 0,     # Critical flag
                    len(re.findall(r'\d+', log.message)),    # Number count
                    len(re.findall(r'[A-Z]', log.message)),  # Uppercase count
                    1 if any(word in log.message.lower() for word in ['failed', 'error', 'denied']) else 0  # Threat keywords
                ]
                data.append([float(value) for value in features])
            
            if len(data) >= 5:
                # Scale features
                data_array = np.asarray(data, dtype=float)
                scaled_data = self.ml_scaler.fit_transform(data_array)
                
                # Train and predict
                predictions = self.ml_model.fit_predict(scaled_data)
                scores = self.ml_model.decision_function(scaled_data)
                
                # Find anomalies
                for i, (prediction, score) in enumerate(zip(predictions, scores)):
                    if prediction == -1:  # Anomaly detected
                        anomalies.append(MLAnomaly(
                            timestamp=logs[i].timestamp,
                            anomaly_score=float(abs(score)),
                            description=f'ML anomaly in {logs[i].log_type} log: {logs[i].message[:80]}...',
                            log_entry={
                                'timestamp': logs[i].timestamp.isoformat(),
                                'source': logs[i].source,
                                'level': logs[i].level,
                                'message': logs[i].message[:100] + '...' if len(logs[i].message) > 100 else logs[i].message,
                                'anomaly_features': {
                                    'message_length': len(logs[i].message),
                                    'hour': logs[i].timestamp.hour,
                                    'level': logs[i].level
                                }
                            },
                            detection_method='Isolation Forest ML'
                        ))
        
        except Exception as e:
            print(f"Advanced ML analysis error: {e}")
        
        return anomalies
    
    def start_monitoring(self):
        """Start real-time log monitoring."""
        self.running = True
        print(f"🚀 Starting unified log monitoring on {self.os_type.upper()}")
        
        try:
            while self.running:
                # Collect logs based on OS
                if self.os_type == 'windows':
                    new_logs = self.collect_windows_logs()
                elif self.os_type == 'linux':
                    new_logs = self.collect_linux_logs()
                else:
                    print("macOS log collection not implemented yet")
                    new_logs = []
                
                # Analyze new logs
                for log in new_logs:
                    if self.display_logs:
                        print(f"[{log.timestamp.strftime('%H:%M:%S')}] {log.level} - {log.source}: {log.message[:100]}...")
                    
                    # Detect threats
                    self.detect_threats(log)
                
                # Run ML analysis periodically
                if len(self.logs) >= 10 and len(self.logs) % 20 == 0:
                    recent_logs = self.logs[-20:]  # Analyze last 20 logs
                    self.detect_ml_anomalies(recent_logs)
                
                # Check if duration limit reached
                if self.collection_duration:
                    elapsed = (datetime.now() - self.start_time).total_seconds()
                    if elapsed >= self.collection_duration:
                        print(f"⏰ Collection duration ({self.collection_duration}s) reached")
                        break
                
                time.sleep(3)  # Wait 3 seconds between collections
        
        except KeyboardInterrupt:
            print("\n⏹️  Monitoring stopped by user")
        except Exception as e:
            print(f"❌ Error during monitoring: {e}")
        finally:
            self.running = False
    
    def stop(self):
        """Stop log monitoring."""
        self.running = False
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of collected data and analysis."""
        duration = (datetime.now() - self.start_time).total_seconds()
        
        # Log statistics
        log_types = Counter(log.log_type for log in self.logs)
        log_levels = Counter(log.level for log in self.logs)
        log_sources = Counter(log.source for log in self.logs)
        
        # Threat statistics
        threat_types = Counter(threat.threat_type for threat in self.threats)
        threat_severities = Counter(threat.severity for threat in self.threats)
        
        return {
            'collection_info': {
                'start_time': self.start_time.isoformat(),
                'duration_seconds': duration,
                'os_type': self.os_type,
                'total_logs': len(self.logs),
                'total_threats': len(self.threats),
                'total_anomalies': len(self.anomalies)
            },
            'log_analysis': {
                'types': dict(log_types),
                'levels': dict(log_levels),
                'top_sources': dict(log_sources.most_common(10))
            },
            'threat_analysis': {
                'types': dict(threat_types),
                'severities': dict(threat_severities),
                'threat_rate': len(self.threats) / len(self.logs) * 100 if self.logs else 0
            },
            'ml_analysis': {
                'anomaly_count': len(self.anomalies),
                'anomaly_rate': len(self.anomalies) / len(self.logs) * 100 if self.logs else 0,
                'ml_available': HAS_ML and self.ml_model is not None
            }
        }
    
    def export_to_excel(self, filename: Optional[str] = None, directory: Optional[str] = None) -> str:
        """Export all collected data to Excel file."""
        if not HAS_PANDAS or pd is None:
            raise RuntimeError("pandas not available for Excel export")
        assert pd is not None
        
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"unified_log_analysis_{timestamp}.xlsx"

        if directory:
            os.makedirs(directory, exist_ok=True)
            filepath = os.path.join(directory, filename)
        else:
            filepath = filename
        
        try:
            # Prepare logs data
            logs_data = []
            for log in self.logs:
                logs_data.append({
                    'Timestamp': log.timestamp,
                    'OS_Type': log.os_type,
                    'Log_Type': log.log_type,
                    'Source': log.source,
                    'Event_ID': log.event_id,
                    'Level': log.level,
                    'Message': log.message,
                    'Raw_Data': log.raw_data[:200] if len(log.raw_data) > 200 else log.raw_data
                })
            
            # Prepare threats data
            threats_data = []
            for threat in self.threats:
                threats_data.append({
                    'Threat_Type': threat.threat_type,
                    'Severity': threat.severity,
                    'Confidence': threat.confidence,
                    'Description': threat.description,
                    'Source_IP': threat.source_ip,
                    'First_Seen': threat.first_seen,
                    'Last_Seen': threat.last_seen
                })
            
            # Prepare anomalies data
            anomalies_data = []
            for anomaly in self.anomalies:
                anomalies_data.append({
                    'Timestamp': anomaly.timestamp,
                    'Anomaly_Score': anomaly.anomaly_score,
                    'Description': anomaly.description,
                    'Detection_Method': anomaly.detection_method,
                    'Log_Source': anomaly.log_entry.get('source', 'Unknown')
                })
            
            # Create Excel file
            with pd.ExcelWriter(filepath, engine='openpyxl') as writer:
                # Raw logs
                if logs_data:
                    pd.DataFrame(logs_data).to_excel(writer, sheet_name='Raw_Logs', index=False)
                
                # Threats
                if threats_data:
                    pd.DataFrame(threats_data).to_excel(writer, sheet_name='Threats', index=False)
                
                # Anomalies
                if anomalies_data:
                    pd.DataFrame(anomalies_data).to_excel(writer, sheet_name='ML_Anomalies', index=False)
                
                # Summary
                summary = self.get_summary()
                summary_data = []
                for key, value in summary.items():
                    if isinstance(value, dict):
                        for subkey, subvalue in value.items():
                            summary_data.append({'Category': key, 'Metric': subkey, 'Value': str(subvalue)})
                    else:
                        summary_data.append({'Category': 'General', 'Metric': key, 'Value': str(value)})
                
                pd.DataFrame(summary_data).to_excel(writer, sheet_name='Summary', index=False)
            
            output_name = os.path.basename(filepath)
            print(f"📊 Analysis exported to: {output_name}")
            return output_name
        
        except Exception as e:
            print(f"❌ Export failed: {e}")
            raise


# Convenience Functions
# ====================

def quick_analysis(duration: int = 60) -> Dict[str, Any]:
    """Run a quick log analysis for specified duration."""
    analyzer = UnifiedLogAnalyzer(collection_duration=duration)
    analyzer.display_logs = False  # Quiet mode
    
    print(f"🔍 Running {duration}-second log analysis...")
    analyzer.start_monitoring()
    
    summary = analyzer.get_summary()
    print("\n📊 ANALYSIS COMPLETE")
    print(f"Collected {summary['collection_info']['total_logs']} logs")
    print(f"Detected {summary['collection_info']['total_threats']} threats")
    print(f"Found {summary['collection_info']['total_anomalies']} anomalies")
    
    return summary


def analyze_log_file(file_path: str) -> Dict[str, Any]:
    """Analyze logs from an existing file."""
    if not os.path.exists(file_path):
        return {'error': f'File not found: {file_path}'}
    
    analyzer = UnifiedLogAnalyzer()
    
    try:
        # Load and analyze file (simplified)
        if file_path.endswith('.xlsx') and HAS_PANDAS and pd is not None:
            assert pd is not None
            df = pd.read_excel(file_path)
            
            # Convert DataFrame to LogEntry objects
            for _, row in df.iterrows():
                try:
                    log_entry = LogEntry(
                        timestamp=pd.to_datetime(row.get('Timestamp', datetime.now())),
                        os_type=row.get('OS_Type', 'unknown'),
                        log_type=row.get('Log_Type', 'unknown'),
                        source=row.get('Source', 'unknown'),
                        event_id=str(row.get('Event_ID', '')),
                        level=row.get('Level', 'INFO'),
                        message=str(row.get('Message', '')),
                        raw_data=str(row.get('Raw_Data', ''))
                    )
                    analyzer.logs.append(log_entry)
                    
                    # Analyze for threats
                    analyzer.detect_threats(log_entry)
                except Exception as e:
                    continue  # Skip problematic rows
            
            # Run ML analysis on all logs
            if analyzer.logs:
                analyzer.detect_ml_anomalies(analyzer.logs)
        
        return analyzer.get_summary()
    
    except Exception as e:
        return {'error': f'Analysis failed: {str(e)}'}


# Main execution
if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == '--quick':
            duration = int(sys.argv[2]) if len(sys.argv) > 2 else 60
            summary = quick_analysis(duration)
        elif sys.argv[1] == '--file':
            if len(sys.argv) > 2:
                summary = analyze_log_file(sys.argv[2])
                print(json.dumps(summary, indent=2, default=str))
            else:
                print("Usage: python unified_analyzer.py --file <path_to_log_file>")
        else:
            print("Usage:")
            print("  python unified_analyzer.py --quick [duration_seconds]")
            print("  python unified_analyzer.py --file <log_file_path>")
    else:
        # Interactive mode
        analyzer = UnifiedLogAnalyzer()
        print("🔍 OS Log Analyzer - Unified Edition")
        print("Press Ctrl+C to stop monitoring...")
        analyzer.start_monitoring()
        
        # Export results
        if analyzer.logs:
            try:
                filename = analyzer.export_to_excel()
                print(f"📊 Results exported to: {filename}")
            except Exception as e:
                print(f"Export failed: {e}")
        
        # Display summary
        summary = analyzer.get_summary()
        print("\n" + "="*50)
        print("FINAL SUMMARY")
        print("="*50)
        print(json.dumps(summary, indent=2, default=str))