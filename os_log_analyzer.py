#!/usr/bin/env python3
"""
OS Log Analyzer - Complete System Log Monitoring and Analysis Tool
=================================================================

This comprehensive tool combines real-time log monitoring, dataset collection, and analysis
capabilities in a single modular application. It provides both interactive and programmatic
interfaces for system log analysis across Windows, Linux, and macOS platforms.

Features:
- Real-time log monitoring with cross-platform support
- Dataset collection with Excel export and analysis
- Interactive launcher with multiple operation modes
- Demo and test modes for safe exploration
- Structured data storage and statistics
- Configurable collection duration and quiet modes
- Comprehensive log analysis and visualization

Requirements:
- pandas>=1.3.0 (for data manipulation and Excel export)
- openpyxl>=3.0.0 (for Excel file creation)
- Python 3.7+ (required for dataclasses)

Author: OS Log Analyzer - Combined Edition
Date: October 3, 2025
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
import argparse
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from dataclasses import dataclass
from collections import defaultdict, Counter

try:
    import pandas as pd
except ImportError:
    pd = None
    print("Warning: pandas not installed. Excel export functionality will be limited.")


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


# Core Classes
# ============

class LogDataset:
    """Class for managing log data collection and analysis."""
    
    def __init__(self):
        self.logs: List[LogEntry] = []
        self.start_time = datetime.now()
        self.collection_active = False
        
    def add_log(self, log_entry: LogEntry):
        """Add a log entry to the dataset."""
        self.logs.append(log_entry)
        
    def get_logs_count(self) -> int:
        """Get total number of logs collected."""
        return len(self.logs)
    
    def get_collection_duration(self) -> timedelta:
        """Get duration of log collection."""
        return datetime.now() - self.start_time
    
    def get_logs_by_type(self) -> Dict[str, int]:
        """Get count of logs by type."""
        return Counter(log.log_type for log in self.logs)
    
    def get_logs_by_source(self) -> Dict[str, int]:
        """Get count of logs by source."""
        return Counter(log.source for log in self.logs)
    
    def get_logs_by_level(self) -> Dict[str, int]:
        """Get count of logs by level."""
        return Counter(log.level for log in self.logs)
    
    def get_hourly_distribution(self) -> Dict[int, int]:
        """Get hourly distribution of logs."""
        return Counter(log.timestamp.hour for log in self.logs)
    
    def to_dataframe(self):
        """Convert logs to pandas DataFrame."""
        if not pd:
            print("pandas not available for DataFrame conversion")
            return None
            
        if not self.logs:
            return pd.DataFrame()
        
        data = []
        for log in self.logs:
            data.append({
                'Timestamp': log.timestamp,
                'OS_Type': log.os_type,
                'Log_Type': log.log_type,
                'Source': log.source,
                'Event_ID': log.event_id,
                'Level': log.level,
                'Message': log.message[:500],  # Truncate long messages
                'Full_Message': log.message,
                'Raw_Data': log.raw_data[:200] if log.raw_data else ''
            })
        
        return pd.DataFrame(data)


class OSLogMonitor:
    """Core OS Log Monitor class for real-time log monitoring."""
    
    def __init__(self):
        self.running = False
        self.os_type = self.detect_os()
        self.log_process: Optional[subprocess.Popen] = None
        
    def detect_os(self) -> str:
        """Detect the current operating system."""
        system = platform.system().lower()
        
        if system == "windows":
            return "windows"
        elif system == "linux":
            return "linux"
        elif system == "darwin":
            return "macos"
        else:
            return "unknown"
    
    def get_os_info(self) -> dict:
        """Get detailed OS information."""
        return {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "node": platform.node()
        }
    
    def display_os_info(self):
        """Display OS information at startup."""
        info = self.get_os_info()
        print("=" * 60)
        print("OS LOG MONITOR - Real-time System Log Viewer")
        print("=" * 60)
        print(f"Operating System: {info['system']}")
        print(f"Release: {info['release']}")
        print(f"Version: {info['version']}")
        print(f"Machine: {info['machine']}")
        print(f"Node: {info['node']}")
        print(f"Detected OS Type: {self.os_type.upper()}")
        print("=" * 60)
        print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("Press Ctrl+C to stop monitoring...")
        print("=" * 60)
        print()
    
    def monitor_windows_logs(self):
        """Monitor Windows Event Logs using PowerShell."""
        print("Starting Windows Event Log monitoring...")
        print("Using continuous polling method for reliable monitoring...")
        print()
        
        self.monitor_windows_logs_fallback()
    
    def monitor_windows_logs_fallback(self):
        """Enhanced Windows log monitoring using Get-EventLog with real-time feel."""
        try:
            print("Monitoring Windows Event Logs...")
            print("Showing recent events and checking for new ones every 5 seconds...")
            print()
            
            last_system_event_id = None
            last_app_event_id = None
            first_run = True
            
            while self.running:
                try:
                    # Get recent System events
                    cmd = [
                        "powershell.exe",
                        "-Command",
                        "Get-EventLog -LogName System -Newest 10 | Select-Object TimeGenerated, Source, EventID, Message | ConvertTo-Json"
                    ]
                    
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if result.returncode == 0 and result.stdout.strip():
                        try:
                            events = json.loads(result.stdout)
                            if not isinstance(events, list):
                                events = [events]
                            
                            # Show events (newest first from PowerShell)
                            new_events_found = False
                            for event in reversed(events):  # Reverse to show chronologically
                                event_time = event.get('TimeGenerated', 'Unknown')
                                source = event.get('Source', 'Unknown')
                                event_id = event.get('EventID', 'Unknown')
                                message = event.get('Message', 'No message')
                                
                                # Truncate long messages
                                if len(message) > 200:
                                    message = message[:200] + "..."
                                
                                if first_run or (last_system_event_id and event_id != last_system_event_id):
                                    print(f"[SYSTEM] {event_time} | {source} | ID:{event_id}")
                                    print(f"  {message}")
                                    print("-" * 80)
                                    new_events_found = True
                                
                                if not last_system_event_id:
                                    last_system_event_id = event_id
                                    
                        except json.JSONDecodeError:
                            if first_run:
                                print("System events: JSON parsing error, showing raw output:")
                                print(result.stdout[:500])
                    
                    # Get recent Application events
                    cmd[2] = "Get-EventLog -LogName Application -Newest 5 | Select-Object TimeGenerated, Source, EventID, Message | ConvertTo-Json"
                    
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if result.returncode == 0 and result.stdout.strip():
                        try:
                            events = json.loads(result.stdout)
                            if not isinstance(events, list):
                                events = [events]
                            
                            for event in reversed(events):
                                event_time = event.get('TimeGenerated', 'Unknown')
                                source = event.get('Source', 'Unknown')
                                event_id = event.get('EventID', 'Unknown')
                                message = event.get('Message', 'No message')
                                
                                if len(message) > 200:
                                    message = message[:200] + "..."
                                
                                if first_run or (last_app_event_id and event_id != last_app_event_id):
                                    print(f"[APPLICATION] {event_time} | {source} | ID:{event_id}")
                                    print(f"  {message}")
                                    print("-" * 80)
                                
                                if not last_app_event_id:
                                    last_app_event_id = event_id
                                    
                        except json.JSONDecodeError:
                            if first_run:
                                print("Application events: JSON parsing error")
                    
                    first_run = False
                    
                except subprocess.TimeoutExpired:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] Timeout getting events, retrying...")
                except Exception as e:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] Error: {e}")
                
                # Wait before next check
                if self.running:
                    time.sleep(5)
                    
        except KeyboardInterrupt:
            print("\nMonitoring stopped by user.")
        except Exception as e:
            print(f"Error in Windows log monitoring: {e}")
    
    def monitor_linux_logs(self):
        """Monitor Linux system logs using journalctl."""
        try:
            cmd = ["journalctl", "-f", "--output=short-iso"]
            print("Starting Linux system log monitoring with journalctl...")
            print()
            
            self.log_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            for line in iter(self.log_process.stdout.readline, ''):
                if not self.running:
                    break
                if line.strip():
                    print(f"{line.strip()}")
                    
        except FileNotFoundError:
            # Fallback to tail on log files
            self.monitor_linux_logs_fallback()
        except Exception as e:
            print(f"Error monitoring Linux logs: {e}")
    
    def monitor_linux_logs_fallback(self):
        """Fallback method for Linux using tail on log files."""
        try:
            log_files = [
                "/var/log/syslog",
                "/var/log/messages",
                "/var/log/kern.log"
            ]
            
            # Find available log files
            available_logs = [f for f in log_files if os.path.exists(f)]
            
            if not available_logs:
                print("No accessible log files found. Try running with sudo.")
                return
            
            print(f"Monitoring log files: {', '.join(available_logs)}")
            print()
            
            # Use tail to follow multiple files
            cmd = ["tail", "-f"] + available_logs
            
            self.log_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            for line in iter(self.log_process.stdout.readline, ''):
                if not self.running:
                    break
                if line.strip():
                    print(f"{line.strip()}")
                    
        except Exception as e:
            print(f"Error in fallback Linux log monitoring: {e}")
    
    def monitor_macos_logs(self):
        """Monitor macOS system logs using the 'log' command."""
        try:
            cmd = ["log", "stream", "--predicate", "eventType == logEvent", "--info", "--debug"]
            print("Starting macOS system log monitoring...")
            print()
            
            self.log_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            for line in iter(self.log_process.stdout.readline, ''):
                if not self.running:
                    break
                if line.strip():
                    print(f"{line.strip()}")
                    
        except Exception as e:
            print(f"Error monitoring macOS logs: {e}")
    
    def signal_handler(self, signum, frame):
        """Handle Ctrl+C gracefully."""
        print("\n\nShutting down log monitor...")
        self.stop()
        sys.exit(0)
    
    def stop(self):
        """Stop the log monitoring."""
        self.running = False
        if self.log_process:
            try:
                self.log_process.terminate()
                self.log_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.log_process.kill()
            except Exception as e:
                print(f"Error stopping log process: {e}")
    
    def start(self):
        """Start the log monitoring based on detected OS."""
        self.running = True
        
        # Set up signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        
        # Display OS information
        self.display_os_info()
        
        # Start appropriate log monitoring
        try:
            if self.os_type == "windows":
                self.monitor_windows_logs()
            elif self.os_type == "linux":
                self.monitor_linux_logs()
            elif self.os_type == "macos":
                self.monitor_macos_logs()
            else:
                print(f"Unsupported operating system: {self.os_type}")
                print("This program supports Windows, Linux, and macOS.")
                
        except KeyboardInterrupt:
            print("\nMonitoring stopped by user.")
        except Exception as e:
            print(f"Error during log monitoring: {e}")
        finally:
            self.stop()


class EnhancedOSLogMonitor(OSLogMonitor):
    """Enhanced OS Log Monitor with dataset creation capabilities."""
    
    def __init__(self, collection_duration: Optional[int] = None):
        super().__init__()
        self.dataset = LogDataset()
        self.collection_duration = collection_duration  # seconds
        self.display_logs = True
        
    def display_os_info(self):
        """Display OS information for dataset collection mode."""
        info = self.get_os_info()
        print("=" * 70)
        print("OS LOG MONITOR - Dataset Collection Mode")
        print("=" * 70)
        print(f"Operating System: {info['system']}")
        print(f"Release: {info['release']}")
        print(f"Version: {info['version']}")
        print(f"Machine: {info['machine']}")
        print(f"Node: {info['node']}")
        print(f"Detected OS Type: {self.os_type.upper()}")
        
        if self.collection_duration:
            print(f"Collection Duration: {self.collection_duration} seconds")
            print(f"Will auto-stop at: {(datetime.now() + timedelta(seconds=self.collection_duration)).strftime('%H:%M:%S')}")
        else:
            print("Collection Duration: Unlimited (until Ctrl+C)")
            
        print("=" * 70)
        print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("Press Ctrl+C to stop and export dataset...")
        print("=" * 70)
        print()
    
    def parse_windows_timestamp(self, timestamp_str: str) -> datetime:
        """Parse Windows timestamp format."""
        try:
            # Handle /Date(timestamp)/ format
            if timestamp_str.startswith('/Date(') and timestamp_str.endswith(')/'):
                timestamp_ms = int(timestamp_str[6:-2])
                return datetime.fromtimestamp(timestamp_ms / 1000)
            else:
                # Try to parse as regular datetime string
                return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except:
            return datetime.now()
    
    def extract_log_level(self, event_id: str, source: str, message: str) -> str:
        """Extract log level based on event ID, source, and message content."""
        message_lower = message.lower()
        
        # Check message content for level indicators
        if any(word in message_lower for word in ['error', 'failed', 'failure', 'exception']):
            return 'error'
        elif any(word in message_lower for word in ['warning', 'warn', 'timeout']):
            return 'warning'
        elif any(word in message_lower for word in ['critical', 'fatal', 'crash']):
            return 'critical'
        else:
            return 'info'
    
    def monitor_windows_logs_for_dataset(self):
        """Monitor Windows logs for dataset collection."""
        try:
            print("Starting Windows log collection for dataset...")
            print("Collecting from System and Application logs...")
            print()
            
            while self.running:
                try:
                    # Get recent System events
                    cmd = [
                        "powershell.exe",
                        "-Command",
                        "Get-EventLog -LogName System -Newest 20 | Select-Object TimeGenerated, Source, EventID, Message | ConvertTo-Json"
                    ]
                    
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                    if result.returncode == 0 and result.stdout.strip():
                        try:
                            events = json.loads(result.stdout)
                            if not isinstance(events, list):
                                events = [events]
                            
                            for event in events:
                                event_time_str = event.get('TimeGenerated', '')
                                event_time = self.parse_windows_timestamp(event_time_str)
                                source = event.get('Source', 'Unknown')
                                event_id = str(event.get('EventID', 'Unknown'))
                                message = event.get('Message', 'No message')
                                level = self.extract_log_level(event_id, source, message)
                                
                                log_entry = LogEntry(
                                    timestamp=event_time,
                                    os_type=self.os_type,
                                    log_type='system',
                                    source=source,
                                    event_id=event_id,
                                    level=level,
                                    message=message,
                                    raw_data=json.dumps(event)
                                )
                                
                                self.dataset.add_log(log_entry)
                                
                                if self.display_logs:
                                    print(f"[SYSTEM] {event_time.strftime('%H:%M:%S')} | {source} | ID:{event_id} | {level.upper()}")
                                    if len(message) > 100:
                                        print(f"  {message[:100]}...")
                                    else:
                                        print(f"  {message}")
                                    print("-" * 80)
                                
                        except json.JSONDecodeError:
                            if self.display_logs:
                                print("JSON parsing error for system events")
                    
                    # Get recent Application events  
                    cmd[2] = "Get-EventLog -LogName Application -Newest 10 | Select-Object TimeGenerated, Source, EventID, Message | ConvertTo-Json"
                    
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                    if result.returncode == 0 and result.stdout.strip():
                        try:
                            events = json.loads(result.stdout)
                            if not isinstance(events, list):
                                events = [events]
                            
                            for event in events:
                                event_time_str = event.get('TimeGenerated', '')
                                event_time = self.parse_windows_timestamp(event_time_str)
                                source = event.get('Source', 'Unknown')
                                event_id = str(event.get('EventID', 'Unknown'))
                                message = event.get('Message', 'No message')
                                level = self.extract_log_level(event_id, source, message)
                                
                                log_entry = LogEntry(
                                    timestamp=event_time,
                                    os_type=self.os_type,
                                    log_type='application',
                                    source=source,
                                    event_id=event_id,
                                    level=level,
                                    message=message,
                                    raw_data=json.dumps(event)
                                )
                                
                                self.dataset.add_log(log_entry)
                                
                                if self.display_logs:
                                    print(f"[APPLICATION] {event_time.strftime('%H:%M:%S')} | {source} | ID:{event_id} | {level.upper()}")
                                    if len(message) > 100:
                                        print(f"  {message[:100]}...")
                                    else:
                                        print(f"  {message}")
                                    print("-" * 80)
                                
                        except json.JSONDecodeError:
                            if self.display_logs:
                                print("JSON parsing error for application events")
                    
                    # Show collection status
                    if self.dataset.get_logs_count() % 20 == 0 and self.dataset.get_logs_count() > 0:
                        duration = self.dataset.get_collection_duration()
                        print(f"\n[DATASET] Collected {self.dataset.get_logs_count()} logs in {duration.total_seconds():.1f} seconds")
                        print(f"[DATASET] Types: {dict(self.dataset.get_logs_by_type())}")
                        print()
                
                except subprocess.TimeoutExpired:
                    if self.display_logs:
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] Timeout getting events, retrying...")
                except Exception as e:
                    if self.display_logs:
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] Error: {e}")
                
                # Wait before next check
                if self.running:
                    time.sleep(3)  # Shorter interval for better data collection
                
        except KeyboardInterrupt:
            print("\nDataset collection stopped by user.")
        except Exception as e:
            print(f"Error in Windows log monitoring: {e}")
    
    def export_to_excel(self, filename: Optional[str] = None) -> str:
        """Export collected logs to Excel file with analysis."""
        if not pd:
            print("Excel export requires pandas. Please install: pip install pandas openpyxl")
            return ""
            
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"os_logs_dataset_{timestamp}.xlsx"
        
        if not filename.endswith('.xlsx'):
            filename += '.xlsx'
        
        filepath = os.path.join(os.getcwd(), filename)
        
        print(f"\nExporting dataset to Excel file: {filename}")
        print("=" * 50)
        
        # Convert to DataFrame
        df = self.dataset.to_dataframe()
        
        if df.empty:
            print("No data collected to export.")
            return ""
        
        with pd.ExcelWriter(filepath, engine='openpyxl') as writer:
            # Main dataset sheet
            df.to_excel(writer, sheet_name='Raw_Logs', index=False)
            
            # Summary statistics sheet
            summary_data = {
                'Collection_Start': [self.dataset.start_time],
                'Collection_End': [datetime.now()],
                'Duration_Seconds': [self.dataset.get_collection_duration().total_seconds()],
                'Total_Logs': [self.dataset.get_logs_count()],
                'OS_Type': [self.os_type],
                'System_Info': [f"{platform.system()} {platform.release()}"]
            }
            summary_df = pd.DataFrame(summary_data)
            summary_df.to_excel(writer, sheet_name='Summary', index=False)
            
            # Log type analysis
            type_counts = self.dataset.get_logs_by_type()
            if type_counts:
                type_df = pd.DataFrame(list(type_counts.items()), columns=['Log_Type', 'Count'])
                type_df.to_excel(writer, sheet_name='Log_Types', index=False)
            
            # Source analysis
            source_counts = self.dataset.get_logs_by_source()
            if source_counts:
                # Get top 20 sources
                top_sources = dict(sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:20])
                source_df = pd.DataFrame(list(top_sources.items()), columns=['Source', 'Count'])
                source_df.to_excel(writer, sheet_name='Top_Sources', index=False)
            
            # Level analysis
            level_counts = self.dataset.get_logs_by_level()
            if level_counts:
                level_df = pd.DataFrame(list(level_counts.items()), columns=['Level', 'Count'])
                level_df.to_excel(writer, sheet_name='Log_Levels', index=False)
            
            # Hourly distribution
            hourly_dist = self.dataset.get_hourly_distribution()
            if hourly_dist:
                hourly_df = pd.DataFrame(list(hourly_dist.items()), columns=['Hour', 'Count'])
                hourly_df = hourly_df.sort_values('Hour')
                hourly_df.to_excel(writer, sheet_name='Hourly_Distribution', index=False)
        
        print(f"✅ Dataset exported successfully!")
        print(f"📁 File location: {filepath}")
        print(f"📊 Total logs: {self.dataset.get_logs_count()}")
        print(f"⏱️  Collection duration: {self.dataset.get_collection_duration().total_seconds():.1f} seconds")
        print(f"📈 Worksheets created:")
        print("   - Raw_Logs: Complete dataset")
        print("   - Summary: Collection statistics")
        print("   - Log_Types: Distribution by type")
        print("   - Top_Sources: Most active sources")
        print("   - Log_Levels: Distribution by severity")
        print("   - Hourly_Distribution: Time-based analysis")
        
        return filepath
    
    def auto_stop_timer(self):
        """Auto-stop the monitoring after specified duration."""
        if self.collection_duration:
            time.sleep(self.collection_duration)
            print(f"\n\n[AUTO-STOP] Collection duration ({self.collection_duration}s) reached.")
            self.stop()
    
    def signal_handler(self, signum, frame):
        """Handle Ctrl+C gracefully."""
        print("\n\nStopping log collection and exporting dataset...")
        self.stop()
    
    def start_collection(self, quiet_mode: bool = False):
        """Start log collection for dataset creation."""
        self.running = True
        self.display_logs = not quiet_mode
        
        # Set up signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        
        # Display OS information
        if not quiet_mode:
            self.display_os_info()
        
        # Start auto-stop timer if duration is set
        if self.collection_duration:
            timer_thread = threading.Thread(target=self.auto_stop_timer)
            timer_thread.daemon = True
            timer_thread.start()
        
        # Start appropriate log monitoring
        try:
            if self.os_type == "windows":
                self.monitor_windows_logs_for_dataset()
            elif self.os_type == "linux":
                print("Linux log collection not yet implemented in dataset mode")
                # TODO: Implement Linux dataset collection
            elif self.os_type == "macos":
                print("macOS log collection not yet implemented in dataset mode")
                # TODO: Implement macOS dataset collection
            else:
                print(f"Unsupported operating system: {self.os_type}")
                return
                
        except KeyboardInterrupt:
            print("\nCollection stopped by user.")
        except Exception as e:
            print(f"Error during log collection: {e}")
        finally:
            self.stop()
            
            # Export dataset
            if self.dataset.get_logs_count() > 0:
                self.export_to_excel()
            else:
                print("No logs collected for export.")


# Interactive Launcher Classes
# ============================

class InteractiveLauncher:
    """Interactive launcher for OS log monitoring operations."""
    
    def __init__(self):
        self.monitor = OSLogMonitor()
    
    def show_main_menu(self):
        """Display the main menu options."""
        print("\n" + "=" * 60)
        print("OS LOG ANALYZER - Interactive Launcher")
        print("=" * 60)
        
        print(f"Detected OS: {self.monitor.os_type.upper()}")
        print(f"System: {self.monitor.get_os_info()['system']} {self.monitor.get_os_info()['release']}")
        
        print("\n🔍 REAL-TIME MONITORING:")
        print("1. Real-time log monitoring (display only)")
        print("2. Quick 30-second test")
        print("3. Show demo (no actual monitoring)")
        
        print("\n📊 DATASET COLLECTION:")
        print("4. Collect logs for 5 minutes → Excel dataset")
        print("5. Collect logs for 15 minutes → Excel dataset")
        print("6. Collect logs for 1 hour → Excel dataset")
        print("7. Custom duration collection → Excel dataset")
        print("8. Continuous collection → Manual stop → Excel dataset")
        
        print("\n📋 INFORMATION:")
        print("9. Show system information")
        print("10. View dataset collection guide")
        
        print("\n❌ EXIT:")
        print("11. Exit")
        print("-" * 60)
    
    def show_dataset_guide(self):
        """Show information about dataset collection."""
        print("\n" + "=" * 60)
        print("DATASET COLLECTION GUIDE")
        print("=" * 60)
        
        print("\n📊 What gets collected:")
        print("• Timestamp of each log entry")
        print("• Log type (System, Application, etc.)")
        print("• Event source and ID")
        print("• Severity level (Info, Warning, Error, Critical)")
        print("• Full message content")
        print("• Raw log data for detailed analysis")
        
        print("\n📁 Excel file structure:")
        print("• Raw_Logs: Complete dataset with all entries")
        print("• Summary: Collection statistics and metadata")
        print("• Log_Types: Distribution by log category")
        print("• Top_Sources: Most active log sources")
        print("• Log_Levels: Distribution by severity level")
        print("• Hourly_Distribution: Time-based log patterns")
        
        print("\n🔍 Analysis possibilities:")
        print("• Identify most frequent error sources")
        print("• Track system activity patterns over time")
        print("• Monitor application behavior and issues")
        print("• Analyze peak activity periods")
        print("• Correlate events across different log types")
        
        print("\n💡 Collection tips:")
        print("• Longer collection = more comprehensive dataset")
        print("• 5-15 minutes good for quick analysis")
        print("• 1+ hours better for pattern identification")
        print("• Run during normal system usage for realistic data")
        
        print("\n📝 File naming:")
        print("• Auto-generated: os_logs_dataset_YYYYMMDD_HHMMSS.xlsx")
        print("• Saved in current directory: " + os.getcwd())
        
        input("\nPress Enter to continue...")
    
    def get_custom_duration(self):
        """Get custom collection duration from user."""
        print("\n" + "=" * 50)
        print("CUSTOM DURATION COLLECTION")
        print("=" * 50)
        
        while True:
            try:
                print("\nEnter collection duration:")
                minutes = input("Minutes (or 'h' for hours, e.g., '2h' or '30'): ").strip()
                
                if minutes.lower().endswith('h'):
                    hours = float(minutes[:-1])
                    seconds = int(hours * 3600)
                    duration_str = f"{hours} hour(s)"
                elif minutes.lower().endswith('m'):
                    mins = float(minutes[:-1])
                    seconds = int(mins * 60)
                    duration_str = f"{mins} minute(s)"
                else:
                    mins = float(minutes)
                    seconds = int(mins * 60)
                    duration_str = f"{mins} minute(s)"
                
                if seconds < 30:
                    print("⚠️  Duration too short. Minimum: 30 seconds (0.5 minutes)")
                    continue
                elif seconds > 86400:  # 24 hours
                    print("⚠️  Duration too long. Maximum: 24 hours")
                    continue
                    
                print(f"\n✅ Collection duration set to: {duration_str}")
                print(f"   Will collect for {seconds} seconds")
                print(f"   Estimated completion: {(datetime.now() + timedelta(seconds=seconds)).strftime('%H:%M:%S')}")
                
                confirm = input("\nProceed with this duration? (y/n): ").strip().lower()
                if confirm in ['y', 'yes']:
                    return seconds
                
            except ValueError:
                print("❌ Invalid input. Please enter a number (e.g., '30' for 30 minutes or '1.5h' for 1.5 hours)")
                continue
            except KeyboardInterrupt:
                print("\nCancelled.")
                return None
    
    def run_dataset_collection(self, duration_seconds: int, description: str):
        """Run dataset collection with specified duration."""
        print(f"\n🚀 Starting dataset collection: {description}")
        print("=" * 60)
        
        if duration_seconds:
            print(f"⏱️  Duration: {duration_seconds} seconds")
            print(f"🏁 Will auto-stop at: {(datetime.now() + timedelta(seconds=duration_seconds)).strftime('%H:%M:%S')}")
        else:
            print("⏱️  Duration: Unlimited (until Ctrl+C)")
        
        print("📊 Data will be exported to Excel automatically when collection stops")
        print("\nPress Ctrl+C anytime to stop and export dataset")
        
        proceed = input("\nPress Enter to start or Ctrl+C to cancel...")
        
        try:
            monitor = EnhancedOSLogMonitor(collection_duration=duration_seconds)
            monitor.start_collection(quiet_mode=False)
        except KeyboardInterrupt:
            print("\nCollection cancelled.")
    
    def run_demo(self):
        """Run a demonstration of log monitor capabilities."""
        print("\n" + "=" * 60)
        print("DEMONSTRATION MODE - No actual log monitoring")
        print("=" * 60)
        
        if self.monitor.os_type == "windows":
            print("Windows detected - Would monitor:")
            print("✓ Windows Event Logs (System and Application)")
            print("✓ Uses PowerShell for real-time event monitoring")
            print("✓ Falls back to polling if real-time fails")
            print("✓ Displays events with timestamp, source, and message")
            print("\nExample output would look like:")
            print("[10/03/2025 5:53:59 PM] [Service Control Manager] [7036] Service started")
            print("[10/03/2025 5:54:02 PM] [APP] [Windows] [1000] Application event")
            
        elif self.monitor.os_type == "linux":
            print("Linux detected - Would monitor:")
            print("✓ System logs via journalctl (preferred)")
            print("✓ Traditional log files (/var/log/syslog, /var/log/messages)")
            print("✓ Real-time log streaming")
            print("✓ Multiple log sources simultaneously")
            print("\nExample output would look like:")
            print("Oct 03 17:53:59 hostname kernel: USB device connected")
            print("Oct 03 17:54:01 hostname systemd: Service started")
            
        elif self.monitor.os_type == "macos":
            print("macOS detected - Would monitor:")
            print("✓ System logs via 'log stream' command")
            print("✓ Real-time event monitoring")
            print("✓ Filtered for relevant system events")
            print("✓ Info and debug level messages")
            print("\nExample output would look like:")
            print("2025-10-03 17:53:59 localhost kernel: Network interface up")
            print("2025-10-03 17:54:01 localhost system: Service event")
            
        else:
            print(f"Unsupported OS: {self.monitor.os_type}")
            print("This program supports Windows, Linux, and macOS only.")
        
        print("\n" + "=" * 60)
        print("TO RUN THE ACTUAL MONITOR:")
        print("python os_log_analyzer.py --monitor")
        print("\nTO COLLECT A DATASET:")
        print("python os_log_analyzer.py --collect --duration 300")
        print("\nPress Ctrl+C to stop monitoring when running the full program.")
        print("=" * 60)
        
        input("\nPress Enter to continue...")
    
    def auto_stop_monitor(self, monitor, duration=30):
        """Automatically stop the monitor after specified duration."""
        time.sleep(duration)
        print(f"\n\n[AUTO-STOP] Stopping monitor after {duration} seconds...")
        monitor.stop()
    
    def run_quick_test(self):
        """Run a quick 30-second test."""
        print("\n" + "=" * 50)
        print("OS Log Monitor - Quick Test (30 seconds)")
        print("=" * 50)
        
        # Start auto-stop timer in background
        stop_thread = threading.Thread(target=self.auto_stop_monitor, args=(self.monitor, 30))
        stop_thread.daemon = True
        stop_thread.start()
        
        # Start monitoring
        try:
            self.monitor.start()
        except KeyboardInterrupt:
            print("\nTest stopped by user.")
        
        print("\nQuick test completed!")
    
    def start(self):
        """Start the interactive launcher."""
        try:
            while True:
                self.show_main_menu()
                choice = input("Enter your choice (1-11): ").strip()
                
                if choice == "1":
                    print("\nStarting full log monitor...")
                    print("Press Ctrl+C to stop monitoring.")
                    input("Press Enter to continue or Ctrl+C to cancel...")
                    self.monitor.start()
                    break
                    
                elif choice == "2":
                    print("\nStarting 30-second test...")
                    input("Press Enter to continue or Ctrl+C to cancel...")
                    self.run_quick_test()
                    
                elif choice == "3":
                    self.run_demo()
                    
                elif choice == "4":
                    self.run_dataset_collection(300, "5-minute collection")
                    
                elif choice == "5":
                    self.run_dataset_collection(900, "15-minute collection")
                    
                elif choice == "6":
                    self.run_dataset_collection(3600, "1-hour collection")
                    
                elif choice == "7":
                    duration = self.get_custom_duration()
                    if duration:
                        self.run_dataset_collection(duration, f"Custom {duration}s collection")
                        
                elif choice == "8":
                    self.run_dataset_collection(None, "Continuous collection")
                    
                elif choice == "9":
                    print("\nSystem Information:")
                    self.monitor.display_os_info()
                    input("\nPress Enter to continue...")
                    
                elif choice == "10":
                    self.show_dataset_guide()
                    
                elif choice == "11":
                    print("Goodbye!")
                    break
                    
                else:
                    print("Invalid choice. Please enter 1-11.")
                    input("Press Enter to continue...")
                    
        except KeyboardInterrupt:
            print("\n\nLauncher interrupted by user. Goodbye!")
        except Exception as e:
            print(f"\nError: {e}")
            input("Press Enter to exit...")


# Demo and Test Functions  
# =======================

def run_dataset_demo():
    """Run a quick dataset collection demo."""
    print("=" * 60)
    print("QUICK DATASET COLLECTION DEMO")
    print("=" * 60)
    print("This demo will:")
    print("✅ Collect OS logs for 2 minutes")
    print("✅ Structure the data for analysis")
    print("✅ Export to Excel with multiple worksheets")
    print("✅ Show collection statistics")
    print()
    print("The Excel file will contain:")
    print("📊 Raw logs with timestamps, sources, events")
    print("📈 Analysis worksheets with summaries")
    print("📋 Statistics and distributions")
    print("=" * 60)
    
    proceed = input("\nStart 2-minute demo collection? (y/n): ").strip().lower()
    
    if proceed not in ['y', 'yes']:
        print("Demo cancelled.")
        return
    
    print(f"\n🚀 Starting demo collection at {datetime.now().strftime('%H:%M:%S')}")
    print("Collection will auto-stop after 2 minutes...")
    print()
    
    try:
        # Create monitor with 2-minute duration
        monitor = EnhancedOSLogMonitor(collection_duration=120)
        monitor.start_collection(quiet_mode=False)
        
    except KeyboardInterrupt:
        print("\nDemo stopped by user.")
    except Exception as e:
        print(f"Error during demo: {e}")
    
    print("\n" + "=" * 60)
    print("DEMO COMPLETED!")
    print("Check the generated Excel file for your log dataset.")
    print("=" * 60)


def run_dataset_test():
    """Run a quick 1-minute dataset collection test."""
    print("=" * 60)
    print("QUICK DATASET TEST - 1 Minute Collection")
    print("=" * 60)
    print("This will collect logs for 1 minute and export to Excel.")
    print("Perfect for testing the functionality!")
    print()
    
    proceed = input("Start 1-minute test? (y/n): ").strip().lower()
    
    if proceed not in ['y', 'yes']:
        print("Test cancelled.")
        return
    
    print(f"\n🚀 Starting test collection at {datetime.now().strftime('%H:%M:%S')}")
    print("Collection will auto-stop after 1 minute...")
    print()
    
    try:
        # Create monitor with 1-minute duration
        monitor = EnhancedOSLogMonitor(collection_duration=60)
        monitor.start_collection(quiet_mode=False)
        
    except KeyboardInterrupt:
        print("\nTest stopped by user.")
    except Exception as e:
        print(f"Error during test: {e}")
    
    print("\n" + "=" * 60)
    print("TEST COMPLETED!")
    print("Check the generated Excel file for your log dataset.")
    print("=" * 60)


def run_monitor_test():
    """Run a quick monitor test."""
    def auto_stop_monitor(monitor, duration=30):
        """Automatically stop the monitor after specified duration."""
        time.sleep(duration)
        print(f"\n\n[AUTO-STOP] Stopping monitor after {duration} seconds...")
        monitor.stop()

    print("OS Log Monitor - Quick Test (30 seconds)")
    print("=" * 50)
    
    monitor = OSLogMonitor()
    
    # Start auto-stop timer in background
    stop_thread = threading.Thread(target=auto_stop_monitor, args=(monitor, 30))
    stop_thread.daemon = True
    stop_thread.start()
    
    # Start monitoring
    try:
        monitor.start()
    except KeyboardInterrupt:
        print("\nTest stopped by user.")
    
    print("\nQuick test completed!")
    print("To run the full monitor, use: python os_log_analyzer.py --monitor")


# Main Entry Point and CLI
# ========================

def main():
    """Main entry point with command line argument support."""
    parser = argparse.ArgumentParser(
        description='OS Log Analyzer - Complete System Log Monitoring and Analysis Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python os_log_analyzer.py                          # Interactive launcher
  python os_log_analyzer.py --monitor                # Real-time monitoring
  python os_log_analyzer.py --collect --duration 300 # 5-minute dataset collection
  python os_log_analyzer.py --demo                   # Show demo
  python os_log_analyzer.py --test                   # 30-second test
  python os_log_analyzer.py --dataset-demo           # 2-minute dataset demo
  python os_log_analyzer.py --dataset-test           # 1-minute dataset test
        """
    )
    
    # Operation modes
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--monitor', '-m', action='store_true', 
                       help='Start real-time log monitoring')
    group.add_argument('--collect', '-c', action='store_true',
                       help='Start dataset collection mode')
    group.add_argument('--demo', action='store_true',
                       help='Show monitoring demo (no actual monitoring)')
    group.add_argument('--test', action='store_true', 
                       help='Run 30-second monitoring test')
    group.add_argument('--dataset-demo', action='store_true',
                       help='Run 2-minute dataset collection demo')
    group.add_argument('--dataset-test', action='store_true',
                       help='Run 1-minute dataset collection test')
    
    # Collection options
    parser.add_argument('--duration', '-d', type=int, 
                        help='Collection duration in seconds (for --collect mode)')
    parser.add_argument('--quiet', '-q', action='store_true',
                        help='Quiet mode - minimal output during collection')
    parser.add_argument('--output', '-o', type=str,
                        help='Output Excel filename (for dataset collection)')
    
    # Parse arguments
    args = parser.parse_args()
    
    try:
        # Handle different operation modes
        if args.monitor:
            print("Starting real-time log monitoring...")
            monitor = OSLogMonitor()
            monitor.start()
            
        elif args.collect:
            print("Starting dataset collection mode...")
            monitor = EnhancedOSLogMonitor(collection_duration=args.duration)
            monitor.start_collection(quiet_mode=args.quiet)
            
        elif args.demo:
            print("Running monitoring demonstration...")
            launcher = InteractiveLauncher()
            launcher.run_demo()
            
        elif args.test:
            print("Running monitoring test...")
            run_monitor_test()
            
        elif args.dataset_demo:
            print("Running dataset collection demo...")
            run_dataset_demo()
            
        elif args.dataset_test:
            print("Running dataset collection test...")
            run_dataset_test()
            
        else:
            # No arguments provided, start interactive launcher
            print("Starting interactive launcher...")
            launcher = InteractiveLauncher()
            launcher.start()
            
    except KeyboardInterrupt:
        print("\n\nProgram interrupted by user. Goodbye!")
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()