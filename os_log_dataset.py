#!/usr/bin/env python3
"""
OS Log Monitor with Excel Dataset Export
=========================================

This enhanced version of the OS log monitor collects system logs and exports them 
to Excel files for analysis. Includes data structuring, analysis features, and 
multiple export formats.

Features:
- Real-time log monitoring and collection
- Structured data storage with timestamps, sources, event IDs
- Excel export with multiple worksheets
- Basic log analysis and statistics
- Configurable collection duration
- Cross-platform support (Windows, Linux, macOS)

Requirements:
- pandas: for data manipulation and Excel export
- openpyxl: for Excel file creation
- Standard Python libraries for OS detection and log monitoring

Author: OS Log Monitor Dataset Edition
Date: September 26, 2025
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
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from dataclasses import dataclass
from collections import defaultdict, Counter

import pandas as pd


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
    
    def to_dataframe(self) -> pd.DataFrame:
        """Convert logs to pandas DataFrame."""
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


class EnhancedOSLogMonitor:
    """Enhanced OS Log Monitor with dataset creation capabilities."""
    
    def __init__(self, collection_duration: Optional[int] = None):
        self.running = False
        self.os_type = self.detect_os()
        self.log_process: Optional[subprocess.Popen] = None
        self.dataset = LogDataset()
        self.collection_duration = collection_duration  # seconds
        self.display_logs = True
        
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
        """Monitor Windows Event Logs and collect data for dataset."""
        try:
            print("Starting Windows Event Log monitoring for dataset collection...")
            print("Collecting structured data for Excel export...")
            print()
            
            last_system_event_id = None
            last_app_event_id = None
            
            while self.running:
                try:
                    # Get recent System events
                    cmd = [
                        "powershell.exe",
                        "-Command",
                        "Get-EventLog -LogName System -Newest 10 | Select-Object TimeGenerated, Source, EventID, EntryType, Message | ConvertTo-Json"
                    ]
                    
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                    if result.returncode == 0 and result.stdout.strip():
                        try:
                            events = json.loads(result.stdout)
                            if not isinstance(events, list):
                                events = [events]
                            
                            for event in events:
                                event_time = self.parse_windows_timestamp(str(event.get('TimeGenerated', '')))
                                source = event.get('Source', 'Unknown')
                                event_id = str(event.get('EventID', 'Unknown'))
                                entry_type = event.get('EntryType', 'Information')
                                message = event.get('Message', 'No message')
                                
                                # Convert entry type to level
                                if entry_type and isinstance(entry_type, str):
                                    level = entry_type.lower()
                                elif entry_type and isinstance(entry_type, int):
                                    # Map numeric entry types to level names
                                    entry_type_map = {1: 'error', 2: 'warning', 4: 'info', 8: 'success', 16: 'audit'}
                                    level = entry_type_map.get(entry_type, 'info')
                                else:
                                    level = self.extract_log_level(event_id, source, message)
                                
                                # Create log entry
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
                                
                                # Add to dataset
                                self.dataset.add_log(log_entry)
                                
                                # Display if enabled
                                if self.display_logs:
                                    print(f"[SYSTEM] {event_time.strftime('%H:%M:%S')} | {source} | ID:{event_id} | {level.upper()}")
                                    if len(message) > 100:
                                        print(f"  {message[:100]}...")
                                    else:
                                        print(f"  {message}")
                                    print("-" * 80)
                                
                        except json.JSONDecodeError as e:
                            if self.display_logs:
                                print(f"JSON parsing error for system events: {e}")
                    
                    # Get recent Application events
                    cmd[2] = "Get-EventLog -LogName Application -Newest 5 | Select-Object TimeGenerated, Source, EventID, EntryType, Message | ConvertTo-Json"
                    
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
                    if result.returncode == 0 and result.stdout.strip():
                        try:
                            events = json.loads(result.stdout)
                            if not isinstance(events, list):
                                events = [events]
                            
                            for event in events:
                                event_time = self.parse_windows_timestamp(str(event.get('TimeGenerated', '')))
                                source = event.get('Source', 'Unknown')
                                event_id = str(event.get('EventID', 'Unknown'))
                                entry_type = event.get('EntryType', 'Information')
                                message = event.get('Message', 'No message')
                                
                                if entry_type and isinstance(entry_type, str):
                                    level = entry_type.lower()
                                elif entry_type and isinstance(entry_type, int):
                                    entry_type_map = {1: 'error', 2: 'warning', 4: 'info', 8: 'success', 16: 'audit'}
                                    level = entry_type_map.get(entry_type, 'info')
                                else:
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


def main():
    """Main entry point for dataset collection."""
    import argparse
    
    parser = argparse.ArgumentParser(description='OS Log Monitor - Dataset Collection Mode')
    parser.add_argument('--duration', '-d', type=int, help='Collection duration in seconds')
    parser.add_argument('--quiet', '-q', action='store_true', help='Quiet mode - minimal output')
    parser.add_argument('--output', '-o', type=str, help='Output Excel filename')
    
    args = parser.parse_args()
    
    monitor = EnhancedOSLogMonitor(collection_duration=args.duration)
    monitor.start_collection(quiet_mode=args.quiet)


if __name__ == "__main__":
    main()