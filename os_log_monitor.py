#!/usr/bin/env python3
"""
Real-time OS Log Monitor
========================

This program detects the current operating system and displays system logs in real-time.
Supports Windows, Linux, and macOS with platform-specific log reading methods.

Requirements:
- Windows: Uses PowerShell to read Event Logs
- Linux: Uses journalctl or tail on log files
- macOS: Uses the 'log' command

Author: OS Log Monitor
Date: September 26, 2025
"""

import platform
import subprocess
import sys
import threading
import time
import signal
import os
from datetime import datetime
from typing import Optional


class OSLogMonitor:
    """Main class for monitoring OS logs across different platforms."""
    
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
        
        # Use the more reliable fallback method as the primary method
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
                        import json
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
                                    new_events_found = True
                                
                                if not last_app_event_id:
                                    last_app_event_id = event_id
                                    
                        except json.JSONDecodeError:
                            if first_run:
                                print("Application events: JSON parsing error")
                    
                    if first_run:
                        print(f"\n=== Monitoring started at {datetime.now().strftime('%H:%M:%S')} ===")
                        print("Watching for new events... (Press Ctrl+C to stop)")
                        print("=" * 80)
                        first_run = False
                    elif new_events_found:
                        print(f"\n=== New events detected at {datetime.now().strftime('%H:%M:%S')} ===")
                    else:
                        # Show a heartbeat so user knows it's working
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] Monitoring... (no new events)")
                
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
            print("Trying alternative method...")
            self.monitor_windows_logs_simple()
    
    def monitor_windows_logs_simple(self):
        """Simple Windows log monitoring with basic text output."""
        try:
            print("Using simple text-based log monitoring...")
            print()
            
            while self.running:
                # Get recent events in simple format
                cmd = [
                    "powershell.exe",
                    "-Command",
                    "Get-EventLog -LogName System -Newest 3 | Format-List TimeGenerated, Source, EventID, Message"
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    print(f"\n=== System Events at {datetime.now().strftime('%H:%M:%S')} ===")
                    print(result.stdout)
                
                # Application events
                cmd[2] = "Get-EventLog -LogName Application -Newest 2 | Format-List TimeGenerated, Source, EventID, Message"
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    print(f"\n=== Application Events at {datetime.now().strftime('%H:%M:%S')} ===")
                    print(result.stdout)
                
                if self.running:
                    time.sleep(8)
                    
        except Exception as e:
            print(f"Error in simple Windows log monitoring: {e}")
    
    def monitor_linux_logs(self):
        """Monitor Linux system logs using journalctl."""
        try:
            # Try journalctl first (systemd systems)
            cmd = ["journalctl", "-f", "-n", "0"]
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


def main():
    """Main entry point."""
    monitor = OSLogMonitor()
    monitor.start()


if __name__ == "__main__":
    main()