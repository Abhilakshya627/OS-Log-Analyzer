#!/usr/bin/env python3
"""
OS Log Monitor - Demo
=====================

This script demonstrates what the OS log monitor will do without actually monitoring logs.
Use this to understand the program's capabilities before running the full monitor.
"""

from os_log_monitor import OSLogMonitor
import platform


def main():
    """Run a demonstration of the log monitor capabilities."""
    monitor = OSLogMonitor()
    
    # Show OS information
    monitor.display_os_info()
    
    # Show what would happen based on OS type
    print("DEMONSTRATION MODE - No actual log monitoring")
    print("=" * 60)
    
    if monitor.os_type == "windows":
        print("Windows detected - Would monitor:")
        print("✓ Windows Event Logs (System and Application)")
        print("✓ Uses PowerShell for real-time event monitoring")
        print("✓ Falls back to polling if real-time fails")
        print("✓ Displays events with timestamp, source, and message")
        print("\nExample output would look like:")
        print("[9/26/2025 5:53:59 PM] [Service Control Manager] [7036] Service started")
        print("[9/26/2025 5:54:02 PM] [APP] [Windows] [1000] Application event")
        
    elif monitor.os_type == "linux":
        print("Linux detected - Would monitor:")
        print("✓ System logs via journalctl (preferred)")
        print("✓ Traditional log files (/var/log/syslog, /var/log/messages)")
        print("✓ Real-time log streaming")
        print("✓ Multiple log sources simultaneously")
        print("\nExample output would look like:")
        print("Sep 26 17:53:59 hostname kernel: USB device connected")
        print("Sep 26 17:54:01 hostname systemd: Service started")
        
    elif monitor.os_type == "macos":
        print("macOS detected - Would monitor:")
        print("✓ System logs via 'log stream' command")
        print("✓ Real-time event monitoring")
        print("✓ Filtered for relevant system events")
        print("✓ Info and debug level messages")
        print("\nExample output would look like:")
        print("2025-09-26 17:53:59 localhost kernel: Network interface up")
        print("2025-09-26 17:54:01 localhost system: Service event")
        
    else:
        print(f"Unsupported OS: {monitor.os_type}")
        print("This program supports Windows, Linux, and macOS only.")
    
    print("\n" + "=" * 60)
    print("TO RUN THE ACTUAL MONITOR:")
    print("python os_log_monitor.py")
    print("\nTO RUN A 30-SECOND TEST:")
    print("python test_monitor.py")
    print("\nPress Ctrl+C to stop monitoring when running the full program.")
    print("=" * 60)


if __name__ == "__main__":
    main()