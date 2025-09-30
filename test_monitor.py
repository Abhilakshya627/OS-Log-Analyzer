#!/usr/bin/env python3
"""
OS Log Monitor - Quick Test
============================

This script demonstrates the OS log monitoring functionality with a short run time.
It will run for 30 seconds and then automatically stop to show you how it works.
"""

import time
import threading
from os_log_monitor import OSLogMonitor


def auto_stop_monitor(monitor, duration=30):
    """Automatically stop the monitor after specified duration."""
    time.sleep(duration)
    print(f"\n\n[AUTO-STOP] Stopping monitor after {duration} seconds...")
    monitor.stop()


def main():
    """Run a quick test of the log monitor."""
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
    print("To run the full monitor, use: python os_log_monitor.py")


if __name__ == "__main__":
    main()