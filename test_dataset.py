#!/usr/bin/env python3
"""
Quick Dataset Test - 1 Minute Collection
=========================================

Test script to verify the dataset collection functionality with a 1-minute collection.
"""

from os_log_dataset import EnhancedOSLogMonitor
from datetime import datetime


def main():
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


if __name__ == "__main__":
    main()