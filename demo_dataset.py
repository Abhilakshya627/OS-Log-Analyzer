#!/usr/bin/env python3
"""
Quick Dataset Collection Demo
=============================

This script demonstrates the dataset collection functionality with a 2-minute collection
and immediate Excel export. Perfect for testing the feature.
"""

from os_log_dataset import EnhancedOSLogMonitor
from datetime import datetime


def main():
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


if __name__ == "__main__":
    main()