#!/usr/bin/env python3
"""
Enhanced OS Log Monitor Launcher with Dataset Creation
======================================================

Interactive launcher for OS log monitoring with Excel dataset export capabilities.
Provides options for real-time monitoring, dataset collection, and analysis.
"""

import sys
import os
from datetime import datetime, timedelta
from os_log_monitor import OSLogMonitor
from os_log_dataset import EnhancedOSLogMonitor


def show_main_menu():
    """Display the main menu options."""
    print("\n" + "=" * 60)
    print("OS LOG MONITOR - Enhanced Launcher")
    print("=" * 60)
    
    monitor = OSLogMonitor()
    print(f"Detected OS: {monitor.os_type.upper()}")
    print(f"System: {monitor.get_os_info()['system']} {monitor.get_os_info()['release']}")
    
    print("\n🔍 MONITORING OPTIONS:")
    print("1. Real-time log monitoring (display only)")
    print("2. Quick 30-second test")
    print("3. Show demo (no actual monitoring)")
    
    print("\n📊 DATASET COLLECTION OPTIONS:")
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


def show_dataset_guide():
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


def get_custom_duration():
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


def run_dataset_collection(duration_seconds: int, description: str):
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
    
    confirm = input("\nReady to start collection? (y/n): ").strip().lower()
    
    if confirm not in ['y', 'yes']:
        print("Collection cancelled.")
        return
    
    print("\n" + "🟢 STARTING COLLECTION..." + "\n")
    
    try:
        monitor = EnhancedOSLogMonitor(collection_duration=duration_seconds)
        monitor.start_collection(quiet_mode=False)
    except KeyboardInterrupt:
        print("\nCollection interrupted by user.")
    except Exception as e:
        print(f"Error during collection: {e}")


def main():
    """Main interactive launcher."""
    try:
        while True:
            show_main_menu()
            choice = input("Enter your choice (1-11): ").strip()
            
            if choice == "1":
                print("\n🟢 Starting real-time log monitoring...")
                print("This will display logs in real-time without saving to Excel.")
                input("Press Enter to continue or Ctrl+C to cancel...")
                monitor = OSLogMonitor()
                monitor.start()
                
            elif choice == "2":
                print("\n🟢 Starting 30-second test...")
                input("Press Enter to continue...")
                os.system("python test_monitor.py")
                
            elif choice == "3":
                print("\n🟢 Running demonstration...")
                input("Press Enter to continue...")
                os.system("python demo_monitor.py")
                
            elif choice == "4":
                run_dataset_collection(300, "5-minute collection")
                
            elif choice == "5":
                run_dataset_collection(900, "15-minute collection")
                
            elif choice == "6":
                run_dataset_collection(3600, "1-hour collection")
                
            elif choice == "7":
                duration = get_custom_duration()
                if duration:
                    run_dataset_collection(duration, f"Custom {duration//60}-minute collection")
                    
            elif choice == "8":
                run_dataset_collection(None, "Continuous collection")
                
            elif choice == "9":
                print("\n📋 System Information:")
                monitor = OSLogMonitor()
                monitor.display_os_info()
                input("\nPress Enter to continue...")
                
            elif choice == "10":
                show_dataset_guide()
                
            elif choice == "11":
                print("👋 Goodbye!")
                break
                
            else:
                print("❌ Invalid choice. Please enter 1-11.")
                input("Press Enter to continue...")
                
    except KeyboardInterrupt:
        print("\n\n👋 Launcher interrupted by user. Goodbye!")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        input("Press Enter to exit...")


if __name__ == "__main__":
    main()