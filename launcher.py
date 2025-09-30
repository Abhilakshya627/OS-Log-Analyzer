#!/usr/bin/env python3
"""
OS Log Monitor - Interactive Launcher
=====================================

This script provides an interactive menu to choose how to run the OS log monitor.
"""

import sys
import os
from os_log_monitor import OSLogMonitor


def show_menu():
    """Display the main menu options."""
    print("\n" + "=" * 50)
    print("OS LOG MONITOR - Interactive Launcher")
    print("=" * 50)
    
    monitor = OSLogMonitor()
    print(f"Detected OS: {monitor.os_type.upper()}")
    print(f"System: {monitor.get_os_info()['system']} {monitor.get_os_info()['release']}")
    
    print("\nChoose an option:")
    print("1. Run full monitor (continuous until Ctrl+C)")
    print("2. Run 30-second test")
    print("3. Show demo (no actual monitoring)")
    print("4. Show system information only")
    print("5. Exit")
    print("-" * 50)


def main():
    """Main interactive launcher."""
    try:
        while True:
            show_menu()
            choice = input("Enter your choice (1-5): ").strip()
            
            if choice == "1":
                print("\nStarting full log monitor...")
                print("Press Ctrl+C to stop monitoring.")
                input("Press Enter to continue or Ctrl+C to cancel...")
                monitor = OSLogMonitor()
                monitor.start()
                break
                
            elif choice == "2":
                print("\nStarting 30-second test...")
                input("Press Enter to continue or Ctrl+C to cancel...")
                os.system("python test_monitor.py")
                
            elif choice == "3":
                print("\nRunning demonstration...")
                input("Press Enter to continue...")
                os.system("python demo_monitor.py")
                
            elif choice == "4":
                print("\nSystem Information:")
                monitor = OSLogMonitor()
                monitor.display_os_info()
                input("\nPress Enter to continue...")
                
            elif choice == "5":
                print("Goodbye!")
                break
                
            else:
                print("Invalid choice. Please enter 1-5.")
                input("Press Enter to continue...")
                
    except KeyboardInterrupt:
        print("\n\nLauncher interrupted by user. Goodbye!")
    except Exception as e:
        print(f"\nError: {e}")
        input("Press Enter to exit...")


if __name__ == "__main__":
    main()