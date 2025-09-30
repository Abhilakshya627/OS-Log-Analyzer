# OS Log Monitor with Excel Dataset Export

A comprehensive cross-platform Python application that detects your operating system, monitors system logs in real-time, and creates structured Excel datasets for log analysis.

## Features

- **Automatic OS Detection**: Identifies Windows, Linux, or macOS
- **Real-time Log Monitoring**: Continuously displays system logs as they're generated
- **Excel Dataset Export**: Collects logs and exports to structured Excel files with analysis
- **Cross-platform Support**: Works on Windows, Linux, and macOS with platform-specific optimizations
- **Multiple Collection Modes**: Quick tests, timed collection, or continuous monitoring
- **Data Analysis**: Built-in statistics, distributions, and trend analysis
- **Graceful Shutdown**: Clean exit with Ctrl+C and automatic dataset export

## Supported Operating Systems

### Windows
- Uses PowerShell to access Windows Event Logs
- Monitors both System and Application event logs
- Falls back to polling method if real-time monitoring fails

### Linux
- Primary: Uses `journalctl -f` for systemd-based systems
- Fallback: Uses `tail -f` on traditional log files (`/var/log/syslog`, `/var/log/messages`, etc.)
- May require elevated privileges for some log files

### macOS
- Uses the built-in `log stream` command
- Monitors system events in real-time
- Filters for log events with info and debug levels

## Requirements

- Python 3.7 or higher (required for dataclasses)
- pandas (for Excel export and data analysis)
- openpyxl (for Excel file creation)
- Administrative/root privileges may be required for accessing some system logs
- Platform-specific tools (all built-in):
  - Windows: PowerShell
  - Linux: `journalctl` or `tail`
  - macOS: `log` command

## Installation

```bash
# Install required packages
pip install pandas openpyxl

# Or install from requirements.txt
pip install -r requirements.txt
```

## Usage

### 🚀 Quick Start (Recommended)
```bash
python enhanced_launcher.py
```
Interactive menu with all options including dataset collection.

### 📊 Dataset Collection Options
```bash
# 1-minute test collection
python test_dataset.py

# 2-minute demo collection  
python demo_dataset.py

# Custom duration collection
python os_log_dataset.py --duration 300  # 5 minutes

# Continuous collection (until Ctrl+C)
python os_log_dataset.py
```

### 🔍 Real-time Monitoring (Display Only)
```bash
# Standard monitoring
python os_log_monitor.py

# Quick 30-second test
python test_monitor.py

# Demo mode (no actual monitoring)
python demo_monitor.py

# Windows batch file
run_monitor.bat
```

## Sample Output

```
============================================================
OS LOG MONITOR - Real-time System Log Viewer
============================================================
Operating System: Windows
Release: 10
Version: 10.0.19044
Machine: AMD64
Node: DESKTOP-ABC123
Detected OS Type: WINDOWS
============================================================
Started at: 2025-09-26 14:30:15
Press Ctrl+C to stop monitoring...
============================================================

Starting Windows Event Log monitoring...
Note: This may take a moment to initialize...

[9/26/2025 2:30:20 PM] [Service Control Manager] [7036] The Windows Update service entered the running state.
---
[9/26/2025 2:30:25 PM] [APP] [Application] [1000] Application started successfully.
---
```

## How It Works

1. **OS Detection**: Uses Python's `platform` module to identify the current operating system
2. **Platform-Specific Monitoring**:
   - **Windows**: Leverages PowerShell's WMI events or Get-EventLog cmdlets
   - **Linux**: Uses `journalctl` for systemd systems or `tail` for traditional log files
   - **macOS**: Uses the `log stream` command with appropriate filters
3. **Real-time Display**: Continuously processes and displays log entries as they occur
4. **Error Handling**: Includes fallback methods and graceful error handling

## Troubleshooting

### Windows
- If you see "Access Denied" errors, try running as Administrator
- If PowerShell is restricted, you may need to adjust execution policy

### Linux
- For journalctl access, you may need to be in the `systemd-journal` group
- For log file access, you may need sudo privileges
- If logs don't appear, check if the system uses systemd or traditional logging

### macOS
- The `log` command requires macOS 10.12 (Sierra) or later
- Some log entries may require elevated privileges to view

## 📊 Excel Dataset Features

### Dataset Structure
The exported Excel files contain multiple worksheets:

- **Raw_Logs**: Complete dataset with all log entries
  - Timestamp, OS_Type, Log_Type, Source, Event_ID
  - Level (Info, Warning, Error, Critical)
  - Message content and raw data
  
- **Summary**: Collection statistics and metadata
  - Collection start/end times and duration
  - Total log count, OS information
  
- **Log_Types**: Distribution analysis by log category
  - System vs Application logs breakdown
  
- **Top_Sources**: Most active log sources
  - Identifies which services/components generate most logs
  
- **Log_Levels**: Distribution by severity level
  - Info, Warning, Error, Critical counts
  
- **Hourly_Distribution**: Time-based analysis
  - Log activity patterns throughout the day

### Sample Analysis Use Cases
- **System Health Monitoring**: Track error rates and sources
- **Performance Analysis**: Identify peak activity periods
- **Troubleshooting**: Correlate events across log types
- **Capacity Planning**: Understand system load patterns
- **Compliance**: Historical log data for audits

### File Naming Convention
```
os_logs_dataset_YYYYMMDD_HHMMSS.xlsx
Example: os_logs_dataset_20250926_210947.xlsx
```

## Stopping the Monitor

Press `Ctrl+C` to gracefully stop the log monitoring. In dataset collection mode, this will automatically export the collected data to Excel before exiting.

## Code Structure

- `OSLogMonitor`: Main class handling OS detection and log monitoring
- `detect_os()`: Identifies the current operating system
- `monitor_*_logs()`: Platform-specific log monitoring methods
- `signal_handler()`: Handles graceful shutdown on interruption

## License

This project is open source. Feel free to modify and distribute as needed.