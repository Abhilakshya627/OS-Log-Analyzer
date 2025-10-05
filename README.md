# OS Log Analyzer - Complete System Log Monitoring Tool

A comprehensive cross-platform Python application that combines real-time system log monitoring, dataset collection, and analysis capabilities into a single modular tool. Features both interactive and command-line interfaces for system log analysis across Windows, Linux, and macOS platforms.

## Features

- **🔄 Real-time Log Monitoring**: Continuously displays system logs as they're generated
- **📊 Dataset Collection & Analysis**: Collects logs and exports to structured Excel files with comprehensive analysis
- **🖥️ Interactive Launcher**: User-friendly menu-driven interface for all operations
- **⚡ Command-Line Interface**: Direct access to all features via CLI arguments
- **🔍 Cross-platform Support**: Works on Windows, Linux, and macOS with platform-specific optimizations
- **📈 Built-in Analysis**: Statistics, distributions, trend analysis, and visualizations
- **🛡️ Graceful Shutdown**: Clean exit with Ctrl+C and automatic dataset export
- **🧪 Demo & Test Modes**: Safe exploration with demo modes and timed tests

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

### 🚀 Quick Start (Interactive Mode)
```bash
python os_log_analyzer.py
```
Launches an interactive menu with all available options.

### 📊 Dataset Collection
```bash
# 5-minute dataset collection
python os_log_analyzer.py --collect --duration 300

# 1-hour collection  
python os_log_analyzer.py --collect --duration 3600

# Continuous collection (until Ctrl+C)
python os_log_analyzer.py --collect

# Quiet mode (minimal output)
python os_log_analyzer.py --collect --duration 600 --quiet
```

### 🔍 Real-time Monitoring
```bash
# Real-time log monitoring
python os_log_analyzer.py --monitor

# 30-second test
python os_log_analyzer.py --test

# Demo mode (no actual monitoring)
python os_log_analyzer.py --demo
```

### 🧪 Testing & Demo Modes
```bash
# Quick dataset collection demo (2 minutes)
python os_log_analyzer.py --dataset-demo

# Dataset collection test (1 minute)
python os_log_analyzer.py --dataset-test
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

The application is now consolidated into a single modular file (`os_log_analyzer.py`) with the following key components:

### Core Classes
- **`LogEntry`**: Data structure for individual log entries
- **`LogDataset`**: Manages log data collection and analysis
- **`OSLogMonitor`**: Core log monitoring functionality
- **`EnhancedOSLogMonitor`**: Extended version with dataset collection
- **`InteractiveLauncher`**: User-friendly interactive interface

### Key Methods
- `detect_os()`: Identifies the current operating system
- `monitor_*_logs()`: Platform-specific log monitoring methods
- `export_to_excel()`: Creates comprehensive Excel reports
- `signal_handler()`: Handles graceful shutdown on interruption

### Command Line Interface
Full argument parsing with help system:
```bash
python os_log_analyzer.py --help
```

## Interactive Menu Options

When run without arguments, the tool presents an interactive menu:

1. **Real-time log monitoring** - Display-only monitoring
2. **Quick 30-second test** - Short monitoring test
3. **Show demo** - Safe demonstration mode
4. **5-minute dataset collection** - Quick dataset creation
5. **15-minute dataset collection** - Standard dataset
6. **1-hour dataset collection** - Comprehensive dataset
7. **Custom duration collection** - User-specified duration
8. **Continuous collection** - Until manual stop
9. **System information** - OS and system details
10. **Dataset collection guide** - Help and documentation
11. **Exit** - Quit the application

## Benefits of the Combined Approach

- **Simplified Deployment**: Single file with all functionality
- **Consistent Interface**: Unified command structure across all features
- **Reduced Complexity**: No need to remember multiple script names
- **Better Maintenance**: Single codebase to update and maintain
- **Enhanced Modularity**: Clear separation of concerns within one file

## License

This project is open source. Feel free to modify and distribute as needed.