@echo off
REM OS Log Monitor Launcher for Windows
REM This batch file runs the Python log monitor

echo Starting OS Log Monitor...
echo.

REM Check if Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Python is not installed or not in PATH
    echo Please install Python 3.6 or higher
    pause
    exit /b 1
)

REM Run the log monitor
python os_log_monitor.py

pause