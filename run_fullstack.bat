@echo off
REM Full Stack Application Launcher - Windows Batch File
REM ====================================================

echo.
echo ========================================
echo   OS Log Analyzer - Full Stack
echo ========================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Python is not installed or not in PATH
    pause
    exit /b 1
)

REM Check if Node.js is available
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Node.js is not installed or not in PATH
    echo Please install Node.js from https://nodejs.org/
    pause
    exit /b 1
)

echo 🚀 Starting Full Stack Application...
echo.
echo Backend (Flask): http://localhost:5000
echo Frontend (React): http://localhost:3000 (or next available port)
echo.
echo Note: If port 3000 is busy, React will use port 3001, 3002, etc.
echo Press Ctrl+C to stop both servers
echo.

REM Run the full stack launcher
python run_fullstack.py

pause