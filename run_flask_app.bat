@echo off
REM Flask Application Launcher - Windows Batch File
REM ===============================================
REM
REM This batch file launches the OS Log Analyzer Flask application
REM with appropriate settings for Windows environments.

echo.
echo ========================================
echo   OS Log Analyzer - Flask Edition
echo ========================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Python is not installed or not in PATH
    echo Please install Python 3.7+ and try again
    pause
    exit /b 1
)

REM Check if the main application file exists
if not exist "app\main.py" (
    echo ❌ Flask application not found!
    echo Please make sure you're in the correct directory
    pause
    exit /b 1
)

echo 🔍 Checking dependencies...
python run_flask_app.py --check-deps
if %errorlevel% neq 0 (
    echo.
    echo ❌ Missing dependencies detected!
    echo Install them with: pip install -r requirements.txt
    pause
    exit /b 1
)

echo.
echo 🚀 Starting Flask Application...
echo.
echo Dashboard will be available at: http://localhost:5000
echo Press Ctrl+C to stop the server
echo.

REM Start the Flask application
python run_flask_app.py --debug

pause