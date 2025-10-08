#!/usr/bin/env python3
"""
Full Stack Application Launcher
===============================

Launches both Flask backend and React frontend for development.
"""

import os
import sys
import subprocess
import threading
import time
import signal
from pathlib import Path

def run_flask_backend():
    """Run Flask backend server."""
    print("🐍 Starting Flask backend...")
    try:
        # Set working directory to project root
        project_root = Path(__file__).parent
        
        # Run Flask app with proper working directory
        result = subprocess.run([
            sys.executable, 'run_flask_app.py', '--debug'
        ], cwd=project_root, capture_output=False)
        
        return result.returncode
    except Exception as e:
        print(f"❌ Error starting Flask backend: {e}")
        return 1

def run_react_frontend():
    """Run React frontend development server."""
    print("⚛️ Starting React frontend...")
    try:
        # Change to frontend directory
        frontend_dir = Path(__file__).parent / 'frontend'
        
        # Determine npm command (Windows needs .cmd extension)
        npm_cmd = 'npm.cmd' if os.name == 'nt' else 'npm'
        
        # Check if node_modules exists
        if not (frontend_dir / 'node_modules').exists():
            print("📦 Installing npm dependencies...")
            subprocess.run([npm_cmd, 'install'], cwd=frontend_dir, check=True, shell=True)
        
        # Run React dev server with proper working directory
        result = subprocess.run([npm_cmd, 'run', 'dev'], cwd=frontend_dir, capture_output=False, shell=True)
        
        return result.returncode
    except Exception as e:
        print(f"❌ Error starting React frontend: {e}")
        return 1

def main():
    print("🚀 Starting OS Log Analyzer Full Stack Application")
    print("=" * 60)
    print("📊 Backend (Flask): http://localhost:5000")
    print("🌐 Frontend (React): http://localhost:3000")
    print("=" * 60)
    print("Press Ctrl+C to stop both servers")
    print()
    
    # Start Flask backend in a separate thread
    flask_thread = threading.Thread(target=run_flask_backend, daemon=True)
    flask_thread.start()
    
    # Wait a moment for Flask to start
    time.sleep(3)
    
    # Start React frontend (this will block)
    try:
        run_react_frontend()
    except KeyboardInterrupt:
        print("\n🛑 Shutting down servers...")
        return 0
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1

if __name__ == '__main__':
    sys.exit(main())