#!/usr/bin/env python3
"""
Simplified OS Log Analyzer Startup Script
========================================

This script starts the simplified OS Log Analyzer with the unified backend
and enhanced React frontend.

Usage:
  python run_simplified.py [options]

Options:
  --backend-only    Start only the Flask backend
  --frontend-only   Start only the React frontend  
  --port PORT       Set Flask backend port (default: 5000)
  --quick-test      Run a quick 30-second analysis test
  --help            Show this help message

Author: OS Log Analyzer - Simplified Edition
Date: October 8, 2025
"""

import sys
import os
import subprocess
import threading
import time
import signal
from pathlib import Path

# Configuration
BACKEND_PORT = 5000
FRONTEND_PORT = 3000
BACKEND_FILE = "app/main.py"
FRONTEND_DIR = "frontend"

def print_banner():
    """Print startup banner."""
    print("=" * 60)
    print("🚀 OS Log Analyzer - Simplified Edition")
    print("=" * 60)
    print("📊 Unified backend with real-time monitoring")
    print("🔍 Enhanced threat detection and ML analysis")
    print("⚡ Improved React frontend with user feedback")
    print("📱 Responsive design with notifications")
    print("=" * 60)

def check_requirements(backend_only=False, frontend_only=False):
    """Check if required files and dependencies exist."""
    issues = []
    
    # Check backend file (unless frontend-only)
    if not frontend_only and not os.path.exists(BACKEND_FILE):
        issues.append(f"❌ Backend file not found: {BACKEND_FILE}")
    
    # Check frontend directory (unless backend-only)
    if not backend_only and not os.path.exists(FRONTEND_DIR):
        issues.append(f"❌ Frontend directory not found: {FRONTEND_DIR}")
    
    # Check if unified_analyzer.py exists (unless frontend-only)
    if not frontend_only and not os.path.exists("unified_analyzer.py"):
        issues.append("❌ unified_analyzer.py not found (required for backend)")
    
    # Check Python dependencies (unless frontend-only)
    if not frontend_only:
        try:
            import flask
            import flask_cors
            import pandas
            print("✅ Python dependencies available")
        except ImportError as e:
            issues.append(f"❌ Missing Python dependency: {e}")
    
    # Check Node.js and npm (for frontend, unless backend-only)
    if not backend_only:
        try:
            # Try multiple ways to find npm
            npm_commands = ["npm", "npm.cmd", "npm.exe"]
            npm_found = False
            
            for npm_cmd in npm_commands:
                try:
                    result = subprocess.run([npm_cmd, "--version"], capture_output=True, text=True, shell=True)
                    if result.returncode == 0:
                        print("✅ Node.js/npm available")
                        npm_found = True
                        break
                except:
                    continue
            
            if not npm_found:
                issues.append("❌ Node.js/npm not available (required for frontend)")
        except Exception as e:
            issues.append(f"❌ Node.js/npm check failed: {e}")
    
    return issues

def start_backend(port=BACKEND_PORT):
    """Start the Flask backend server."""
    print(f"🔧 Starting Flask backend on port {port}...")
    
    try:
        # Use python -u for unbuffered output
        process = subprocess.Popen([
            sys.executable, "-u", BACKEND_FILE
        ], env={
            **os.environ,
            "FLASK_PORT": str(port),
            "PYTHONUNBUFFERED": "1"
        })
        
        print(f"✅ Backend started (PID: {process.pid})")
        print(f"🔗 Backend API: http://localhost:{port}/api/")
        return process
    
    except Exception as e:
        print(f"❌ Failed to start backend: {e}")
        return None

def start_frontend():
    """Start the React frontend development server."""
    print(f"🎨 Starting React frontend on port {FRONTEND_PORT}...")
    
    try:
        # Change to frontend directory
        frontend_path = Path(FRONTEND_DIR).resolve()
        
        # Check if node_modules exists, if not run npm install
        if not (frontend_path / "node_modules").exists():
            print("📦 Installing frontend dependencies...")
            install_process = subprocess.run([
                "npm", "install"
            ], cwd=frontend_path, capture_output=True, text=True, shell=True)
            
            if install_process.returncode != 0:
                print(f"❌ npm install failed: {install_process.stderr}")
                return None
            print("✅ Frontend dependencies installed")
        
        # Start React development server (using Vite)
        process = subprocess.Popen([
            "npm", "run", "dev"
        ], cwd=frontend_path, env={
            **os.environ,
            "BROWSER": "none",  # Don't auto-open browser
            "PORT": str(FRONTEND_PORT)
        }, shell=True)
        
        print(f"✅ Frontend started (PID: {process.pid})")
        print(f"🌐 Frontend URL: http://localhost:{FRONTEND_PORT}")
        return process
    
    except Exception as e:
        print(f"❌ Failed to start frontend: {e}")
        return None

def run_quick_test():
    """Run a quick analysis test."""
    print("🧪 Running quick analysis test...")
    
    try:
        from unified_analyzer import quick_analysis
        
        print("⏱️  Running 30-second log collection and analysis...")
        results = quick_analysis(30)
        
        print("\n📊 QUICK TEST RESULTS:")
        print("-" * 40)
        info = results.get('collection_info', {})
        print(f"📁 Total logs collected: {info.get('total_logs', 0)}")
        print(f"🚨 Threats detected: {info.get('total_threats', 0)}")
        print(f"🔍 Anomalies found: {info.get('total_anomalies', 0)}")
        print(f"⏰ Collection time: {info.get('duration_seconds', 0):.1f} seconds")
        print(f"💻 Operating system: {info.get('os_type', 'unknown')}")
        
        threat_analysis = results.get('threat_analysis', {})
        if threat_analysis.get('types'):
            print(f"\n🛡️  Threat types found: {list(threat_analysis['types'].keys())}")
        
        ml_analysis = results.get('ml_analysis', {})
        if ml_analysis.get('ml_available'):
            print(f"🤖 ML anomaly rate: {ml_analysis.get('anomaly_rate', 0):.1f}%")
        
        print("\n✅ Quick test completed successfully!")
        return True
    
    except Exception as e:
        print(f"❌ Quick test failed: {e}")
        return False

def main():
    """Main startup function."""
    # Parse command line arguments
    args = sys.argv[1:]
    
    if "--help" in args:
        print(__doc__)
        return
    
    backend_only = "--backend-only" in args
    frontend_only = "--frontend-only" in args
    quick_test = "--quick-test" in args
    
    # Get port from arguments
    port = BACKEND_PORT
    if "--port" in args:
        try:
            port_index = args.index("--port")
            if port_index + 1 < len(args):
                port = int(args[port_index + 1])
        except (ValueError, IndexError):
            print("❌ Invalid port number")
            return
    
    print_banner()
    
    # Run quick test if requested
    if quick_test:
        success = run_quick_test()
        sys.exit(0 if success else 1)
    
    # Check requirements
    print("🔍 Checking requirements...")
    issues = check_requirements(backend_only=backend_only, frontend_only=frontend_only)
    
    if issues:
        print("\n⚠️  Issues found:")
        for issue in issues:
            print(f"  {issue}")
        print("\nPlease resolve these issues before starting.")
        sys.exit(1)
    
    print("✅ All requirements satisfied")
    print()
    
    # Start services
    processes = []
    
    try:
        if not frontend_only:
            backend_process = start_backend(port)
            if backend_process:
                processes.append(("Backend", backend_process))
                time.sleep(2)  # Give backend time to start
        
        if not backend_only:
            frontend_process = start_frontend()
            if frontend_process:
                processes.append(("Frontend", frontend_process))
                time.sleep(3)  # Give frontend time to start
        
        if not processes:
            print("❌ No services started")
            return
        
        print("\n🎉 All services started successfully!")
        print("\n📋 Service Status:")
        for name, process in processes:
            status = "🟢 Running" if process.poll() is None else "🔴 Stopped"
            print(f"  {name}: {status} (PID: {process.pid})")
        
        print(f"\n🔗 Access the application:")
        if not frontend_only:
            print(f"  • Backend API: http://localhost:{port}/api/")
            print(f"  • Health Check: http://localhost:{port}/api/health")
        if not backend_only:
            print(f"  • Frontend App: http://localhost:{FRONTEND_PORT}")
        
        print(f"\n💡 Tips:")
        print(f"  • Monitor backend logs in this terminal")
        print(f"  • Frontend will auto-reload on file changes")
        print(f"  • Press Ctrl+C to stop all services")
        print(f"  • Use --help for more options")
        
        # Wait for interrupt
        def signal_handler(signum, frame):
            print("\n\n🛑 Stopping services...")
            for name, process in processes:
                if process.poll() is None:
                    print(f"  Stopping {name}...")
                    process.terminate()
            
            # Wait a bit for graceful shutdown
            time.sleep(2)
            
            # Force kill if still running
            for name, process in processes:
                if process.poll() is None:
                    print(f"  Force stopping {name}...")
                    process.kill()
            
            print("✅ All services stopped")
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Keep main thread alive
        while True:
            time.sleep(1)
            # Check if any process died
            for name, process in processes:
                if process.poll() is not None:
                    print(f"⚠️  {name} process stopped unexpectedly")
                    break
    
    except KeyboardInterrupt:
        print("\n\n🛑 Interrupted by user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
    finally:
        # Cleanup
        for name, process in processes:
            if process.poll() is None:
                process.terminate()

if __name__ == "__main__":
    main()