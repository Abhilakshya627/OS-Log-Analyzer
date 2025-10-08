#!/usr/bin/env python3
"""
Flask Application Launcher for OS Log Analyzer
==============================================

Simple launcher script to start the Flask web application with proper
configuration and environment setup.

Usage:
    python run_flask_app.py          # Start in production mode
    python run_flask_app.py --debug  # Start in debug mode
    python run_flask_app.py --help   # Show help
"""

import os
import sys
import argparse
from pathlib import Path

# Add the current directory to Python path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

def main():
    parser = argparse.ArgumentParser(
        description="Launch OS Log Analyzer Flask Application",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_flask_app.py                 # Start in production mode
  python run_flask_app.py --debug         # Start with debug enabled
  python run_flask_app.py --port 8080     # Use custom port
  python run_flask_app.py --host 0.0.0.0  # Bind to all interfaces
        """
    )
    
    parser.add_argument(
        '--debug', 
        action='store_true',
        help='Enable debug mode (default: False)'
    )
    
    parser.add_argument(
        '--port', 
        type=int, 
        default=5000,
        help='Port to run the server on (default: 5000)'
    )
    
    parser.add_argument(
        '--host', 
        type=str, 
        default='127.0.0.1',
        help='Host to bind to (default: 127.0.0.1)'
    )
    
    parser.add_argument(
        '--check-deps',
        action='store_true',
        help='Check if all dependencies are installed'
    )
    
    args = parser.parse_args()
    
    if args.check_deps:
        check_dependencies()
        return
    
    # Set environment variables
    os.environ['FLASK_DEBUG'] = 'True' if args.debug else 'False'
    
    print("🚀 Starting OS Log Analyzer Flask Application")
    print(f"📊 Dashboard: http://{args.host}:{args.port}")
    print(f"🔍 Debug Mode: {'Enabled' if args.debug else 'Disabled'}")
    print("=" * 50)
    
    try:
        # Import and run the Flask app
        from app.main import app
        
        app.run(
            host=args.host,
            port=args.port,
            debug=args.debug
        )
        
    except ImportError as e:
        print(f"❌ Import Error: {e}")
        print("Please make sure all dependencies are installed:")
        print("pip install flask flask-cors pandas openpyxl scikit-learn matplotlib")
        sys.exit(1)
        
    except KeyboardInterrupt:
        print("\n🛑 Application stopped by user")
        sys.exit(0)
        
    except Exception as e:
        print(f"❌ Error starting application: {e}")
        sys.exit(1)

def check_dependencies():
    """Check if all required dependencies are installed."""
    required_packages = [
        'flask',
        'flask_cors',
        'pandas',
        'openpyxl',
        'sklearn',
        'matplotlib'
    ]
    
    missing_packages = []
    
    print("🔍 Checking dependencies...")
    
    for package in required_packages:
        try:
            __import__(package)
            print(f"✅ {package}")
        except ImportError:
            print(f"❌ {package}")
            missing_packages.append(package)
    
    if missing_packages:
        print(f"\n❌ Missing packages: {', '.join(missing_packages)}")
        print("Install them with:")
        print("pip install " + " ".join(missing_packages))
        sys.exit(1)
    else:
        print("\n✅ All dependencies are installed!")

if __name__ == '__main__':
    main()