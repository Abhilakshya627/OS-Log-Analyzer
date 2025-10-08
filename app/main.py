#!/usr/bin/env python3
"""
Flask Web Application for OS Log Analyzer - Simplified Version
==============================================================

This Flask application provides a web interface for the
OS Log Analyzer suite, integrating monitoring, threat detection,
and machine learning analysis capabilities.

Features:
- Log analysis and monitoring
- Security threat detection and analysis
- Machine learning anomaly detection
- REST API endpoints
- Export functionality

Author: OS Log Analyzer - Flask Edition
Date: October 8, 2025
"""

import sys
import os
import json
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

# Add parent directory to path to import our modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import pandas as pd

# Import our analysis modules
try:
    from os_log_analyzer import OSLogMonitor, EnhancedOSLogMonitor
    from rules import ThreatDetectionEngine, analyze_log_file
    from model import LogMLAnalyzer, analyze_logs_ml
    from integrated_analysis import comprehensive_analysis
except ImportError as e:
    print(f"⚠️ Import warning: {e}")
    print("Some analysis features may not be available")

# Configuration
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'os-log-analyzer-secret-key'
    DEBUG = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
    CORS_ORIGINS = ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://localhost:5000', 'http://127.0.0.1:5000']
    LOG_UPDATE_INTERVAL = 3  # seconds
    MAX_LOGS_DISPLAY = 1000
    UPLOAD_FOLDER = 'uploads'
    ALLOWED_EXTENSIONS = {'xlsx', 'csv', 'json'}

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
CORS(app, origins=app.config['CORS_ORIGINS'])

# Global services
log_monitor = None
threat_engine = None
ml_analyzer = None
real_time_logs = []
monitoring_active = False
monitoring_thread = None
app_start_time = datetime.now()

# Initialize services
def initialize_services():
    """Initialize all analysis services."""
    global log_monitor, threat_engine, ml_analyzer
    
    try:
        # Try to initialize services if modules are available
        if 'os_log_analyzer' in sys.modules:
            log_monitor = EnhancedOSLogMonitor()
        if 'rules' in sys.modules:
            threat_engine = ThreatDetectionEngine()
        if 'model' in sys.modules:
            ml_analyzer = LogMLAnalyzer()
        
        print("✅ Services initialized successfully")
        return True
    except Exception as e:
        print(f"❌ Error initializing services: {e}")
        return False

def start_monitoring():
    """Start real-time log monitoring in background thread."""
    global monitoring_active, monitoring_thread
    
    if not monitoring_active:
        monitoring_active = True
        monitoring_thread = threading.Thread(target=monitor_logs_background, daemon=True)
        monitoring_thread.start()
        print("🔄 Real-time monitoring started")

def stop_monitoring():
    """Stop real-time log monitoring."""
    global monitoring_active
    monitoring_active = False
    if log_monitor:
        try:
            log_monitor.stop()
        except:
            pass
    print("⏹️ Real-time monitoring stopped")

def monitor_logs_background():
    """Background thread for real-time log monitoring."""
    global real_time_logs
    
    log_counter = 0
    while monitoring_active:
        try:
            # Generate sample log data for demonstration
            current_time = datetime.now()
            log_counter += 1
            
            # Create different types of sample logs
            log_types = ['info', 'warning', 'error', 'debug']
            sources = ['System', 'Authentication', 'Network', 'Application']
            
            sample_log = {
                'timestamp': current_time.isoformat(),
                'os_type': 'windows' if os.name == 'nt' else 'linux',
                'log_type': 'system',
                'source': sources[log_counter % len(sources)],
                'event_id': str(1000 + (log_counter % 100)),
                'level': log_types[log_counter % len(log_types)],
                'message': f'Sample log entry #{log_counter} at {current_time.strftime("%H:%M:%S")}',
                'raw_data': json.dumps({
                    'sample': True, 
                    'timestamp': current_time.isoformat(),
                    'counter': log_counter
                })
            }
            
            # Add to real-time logs
            real_time_logs.append(sample_log)
            
            # Keep only recent logs
            if len(real_time_logs) > app.config['MAX_LOGS_DISPLAY']:
                real_time_logs = real_time_logs[-app.config['MAX_LOGS_DISPLAY']:]
            
            time.sleep(app.config['LOG_UPDATE_INTERVAL'])
            
        except Exception as e:
            print(f"Error in monitoring thread: {e}")
            time.sleep(5)

# API Routes
# ==========

@app.route('/')
def index():
    """API root endpoint - redirects to React frontend."""
    return jsonify({
        'message': 'OS Log Analyzer API',
        'frontend_url': 'http://localhost:3000',
        'api_docs': '/api/',
        'health': '/api/health'
    })

@app.route('/api/system/status')
def system_status():
    """Get current system and monitoring status."""
    uptime = (datetime.now() - app_start_time).total_seconds()
    
    status = {
        'timestamp': datetime.now().isoformat(),
        'monitoring_active': monitoring_active,
        'os_type': 'windows' if os.name == 'nt' else 'linux',
        'system_info': {
            'platform': os.name,
            'python_version': sys.version
        },
        'total_logs': len(real_time_logs),
        'uptime_seconds': uptime,
        'services': {
            'log_monitor': log_monitor is not None,
            'threat_engine': threat_engine is not None,
            'ml_analyzer': ml_analyzer is not None
        }
    }
    return jsonify(status)

@app.route('/api/logs/live')
def logs_live():
    """Get recent logs for real-time display."""
    limit = request.args.get('limit', 100, type=int)
    logs = real_time_logs[-limit:] if real_time_logs else []
    
    return jsonify({
        'timestamp': datetime.now().isoformat(),
        'total': len(real_time_logs),
        'returned': len(logs),
        'logs': logs
    })

@app.route('/api/logs/recent/<int:limit>')
def logs_recent(limit):
    """Get recent logs with specified limit."""
    logs = real_time_logs[-limit:] if real_time_logs else []
    
    return jsonify({
        'timestamp': datetime.now().isoformat(),
        'limit': limit,
        'total': len(real_time_logs),
        'logs': logs
    })

@app.route('/api/threats/active')
def threats_active():
    """Get currently active threats."""
    sample_threats = []
    
    # Analyze recent logs for threats if we have data and threat engine
    if real_time_logs and threat_engine:
        try:
            recent_logs = real_time_logs[-50:]  # Check last 50 logs
            for log_entry in recent_logs:
                threats = threat_engine.analyze_log_entry(log_entry)
                for threat in threats:
                    sample_threats.append({
                        'id': f'threat_{len(sample_threats)}',
                        'type': threat.threat_type,
                        'severity': threat.severity,
                        'confidence': threat.confidence,
                        'description': threat.description,
                        'timestamp': log_entry['timestamp'],
                        'source': log_entry.get('source', 'Unknown')
                    })
        except Exception as e:
            print(f"Error analyzing threats: {e}")
    
    return jsonify({
        'timestamp': datetime.now().isoformat(),
        'active_threats': len(sample_threats),
        'threats': sample_threats
    })

@app.route('/api/threats/analyze', methods=['POST'])
def threats_analyze():
    """Analyze specific log entries for threats."""
    data = request.get_json()
    
    if not data or 'logs' not in data:
        return jsonify({'error': 'No log data provided'}), 400
    
    if not threat_engine:
        return jsonify({'error': 'Threat engine not initialized'}), 500
    
    results = []
    try:
        for log_entry in data['logs']:
            threats = threat_engine.analyze_log_entry(log_entry)
            if threats:
                results.extend([
                    {
                        'log_entry': log_entry,
                        'threat_type': t.threat_type,
                        'severity': t.severity,
                        'confidence': t.confidence,
                        'description': t.description
                    } for t in threats
                ])
    except Exception as e:
        return jsonify({'error': f'Threat analysis failed: {str(e)}'}), 500
    
    return jsonify({
        'timestamp': datetime.now().isoformat(),
        'analyzed_logs': len(data['logs']),
        'threats_found': len(results),
        'results': results
    })

@app.route('/api/ml/anomalies')
def ml_anomalies():
    """Get detected anomalies from ML analysis."""
    if not real_time_logs:
        return jsonify({'anomalies': [], 'message': 'No data available for analysis'})
    
    # Convert logs to DataFrame for ML analysis
    try:
        df = pd.DataFrame(real_time_logs)
        df['Timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Rename columns to match expected format
        column_mapping = {
            'timestamp': 'Timestamp',
            'os_type': 'OS_Type',
            'log_type': 'Log_Type',
            'source': 'Source',
            'event_id': 'Event_ID',
            'level': 'Level',
            'message': 'Message',
            'raw_data': 'Raw_Data'
        }
        df = df.rename(columns=column_mapping)
        
        # Train and detect anomalies if ML analyzer is available
        if ml_analyzer and len(df) > 10:  # Need minimum data for ML
            train_result = ml_analyzer.anomaly_detector.train(df)
            anomalies = ml_analyzer.anomaly_detector.detect_anomalies(df)
            
            anomaly_data = [
                {
                    'timestamp': a.timestamp.isoformat(),
                    'anomaly_score': a.anomaly_score,
                    'description': a.description,
                    'source': a.original_log.get('Source', 'Unknown')
                } for a in anomalies
            ]
            
            return jsonify({
                'timestamp': datetime.now().isoformat(),
                'total_logs_analyzed': len(df),
                'anomalies_detected': len(anomalies),
                'anomaly_rate': len(anomalies) / len(df) * 100,
                'anomalies': anomaly_data
            })
    except Exception as e:
        return jsonify({'error': f'ML analysis failed: {str(e)}'}), 500
    
    return jsonify({'anomalies': [], 'message': 'ML analyzer not available or insufficient data'})

@app.route('/api/export/logs/<format>')
def export_logs(format):
    """Export logs in specified format."""
    if not real_time_logs:
        return jsonify({'error': 'No logs available for export'}), 400
    
    if format not in ['json', 'csv', 'xlsx']:
        return jsonify({'error': 'Unsupported format'}), 400
    
    try:
        df = pd.DataFrame(real_time_logs)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create exports directory
        os.makedirs('exports', exist_ok=True)
        
        if format == 'json':
            filename = f'logs_export_{timestamp}.json'
            filepath = os.path.join('exports', filename)
            
            with open(filepath, 'w') as f:
                json.dump(real_time_logs, f, indent=2, default=str)
            
            return send_from_directory('exports', filename, as_attachment=True)
        
        elif format == 'csv':
            filename = f'logs_export_{timestamp}.csv'
            filepath = os.path.join('exports', filename)
            
            df.to_csv(filepath, index=False)
            return send_from_directory('exports', filename, as_attachment=True)
        
        elif format == 'xlsx':
            filename = f'logs_export_{timestamp}.xlsx'
            filepath = os.path.join('exports', filename)
            
            df.to_excel(filepath, index=False)
            return send_from_directory('exports', filename, as_attachment=True)
    
    except Exception as e:
        return jsonify({'error': f'Export failed: {str(e)}'}), 500

@app.route('/api/monitoring/start', methods=['POST'])
def start_monitoring_endpoint():
    """Start real-time monitoring."""
    start_monitoring()
    return jsonify({
        'message': 'Monitoring started',
        'timestamp': datetime.now().isoformat(),
        'status': 'active'
    })

@app.route('/api/monitoring/stop', methods=['POST'])
def stop_monitoring_endpoint():
    """Stop real-time monitoring."""
    stop_monitoring()
    return jsonify({
        'message': 'Monitoring stopped',
        'timestamp': datetime.now().isoformat(),
        'status': 'inactive'
    })

@app.route('/api/analysis/comprehensive', methods=['POST'])
def comprehensive_analysis_endpoint():
    """Run comprehensive analysis on log data."""
    try:
        data = request.get_json()
        
        if not data or 'logs' not in data:
            # Use real-time logs if no data provided
            if not real_time_logs:
                return jsonify({'error': 'No log data available for analysis'}), 400
            
            # Convert real-time logs to DataFrame
            df = pd.DataFrame(real_time_logs)
            df['Timestamp'] = pd.to_datetime(df['timestamp'])
            
            # Run comprehensive analysis if available
            if 'comprehensive_analysis' in globals():
                results = comprehensive_analysis(df)
                
                return jsonify({
                    'timestamp': datetime.now().isoformat(),
                    'analysis_results': results,
                    'logs_analyzed': len(df)
                })
            else:
                return jsonify({'error': 'Comprehensive analysis not available'}), 501
        
        else:
            # Analyze provided logs
            df = pd.DataFrame(data['logs'])
            
            if 'comprehensive_analysis' in globals():
                results = comprehensive_analysis(df)
                
                return jsonify({
                    'timestamp': datetime.now().isoformat(),
                    'analysis_results': results,
                    'logs_analyzed': len(df)
                })
            else:
                return jsonify({'error': 'Comprehensive analysis not available'}), 501
            
    except Exception as e:
        return jsonify({'error': f'Comprehensive analysis failed: {str(e)}'}), 500

# Health check endpoint
@app.route('/api/health')
def health_check():
    """Health check endpoint."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'uptime': (datetime.now() - app_start_time).total_seconds(),
        'version': '1.0.0'
    })

# Error Handlers
# =============

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

# Application startup
# ==================

if __name__ == '__main__':
    # Initialize services
    if not initialize_services():
        print("⚠️ Some services failed to initialize, continuing with limited functionality")
    
    # Create necessary directories
    os.makedirs('exports', exist_ok=True)
    
    print("🚀 Starting OS Log Analyzer Flask API Backend")
    print(f"� API endpoints available at: http://localhost:5000/api/")
    print(f"🌐 React frontend should be running at: http://localhost:3000")
    print(f"💡 Use 'python run_fullstack.py' to start both servers")
    
    # Start monitoring automatically
    start_monitoring()
    
    # Run the Flask app
    app.run(
        host='0.0.0.0', 
        port=5000, 
        debug=app.config['DEBUG']
    )