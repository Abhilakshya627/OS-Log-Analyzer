#!/usr/bin/env python3
"""
Simplified Flask Web Application for OS Log Analyzer
===================================================

A streamlined Flask application that provides a web interface for the
unified OS Log Analyzer, with simplified monitoring, threat detection,
and machine learning analysis capabilities.

Features:
- Real-time log monitoring with unified backend
- Simplified threat detection and analysis
- Machine learning anomaly detection
- REST API endpoints with proper error handling
- Export functionality with multiple formats
- Clear user feedback for all operations

Author: OS Log Analyzer - Simplified Flask Edition
Date: October 8, 2025
"""

import sys
import os
import json
import csv
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any

# Add parent directory to path to import our modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import pandas as pd

# Import our unified analysis module  
try:
    from unified_analyzer import UnifiedLogAnalyzer, quick_analysis, analyze_log_file
    UNIFIED_ANALYZER_AVAILABLE = True
except ImportError as e:
    print(f"⚠️ Import warning: {e}")
    UNIFIED_ANALYZER_AVAILABLE = False

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
unified_analyzer = None
monitoring_active = False
monitoring_thread = None
app_start_time = datetime.now()
real_time_data = {
    'logs': [],
    'threats': [],
    'anomalies': []
}

# Initialize services
def initialize_services():
    """Initialize the unified analyzer service."""
    global unified_analyzer
    
    try:
        if UNIFIED_ANALYZER_AVAILABLE:
            unified_analyzer = UnifiedLogAnalyzer()
            print("✅ Unified analyzer initialized successfully")
            return True
        else:
            print("❌ Unified analyzer not available")
            return False
    except Exception as e:
        print(f"❌ Error initializing services: {e}")
        return False

def start_monitoring():
    """Start real-time log monitoring in background thread."""
    global monitoring_active, monitoring_thread
    
    if not monitoring_active and unified_analyzer:
        monitoring_active = True
        monitoring_thread = threading.Thread(target=monitor_logs_background, daemon=True)
        monitoring_thread.start()
        print("🔄 Real-time monitoring started")
        return True
    return False

def stop_monitoring():
    """Stop real-time log monitoring."""
    global monitoring_active
    
    if monitoring_active and unified_analyzer:
        monitoring_active = False
        unified_analyzer.stop()
        print("⏹️ Real-time monitoring stopped")
        return True
    return False

def monitor_logs_background():
    """Background thread for real-time log monitoring using unified analyzer."""
    global real_time_data, unified_analyzer
    
    if not unified_analyzer:
        print("❌ Unified analyzer not initialized")
        return
    
    print("🔄 Starting unified log collection...")
    
    # Set up the analyzer for background collection
    unified_analyzer.display_logs = False  # Don't print to console
    
    while monitoring_active:
        try:
            # Collect logs based on OS
            if unified_analyzer.os_type == 'windows':
                new_logs = unified_analyzer.collect_windows_logs()
            elif unified_analyzer.os_type == 'linux':
                new_logs = unified_analyzer.collect_linux_logs()
            else:
                new_logs = []
            
            # Update real-time data with new logs
            for log in new_logs:
                log_dict = {
                    'id': f"{log.timestamp.isoformat()}-{log.event_id}",
                    'timestamp': log.timestamp.isoformat(),
                    'formatted_timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    'time_ago': calculate_time_ago(log.timestamp),
                    'os_type': log.os_type,
                    'log_type': log.log_type.capitalize(),
                    'source': log.source,
                    'event_id': log.event_id,
                    'level': log.level.upper(),
                    'message': log.message,
                    'raw_data': log.raw_data,
                    'severity_color': get_severity_color(log.level),
                    'type_icon': get_log_type_icon(log.log_type),
                    'is_recent': is_log_recent(log.timestamp)
                }
                
                # Avoid duplicates
                if log_dict not in real_time_data['logs']:
                    real_time_data['logs'].append(log_dict)
            
            # Update threats and anomalies
            real_time_data['threats'] = [
                {
                    'id': f'threat_{i}',
                    'type': threat.threat_type,
                    'severity': threat.severity,
                    'confidence': threat.confidence,
                    'description': threat.description,
                    'timestamp': threat.first_seen.isoformat() if threat.first_seen else datetime.now().isoformat(),
                    'source_ip': threat.source_ip
                }
                for i, threat in enumerate(unified_analyzer.threats)
            ]
            
            real_time_data['anomalies'] = [
                {
                    'timestamp': anomaly.timestamp.isoformat(),
                    'anomaly_score': anomaly.anomaly_score,
                    'description': anomaly.description,
                    'detection_method': anomaly.detection_method,
                    'source': anomaly.log_entry.get('source', 'Unknown')
                }
                for anomaly in unified_analyzer.anomalies
            ]
            
            # Keep only recent logs to prevent memory issues
            if len(real_time_data['logs']) > app.config['MAX_LOGS_DISPLAY']:
                real_time_data['logs'] = real_time_data['logs'][-app.config['MAX_LOGS_DISPLAY']:]
                
            time.sleep(app.config['LOG_UPDATE_INTERVAL'])
            
        except Exception as e:
            print(f"Error in monitoring thread: {e}")
            time.sleep(5)

# Helper functions
def calculate_time_ago(timestamp):
    """Calculate human-readable time difference."""
    try:
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        
        now = datetime.now(timestamp.tzinfo) if timestamp.tzinfo else datetime.now()
        diff = now - timestamp
        
        if diff.total_seconds() < 60:
            return f"{int(diff.total_seconds())}s ago"
        elif diff.total_seconds() < 3600:
            return f"{int(diff.total_seconds() / 60)}m ago"
        elif diff.total_seconds() < 86400:
            return f"{int(diff.total_seconds() / 3600)}h ago"
        else:
            return f"{int(diff.total_seconds() / 86400)}d ago"
    except:
        return "Unknown"

def get_severity_color(level):
    """Get color code for log level severity."""
    level_colors = {
        'CRITICAL': '#dc3545',  # Red
        'ERROR': '#fd7e14',     # Orange
        'WARNING': '#ffc107',   # Yellow
        'INFO': '#17a2b8',      # Cyan
        'DEBUG': '#6c757d',     # Gray
        'VERBOSE': '#6f42c1'    # Purple
    }
    return level_colors.get(level.upper(), '#17a2b8')

def get_log_type_icon(log_type):
    """Get icon for log type."""
    type_icons = {
        'system': '⚙️',
        'application': '📱',
        'security': '🔒',
        'setup': '⚡',
        'network': '🌐',
        'service': '🔧',
        'unknown': '📄'
    }
    return type_icons.get(log_type.lower(), '📄')

def is_log_recent(timestamp):
    """Check if log is from the last 30 seconds."""
    try:
        if isinstance(timestamp, str):
            log_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        else:
            log_time = timestamp
        
        now = datetime.now(log_time.tzinfo) if log_time.tzinfo else datetime.now()
        return (now - log_time).total_seconds() <= 30
    except:
        return False

# API Routes
@app.route('/')
def index():
    """API root endpoint."""
    return jsonify({
        'message': 'OS Log Analyzer API - Simplified Edition',
        'frontend_url': 'http://localhost:3000',
        'api_docs': '/api/',
        'health': '/api/health',
        'unified_analyzer': UNIFIED_ANALYZER_AVAILABLE
    })

@app.route('/api/system/status')
def system_status():
    """Get current system and monitoring status."""
    uptime = (datetime.now() - app_start_time).total_seconds()
    
    logs_count = len(real_time_data['logs']) if real_time_data['logs'] else 0
    real_logs_collected = len(unified_analyzer.logs) if unified_analyzer else 0
    
    status = {
        'timestamp': datetime.now().isoformat(),
        'monitoring_active': monitoring_active,
        'os_type': unified_analyzer.os_type if unified_analyzer else ('windows' if os.name == 'nt' else 'linux'),
        'system_info': {
            'platform': os.name,
            'python_version': sys.version
        },
        'total_logs': logs_count,
        'real_logs_collected': real_logs_collected,
        'using_unified_analyzer': unified_analyzer is not None,
        'uptime_seconds': uptime,
        'services': {
            'unified_analyzer': unified_analyzer is not None,
            'monitoring_thread': monitoring_thread is not None and monitoring_thread.is_alive() if monitoring_thread else False
        }
    }
    return jsonify(status)

@app.route('/api/logs/live')
def logs_live():
    """Get recent real logs for real-time display."""
    try:
        limit = request.args.get('limit', 100, type=int)
        
        # Get logs in chronological order (most recent last)
        logs = real_time_data['logs'][-limit:] if real_time_data['logs'] else []
        
        return jsonify({
            'timestamp': datetime.now().isoformat(),
            'total': len(real_time_data['logs']),
            'returned': len(logs),
            'logs': logs,
            'monitoring_active': monitoring_active,
            'using_unified_analyzer': unified_analyzer is not None,
            'last_update': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': f'Failed to get live logs: {str(e)}'}), 500

@app.route('/api/threats/active')
def threats_active():
    """Get currently active threats."""
    try:
        threats = real_time_data.get('threats', [])
        
        return jsonify({
            'timestamp': datetime.now().isoformat(),
            'active_threats': len(threats),
            'threats': threats
        })
    except Exception as e:
        return jsonify({'error': f'Failed to get threats: {str(e)}'}), 500

@app.route('/api/threats/analyze', methods=['POST'])
def threats_analyze():
    """Analyze specific log entries for threats."""
    try:
        data = request.get_json()
        
        if not data or 'logs' not in data:
            return jsonify({'error': 'No log data provided'}), 400
        
        if not unified_analyzer:
            return jsonify({'error': 'Unified analyzer not initialized'}), 500
        
        results = []
        for log_data in data['logs']:
            # Convert dict back to LogEntry for analysis
            from unified_analyzer import LogEntry
            log_entry = LogEntry(
                timestamp=datetime.fromisoformat(log_data['timestamp'].replace('Z', '+00:00')),
                os_type=log_data.get('os_type', 'unknown'),
                log_type=log_data.get('log_type', 'unknown'),
                source=log_data.get('source', 'unknown'),
                event_id=log_data.get('event_id', ''),
                level=log_data.get('level', 'INFO'),
                message=log_data.get('message', ''),
                raw_data=log_data.get('raw_data', '')
            )
            
            threats = unified_analyzer.detect_threats(log_entry)
            for threat in threats:
                results.append({
                    'log_entry': log_data,
                    'threat_type': threat.threat_type,
                    'severity': threat.severity,
                    'confidence': threat.confidence,
                    'description': threat.description
                })
        
        return jsonify({
            'timestamp': datetime.now().isoformat(),
            'analyzed_logs': len(data['logs']),
            'threats_found': len(results),
            'results': results
        })
    except Exception as e:
        return jsonify({'error': f'Threat analysis failed: {str(e)}'}), 500

@app.route('/api/ml/anomalies')
def ml_anomalies():
    """Get detected anomalies from ML analysis."""
    try:
        anomalies = real_time_data.get('anomalies', [])
        
        # If we have recent logs but no anomalies, try to run ML analysis
        if not anomalies and unified_analyzer and len(unified_analyzer.logs) > 10:
            recent_logs = unified_analyzer.logs[-20:]
            unified_analyzer.detect_ml_anomalies(recent_logs)
            
            # Update real-time data
            anomalies = [
                {
                    'timestamp': anomaly.timestamp.isoformat(),
                    'anomaly_score': anomaly.anomaly_score,
                    'description': anomaly.description,
                    'detection_method': anomaly.detection_method,
                    'source': anomaly.log_entry.get('source', 'Unknown')
                }
                for anomaly in unified_analyzer.anomalies
            ]
            real_time_data['anomalies'] = anomalies
        
        return jsonify({
            'timestamp': datetime.now().isoformat(),
            'total_logs_analyzed': len(unified_analyzer.logs) if unified_analyzer else 0,
            'anomalies_detected': len(anomalies),
            'anomaly_rate': len(anomalies) / len(unified_analyzer.logs) * 100 if unified_analyzer and unified_analyzer.logs else 0,
            'anomalies': anomalies,
            'ml_available': unified_analyzer is not None and hasattr(unified_analyzer, 'ml_model') and unified_analyzer.ml_model is not None
        })
    except Exception as e:
        return jsonify({'error': f'ML analysis failed: {str(e)}'}), 500

@app.route('/api/export/logs/<format>')
def export_logs(format):
    """Export logs in specified format."""
    try:
        if format not in ['json', 'csv', 'xlsx']:
            return jsonify({'error': 'Unsupported format. Use json, csv, or xlsx'}), 400
        
        if not unified_analyzer or not unified_analyzer.logs:
            return jsonify({'error': 'No logs available for export'}), 400
        
        # Create exports directory
        os.makedirs('exports', exist_ok=True)
        
        if format == 'xlsx':
            filename = unified_analyzer.export_to_excel()
            return send_from_directory('exports' if os.path.exists(os.path.join('exports', filename)) else '.', filename, as_attachment=True)
        
        elif format == 'json':
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f'unified_logs_export_{timestamp}.json'
            filepath = os.path.join('exports', filename)
            
            # Convert logs to JSON-serializable format
            logs_data = []
            for log in unified_analyzer.logs:
                logs_data.append({
                    'timestamp': log.timestamp.isoformat(),
                    'os_type': log.os_type,
                    'log_type': log.log_type,
                    'source': log.source,
                    'event_id': log.event_id,
                    'level': log.level,
                    'message': log.message,
                    'raw_data': log.raw_data
                })
            
            with open(filepath, 'w') as f:
                json.dump({
                    'export_timestamp': datetime.now().isoformat(),
                    'total_logs': len(logs_data),
                    'logs': logs_data
                }, f, indent=2)
            
            return send_from_directory('exports', filename, as_attachment=True)
        
        elif format == 'csv':
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f'unified_logs_export_{timestamp}.csv'
            filepath = os.path.join('exports', filename)
            
            # Create CSV
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Timestamp', 'OS_Type', 'Log_Type', 'Source', 'Event_ID', 'Level', 'Message'])
                
                for log in unified_analyzer.logs:
                    writer.writerow([
                        log.timestamp.isoformat(),
                        log.os_type,
                        log.log_type,
                        log.source,
                        log.event_id,
                        log.level,
                        log.message[:500]  # Truncate long messages
                    ])
            
            return send_from_directory('exports', filename, as_attachment=True)
    
    except Exception as e:
        return jsonify({'error': f'Export failed: {str(e)}'}), 500

@app.route('/api/monitoring/start', methods=['POST'])
def start_monitoring_endpoint():
    """Start real-time monitoring."""
    try:
        success = start_monitoring()
        if success:
            return jsonify({
                'message': 'Monitoring started successfully',
                'timestamp': datetime.now().isoformat(),
                'status': 'active'
            })
        else:
            return jsonify({
                'error': 'Failed to start monitoring - analyzer not available',
                'timestamp': datetime.now().isoformat(),
                'status': 'failed'
            }), 500
    except Exception as e:
        return jsonify({
            'error': f'Failed to start monitoring: {str(e)}',
            'timestamp': datetime.now().isoformat(),
            'status': 'error'
        }), 500

@app.route('/api/monitoring/stop', methods=['POST'])
def stop_monitoring_endpoint():
    """Stop real-time monitoring."""
    try:
        success = stop_monitoring()
        return jsonify({
            'message': 'Monitoring stopped' if success else 'Monitoring was not active',
            'timestamp': datetime.now().isoformat(),
            'status': 'inactive'
        })
    except Exception as e:
        return jsonify({
            'error': f'Failed to stop monitoring: {str(e)}',
            'timestamp': datetime.now().isoformat(),
            'status': 'error'
        }), 500

@app.route('/api/analysis/comprehensive', methods=['POST'])
def comprehensive_analysis_endpoint():
    """Run comprehensive analysis on current log data."""
    try:
        if not unified_analyzer:
            return jsonify({'error': 'Unified analyzer not initialized'}), 500
        
        # Get comprehensive summary
        summary = unified_analyzer.get_summary()
        
        return jsonify({
            'timestamp': datetime.now().isoformat(),
            'analysis_results': summary,
            'logs_analyzed': len(unified_analyzer.logs)
        })
    except Exception as e:
        return jsonify({'error': f'Comprehensive analysis failed: {str(e)}'}), 500

@app.route('/api/analysis/quick', methods=['POST'])
def quick_analysis_endpoint():
    """Run a quick analysis for a specified duration."""
    try:
        data = request.get_json() or {}
        duration = data.get('duration', 30)  # Default 30 seconds
        
        if not UNIFIED_ANALYZER_AVAILABLE:
            return jsonify({'error': 'Unified analyzer not available'}), 500
        
        # Run quick analysis in background thread to avoid blocking
        def run_analysis():
            return quick_analysis(duration)
        
        # For now, run synchronously (in production, consider async handling)
        results = run_analysis()
        
        return jsonify({
            'timestamp': datetime.now().isoformat(),
            'duration': duration,
            'results': results
        })
    except Exception as e:
        return jsonify({'error': f'Quick analysis failed: {str(e)}'}), 500

# Health check endpoint
@app.route('/api/health')
def health_check():
    """Health check endpoint with detailed status."""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'uptime': (datetime.now() - app_start_time).total_seconds(),
        'version': '2.0.0-simplified',
        'services': {
            'unified_analyzer': unified_analyzer is not None,
            'monitoring': monitoring_active,
            'logs_collected': len(unified_analyzer.logs) if unified_analyzer else 0,
            'threats_detected': len(unified_analyzer.threats) if unified_analyzer else 0,
            'anomalies_found': len(unified_analyzer.anomalies) if unified_analyzer else 0
        }
    })

# Error Handlers with detailed feedback
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'error': 'Endpoint not found',
        'message': 'The requested API endpoint does not exist',
        'available_endpoints': [
            '/api/health',
            '/api/system/status',
            '/api/logs/live',
            '/api/threats/active',
            '/api/ml/anomalies',
            '/api/monitoring/start',
            '/api/monitoring/stop',
            '/api/export/logs/<format>'
        ]
    }), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        'error': 'Internal server error',
        'message': 'An unexpected error occurred. Please check the server logs for details.',
        'timestamp': datetime.now().isoformat()
    }), 500

# Application startup
if __name__ == '__main__':
    print("🚀 Starting OS Log Analyzer - Simplified Flask API")
    print("=" * 60)
    
    # Initialize services
    if initialize_services():
        print("✅ All services initialized successfully")
    else:
        print("⚠️ Some services failed to initialize, continuing with limited functionality")
    
    # Create necessary directories
    os.makedirs('exports', exist_ok=True)
    
    print(f"🔗 API endpoints available at: http://localhost:5000/api/")
    print(f"🌐 React frontend should be running at: http://localhost:3000")
    print(f"🔧 Health check: http://localhost:5000/api/health")
    print("=" * 60)
    
    # Start monitoring automatically if analyzer is available
    if unified_analyzer:
        start_monitoring()
        print("✅ Automatic monitoring started")
    
    # Run the Flask app
    app.run(
        host='0.0.0.0', 
        port=5000, 
        debug=app.config['DEBUG']
    )