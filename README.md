# 🚀 OS Log Analyzer - Advanced Security Monitoring & Threat Detection

A next-generation cross-platform system log monitoring and security analysis tool that combines **real-time threat detection**, **machine learning anomaly analysis**, and **professional web interface** into a unified security platform. Built for cybersecurity professionals, system administrators, and security researchers.

## ✨ Key Features

### 🛡️ **Advanced Threat Detection**
- **8 Comprehensive Threat Categories**: Authentication failures, malware detection, network attacks, privilege escalation, suspicious processes, data exfiltration, persistence mechanisms, and Windows security events
- **16+ Windows Security Event Types**: Failed logons, Kerberos failures, audit log clearing, service installations, and more
- **Real-time Pattern Recognition**: Identifies attack patterns as they occur
- **Severity-based Classification**: Critical, High, Medium, Low threat levels with confidence scoring

### 🤖 **Multi-layered ML Anomaly Detection**
- **Statistical Analysis**: Message length anomalies, error rate spikes, source activity patterns
- **Pattern Recognition**: Repeated error sequences, unusual activity bursts, behavioral analysis
- **Temporal Analysis**: Off-hours activity detection, timing pattern recognition
- **Advanced ML Models**: Isolation Forest with 10+ feature dimensions for sophisticated anomaly detection
- **Adaptive Analysis**: Works with minimal data using rule-based fallbacks

### 🌐 **Professional Web Interface**
- **React Frontend**: Modern, responsive UI with real-time updates
- **Interactive Dashboards**: Expandable threat alerts, ML anomaly visualizations, system statistics
- **Color-coded Severity**: Visual threat prioritization with severity-based styling
- **Real-time Monitoring**: Auto-refreshing data with WebSocket-like updates
- **Professional Visualization**: Charts, graphs, and interactive components

### 🏗️ **Unified Architecture**
- **Flask REST API**: Comprehensive endpoints for all monitoring and analysis functions
- **Real-time Processing**: Live log collection with immediate threat analysis
- **Cross-platform Support**: Windows, Linux, and macOS compatibility
- **Scalable Design**: Modular architecture supporting enterprise deployments

## 🚨 **Security Detection Capabilities**

### **Threat Categories Detected**
1. **🔐 Authentication Failures** - Failed logins, credential issues, brute force attempts
2. **🦠 Malware Detection** - Virus, trojan, ransomware, worm, backdoor, rootkit patterns
3. **🌐 Network Attacks** - DDoS, port scans, SQL injection, XSS, CSRF attempts
4. **⬆️ Privilege Escalation** - Unauthorized access attempts, elevation requests
5. **⚙️ Suspicious Processes** - PowerShell, system executables, administrative tools
6. **📤 Data Exfiltration** - Unusual file transfers, exports, backup activities
7. **🔄 Persistence Mechanisms** - Registry modifications, service installations, startup items
8. **🪟 Windows Security Events** - Comprehensive Windows Event Log analysis

### **ML Anomaly Detection Types**
- **📊 Statistical Anomalies**: Message length deviations, error rate spikes
- **🔍 Pattern Recognition**: Repeated error sequences, activity bursts
- **⏰ Temporal Analysis**: Off-hours activity, unusual timing patterns
- **🤖 Advanced ML**: Multi-dimensional feature analysis with Isolation Forest

## 💻 **System Requirements**

### **Backend Requirements**
- **Python 3.8+** (recommended: 3.10+)
- **Required Packages**: Flask, Flask-CORS, pandas, scikit-learn
- **Operating System**: Windows 10+, Linux (Ubuntu 18+), macOS 10.15+
- **Memory**: 2GB RAM minimum, 4GB recommended
- **Storage**: 1GB free space for logs and exports

### **Frontend Requirements**
- **Node.js 16+** and **npm 8+**
- **Modern Web Browser**: Chrome 90+, Firefox 88+, Safari 14+, Edge 90+
- **Network**: Local network access for API communication

### **System Access**
- **Windows**: PowerShell execution privileges
- **Linux**: Access to system logs (`/var/log/`, `journalctl`)
- **macOS**: System log access permissions

## 🚀 **Quick Start**

### **1. Install Dependencies**
```bash
# Install Python backend dependencies
pip install -r requirements.txt

# Install frontend dependencies (requires Node.js)
cd frontend
npm install
cd ..
```

### **2. Launch the Application**
```bash
# Start both frontend and backend
python run_simplified.py

# Or start backend only
python run_simplified.py --backend-only

# Or start frontend only  
python run_simplified.py --frontend-only
```

### **3. Access the Application**
- **Frontend Interface**: `http://localhost:3000` (or `http://localhost:3001` if 3000 is busy)
- **Backend API**: `http://localhost:5000/api/`
- **Health Check**: `http://localhost:5000/api/health`

## 📋 **Usage Examples**

### **Quick Security Analysis**
```bash
# Run 30-second security scan
python run_simplified.py --quick-test

# Backend-only monitoring
python run_simplified.py --backend-only --port 8080

# Custom port configuration
python run_simplified.py --port 5001
```

### **API Endpoints**
```bash
# Get system status
curl http://localhost:5000/api/system/status

# Get active threats
curl http://localhost:5000/api/threats/active

# Get ML anomalies
curl http://localhost:5000/api/ml/anomalies

# Get live logs
curl http://localhost:5000/api/logs/live?limit=50
```

### **Development & Testing**
```bash
# Help and options
python run_simplified.py --help

# Monitor specific duration
python unified_analyzer.py --duration 300

# Export analysis results
python unified_analyzer.py --export --format excel
```

## 📊 **Sample Analysis Results**

### **Threat Detection Output**
```
🚨 THREAT DETECTED: Authentication Failure
├─ Severity: HIGH
├─ Confidence: 85%
├─ Source IP: 192.168.1.100
├─ Description: Multiple failed login attempts detected
└─ Evidence: Event ID 4625 - Failed logon attempt

🚨 THREAT DETECTED: Suspicious Process Activity  
├─ Severity: MEDIUM
├─ Confidence: 65%
├─ Process: powershell.exe
├─ Description: PowerShell execution detected
└─ Evidence: Unusual command line parameters
```

### **ML Anomaly Detection**
```
🤖 ML ANOMALY: Statistical Analysis
├─ Score: 0.847
├─ Method: Statistical Analysis
├─ Description: Message length (340) significantly differs from average (103.2)
└─ Source: Microsoft-Windows-Ntfs

🤖 ML ANOMALY: Temporal Analysis
├─ Score: 0.623  
├─ Method: Temporal Analysis
├─ Description: 100% of activity occurred during off-hours (11PM-6AM)
└─ Pattern: Unusual timing detected
```

### **Real-time Monitoring Stats**
```
📊 SYSTEM STATUS
├─ Total Logs Analyzed: 3,765
├─ Active Threats: 23
├─ ML Anomalies: 8
├─ Monitoring Duration: 17 minutes
├─ Detection Rate: 3.2 threats/minute
└─ System Health: MONITORING
```

## 🏗️ **Architecture Overview**

### **Backend Components**
1. **unified_analyzer.py**: Core log analysis and ML processing engine
2. **app/main.py**: Flask REST API server with real-time endpoints
3. **run_simplified.py**: Unified startup script and service manager

### **Frontend Components**
1. **React Application**: Modern web interface with component-based architecture
2. **Real-time Dashboard**: Live threat monitoring and anomaly visualization  
3. **Interactive Components**: Expandable alerts, filtering, and detailed analysis views

### **Data Flow**
```
System Logs → Log Collection → Threat Detection → ML Analysis → API → Frontend → User
              ↓                                    ↓
         Real-time Storage              Anomaly Detection
```

## 🔧 **Configuration & Customization**

### **Threat Detection Tuning**
```python
# Customize threat patterns in unified_analyzer.py
threat_patterns = {
    'malware': ['virus', 'trojan', 'custom_pattern'],
    'network_attack': ['ddos', 'custom_attack'],
    # Add custom patterns
}

# Adjust severity levels
severity_map = {
    4625: 'critical',  # Failed logon -> critical
    # Customize event severity
}
```

### **ML Model Configuration**  
```python
# Adjust ML sensitivity
ml_model = IsolationForest(
    contamination=0.1,  # Expected anomaly rate
    random_state=42,
    n_estimators=100   # Model complexity
)

# Custom feature engineering
def extract_features(log_entry):
    return [
        len(log_entry.message),
        log_entry.timestamp.hour,
        # Add custom features
    ]
```

### **API Customization**
```python
# Custom endpoints in app/main.py
@app.route('/api/custom/analysis')
def custom_analysis():
    # Add custom analysis logic
    return jsonify(results)
```

## 🚨 **Troubleshooting**

### **Common Issues**

**Backend Issues:**
```bash
# Permission errors on Windows
Run as Administrator or adjust PowerShell execution policy

# Python package conflicts  
pip install --upgrade -r requirements.txt

# Port already in use
python run_simplified.py --port 5001
```

**Frontend Issues:**
```bash
# Node.js not found
Install Node.js 16+ from nodejs.org

# npm install fails
rm -rf node_modules package-lock.json
npm install

# Port 3000 busy (automatic fallback to 3001)
Check console output for actual port
```

**Detection Issues:**
```bash
# No threats detected
Increase monitoring duration or check system activity

# Too many false positives
Adjust threat patterns and confidence thresholds in unified_analyzer.py

# ML anomalies not working
Ensure scikit-learn is installed: pip install scikit-learn
```

## � **Performance & Scalability**

### **Performance Metrics**
- **Log Processing**: 1,000+ logs/minute
- **Threat Detection**: Real-time analysis with <100ms latency
- **ML Processing**: Batch analysis every 20 logs for optimal performance
- **Memory Usage**: ~200MB baseline, scales with log volume
- **Storage**: Automatic log rotation and export management

### **Scalability Features**
- **Multi-threaded Processing**: Separate monitoring and analysis threads
- **Configurable Batch Sizes**: Adjust ML processing frequency
- **Export Management**: Automatic data export and cleanup
- **Resource Monitoring**: Built-in system resource tracking

## 📊 **Export & Reporting**

### **Export Formats**
```bash
# Excel export with multiple worksheets
python unified_analyzer.py --export --format excel

# JSON export for programmatic access
python unified_analyzer.py --export --format json

# CSV export for data analysis
python unified_analyzer.py --export --format csv
```

### **Report Structure**
- **📋 Executive Summary**: Threat overview, risk assessment
- **🚨 Threat Analysis**: Detailed threat breakdown by category
- **🤖 ML Insights**: Anomaly patterns and statistical analysis
- **📊 System Health**: Performance metrics and recommendations
- **🔍 Raw Data**: Complete log entries with metadata

## 🎯 **Use Cases**

### **Cybersecurity Operations**
- **🛡️ SOC Monitoring**: Real-time threat detection and alerting
- **🔍 Incident Response**: Historical analysis and forensics
- **📊 Risk Assessment**: Pattern recognition and trend analysis
- **📈 Compliance Reporting**: Automated security documentation

### **System Administration**  
- **⚡ Performance Monitoring**: System health and resource tracking
- **🔧 Troubleshooting**: Error pattern identification
- **📋 Maintenance Planning**: Predictive analysis for system maintenance
- **📊 Capacity Planning**: Resource utilization forecasting

### **Research & Development**
- **🧪 Security Research**: Custom threat pattern development
- **🤖 ML Experimentation**: Anomaly detection algorithm testing
- **📈 Behavioral Analysis**: System and user behavior modeling
- **🔬 Forensic Analysis**: Deep-dive log investigation

## 🌟 **Advanced Features**

### **Custom Threat Rules**
```python
# Create custom threat detection rules
custom_rules = {
    'custom_malware': {
        'patterns': ['custom_signature', 'suspicious_behavior'],
        'severity': 'high',
        'confidence': 0.9
    }
}
```

### **Integration APIs**
```python
# SIEM Integration
POST /api/integrations/siem
{
    "endpoint": "https://siem.company.com/api/alerts",
    "format": "json",
    "authentication": "bearer_token"
}

# Slack Notifications
POST /api/integrations/slack
{
    "webhook_url": "https://hooks.slack.com/...",
    "channel": "#security-alerts",
    "severity_threshold": "medium"
}
```

### **Machine Learning Pipeline**
- **🔄 Continuous Learning**: Model updates with new data
- **📊 Feature Engineering**: Advanced log pattern extraction
- **🎯 Anomaly Scoring**: Multi-model ensemble predictions
- **📈 Trend Analysis**: Historical pattern recognition

## 🤝 **Contributing**

We welcome contributions! Here's how to get started:

### **Development Setup**
```bash
# Clone the repository
git clone https://github.com/Abhilakshya627/OS-Log-Analyzer.git

# Set up development environment
cd OS-Log-Analyzer
pip install -r requirements.txt
cd frontend && npm install

# Run tests
python -m pytest tests/
npm test
```

### **Contribution Areas**
- 🛡️ **New Threat Patterns**: Expand detection capabilities
- 🤖 **ML Algorithms**: Improve anomaly detection accuracy
- 🎨 **UI/UX**: Enhance frontend user experience
- 📊 **Visualizations**: Add new chart types and dashboards
- 🔌 **Integrations**: SIEM, SOAR, and notification platforms

## 📜 **License**

This project is open source and build for the purpose of  learning. Feel free to take this as a base and improve upon it.

## 🙏 **Acknowledgments**

- **Security Community**: For threat intelligence and patterns
- **Open Source Projects**: Flask, React, scikit-learn, and other dependencies  
- **Contributors**: All developers who helped improve this tool

---

**🔒 Built for Security Professionals | 🚀 Enhanced with AI/ML | 💻 Cross-Platform Compatible**
