# OS Log Analyzer - Clean Project Structure

## 📁 Project Files Overview

After cleanup, the project now contains only essential files:

### Core Application Files
- `os_log_analyzer.py` - Main log analyzer with monitoring capabilities
- `rules.py` - Threat detection engine with security rules
- `model.py` - Machine learning analysis for anomaly detection
- `integrated_analysis.py` - Combined analysis tool

### Flask Web Application (Backend)
- `app/main.py` - Flask REST API backend server
- `run_flask_app.py` - Flask backend launcher script
- `run_flask_app.bat` - Windows batch launcher for Flask

### React Web Application (Frontend)
- `frontend/src/App.jsx` - Main React application component
- `frontend/src/components/` - React components (Header, LogStream, etc.)
- `frontend/src/services/api.js` - API service layer for Flask communication
- `frontend/package.json` - Node.js dependencies and scripts
- `run_fullstack.py` - Full stack launcher script
- `run_fullstack.bat` - Windows batch launcher for both servers

### Configuration & Documentation
- `requirements.txt` - Python dependencies
- `README.md` - Project documentation
- `prompt.txt` - Project specification
- `.gitignore` - Git ignore rules

## 🚀 How to Use

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Install Frontend Dependencies
```bash
cd frontend
npm install
```

### 3. Run the Full Stack Application
```bash
python run_fullstack.py
```
Or double-click `run_fullstack.bat` on Windows

This starts both:
- Flask backend on `http://localhost:5000`
- React frontend on `http://localhost:3000`

### 4. Access Dashboard
- **React Frontend**: `http://localhost:3000` (main dashboard)
- **Flask Backend API**: `http://localhost:5000/api/` (REST endpoints only)

### 4. Use Command Line Tools
```bash
# Run main analyzer
python os_log_analyzer.py

# Run threat analysis
python rules.py

# Run ML analysis
python model.py

# Run comprehensive analysis
python integrated_analysis.py
```

## 🧹 Cleaned Up Files

The following files were removed to keep the project clean:
- Old demo and test files
- Generated analysis reports (*.json)
- Generated plots (*.png)
- Old dataset files
- FastAPI structure (api/, core/, schemas/, services/)
- Python cache files (__pycache__)
- Duplicate files

## 📊 Current Project Structure
```
OS-Log-Analyzer/
├── .git/
├── .gitignore
├── app/
│   └── main.py                 # Flask backend API
├── frontend/                   # React frontend application
│   ├── src/
│   │   ├── components/         # React components
│   │   ├── services/           # API service layer
│   │   ├── App.jsx            # Main React app
│   │   ├── main.jsx           # React entry point
│   │   └── index.css          # Styles
│   ├── public/
│   ├── package.json           # Node.js dependencies
│   ├── vite.config.js         # Vite configuration
│   └── README.md              # Frontend documentation
├── integrated_analysis.py      # Combined analysis tool
├── model.py                    # ML analysis engine
├── os_log_analyzer.py          # Main log analyzer
├── prompt.txt                  # Project specification
├── README.md                   # Documentation
├── requirements.txt            # Python dependencies
├── rules.py                    # Threat detection rules
├── run_flask_app.bat          # Flask backend launcher (Windows)
├── run_flask_app.py           # Flask backend launcher
├── run_fullstack.bat          # Full stack launcher (Windows)
└── run_fullstack.py           # Full stack launcher
```

The project is now clean, organized, and ready for development or deployment!