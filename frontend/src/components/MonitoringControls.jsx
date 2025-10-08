import React from 'react';

const MonitoringControls = ({ 
  onStartMonitoring, 
  onStopMonitoring, 
  onExportLogs, 
  onRunThreatAnalysis, 
  onRunMLAnalysis, 
  onRefreshData,
  onComprehensiveAnalysis,
  buttonStates = {}
}) => {
  
  const getButtonContent = (buttonName, defaultText, loadingText = 'Loading...') => {
    const state = buttonStates[buttonName];
    switch (state) {
      case 'loading':
        return (
          <span>
            <span className="spinner">⏳</span> {loadingText}
          </span>
        );
      case 'success':
        return (
          <span>
            <span className="success-icon">✅</span> {defaultText}
          </span>
        );
      case 'error':
        return (
          <span>
            <span className="error-icon">❌</span> {defaultText}
          </span>
        );
      default:
        return defaultText;
    }
  };

  const getButtonClass = (baseClass, buttonName) => {
    const state = buttonStates[buttonName];
    switch (state) {
      case 'loading':
        return `${baseClass} loading`;
      case 'success':
        return `${baseClass} success`;
      case 'error':
        return `${baseClass} error`;
      default:
        return baseClass;
    }
  };

  const isButtonDisabled = (buttonName) => {
    return buttonStates[buttonName] === 'loading';
  };

  return (
    <div className="card monitoring-controls">
      <h2>⚙️ Monitoring Controls</h2>
      
      {/* Primary monitoring controls */}
      <div className="controls-section">
        <h3>🔄 Real-time Monitoring</h3>
        <div className="controls">
          <button 
            className={getButtonClass("btn btn-primary", "startMonitoring")}
            onClick={onStartMonitoring}
            disabled={isButtonDisabled("startMonitoring")}
            title="Start real-time log monitoring from system events"
          >
            {getButtonContent("startMonitoring", "🚀 Start Monitor", "Starting...")}
          </button>
          
          <button 
            className={getButtonClass("btn btn-danger", "stopMonitoring")}
            onClick={onStopMonitoring}
            disabled={isButtonDisabled("stopMonitoring")}
            title="Stop real-time log monitoring"
          >
            {getButtonContent("stopMonitoring", "⏹️ Stop Monitor", "Stopping...")}
          </button>
          
          <button 
            className={getButtonClass("btn btn-info", "refreshData")}
            onClick={onRefreshData}
            disabled={isButtonDisabled("refreshData")}
            title="Refresh all data from the server"
          >
            {getButtonContent("refreshData", "🔄 Refresh", "Refreshing...")}
          </button>
        </div>
      </div>
      
      {/* Analysis controls */}
      <div className="controls-section">
        <h3>🔍 Analysis & Detection</h3>
        <div className="controls">
          <button 
            className={getButtonClass("btn btn-warning", "threatAnalysis")}
            onClick={onRunThreatAnalysis}
            disabled={isButtonDisabled("threatAnalysis")}
            title="Run security threat analysis on current logs"
          >
            {getButtonContent("threatAnalysis", "🛡️ Analyze Threats", "Analyzing...")}
          </button>
          
          <button 
            className={getButtonClass("btn btn-info", "mlAnalysis")}
            onClick={onRunMLAnalysis}
            disabled={isButtonDisabled("mlAnalysis")}
            title="Run machine learning anomaly detection"
          >
            {getButtonContent("mlAnalysis", "🤖 ML Analysis", "Processing...")}
          </button>
          
          {onComprehensiveAnalysis && (
            <button 
              className={getButtonClass("btn btn-primary", "comprehensiveAnalysis")}
              onClick={onComprehensiveAnalysis}
              disabled={isButtonDisabled("comprehensiveAnalysis")}
              title="Run comprehensive analysis combining all detection methods"
            >
              {getButtonContent("comprehensiveAnalysis", "🔍 Full Analysis", "Analyzing...")}
            </button>
          )}
        </div>
      </div>
      
      {/* Export controls */}
      <div className="controls-section">
        <h3>📊 Data Export</h3>
        <div className="controls">
          <button 
            className={getButtonClass("btn btn-success", "exportLogs")}
            onClick={onExportLogs}
            disabled={isButtonDisabled("exportLogs")}
            title="Export current logs to Excel file"
          >
            {getButtonContent("exportLogs", "📥 Export Logs", "Exporting...")}
          </button>
        </div>
      </div>

      {/* Status indicators */}
      <div className="controls-status">
        <div className="status-indicators">
          {Object.entries(buttonStates).map(([buttonName, state]) => {
            if (state === 'loading') {
              return (
                <div key={buttonName} className="status-indicator loading">
                  <span className="spinner">⏳</span>
                  <span>{buttonName} in progress...</span>
                </div>
              );
            }
            return null;
          })}
        </div>
      </div>
    </div>
  );
};

export default MonitoringControls;