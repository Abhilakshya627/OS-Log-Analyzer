import React from 'react';

const MonitoringControls = ({ 
  onStartMonitoring, 
  onStopMonitoring, 
  onExportLogs, 
  onRunThreatAnalysis, 
  onRunMLAnalysis, 
  onRefreshData 
}) => {
  return (
    <div className="card">
      <h2>⚙️ Monitoring Controls</h2>
      <div className="controls">
        <button className="btn btn-primary" onClick={onStartMonitoring}>
          Start Monitor
        </button>
        <button className="btn btn-danger" onClick={onStopMonitoring}>
          Stop Monitor
        </button>
        <button className="btn btn-success" onClick={onExportLogs}>
          Export Logs
        </button>
      </div>
      
      <div className="controls">
        <button className="btn btn-primary" onClick={onRunThreatAnalysis}>
          Analyze Threats
        </button>
        <button className="btn btn-primary" onClick={onRunMLAnalysis}>
          ML Analysis
        </button>
        <button className="btn btn-primary" onClick={onRefreshData}>
          Refresh
        </button>
      </div>
    </div>
  );
};

export default MonitoringControls;