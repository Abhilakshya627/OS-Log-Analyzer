import React from 'react';

const Header = ({ systemStatus, connectionStatus }) => {
  return (
    <div className="header">
      <h1>🛡️ OS Log Analyzer Dashboard</h1>
      <div className="status-indicator">
        <div className="status-dot"></div>
        <span>{systemStatus?.monitoring_active ? 'System Active' : 'System Inactive'}</span>
      </div>
      
      <div className={`connection-status ${connectionStatus === 'Connected' ? 'connected' : 'disconnected'}`}>
        {connectionStatus}
      </div>
    </div>
  );
};

export default Header;