import React from 'react';

const Header = ({ systemStatus, connectionStatus, wsConnected }) => {
  return (
    <div className="header">
      <h1>🛡️ OS Log Analyzer Dashboard</h1>
      
      <div className={`connection-status ${wsConnected ? 'connected' : 'disconnected'}`}>
        {wsConnected ? 'Live Stream' : 'Stream Offline'}
      </div>
    </div>
  );
};

//Data Exfileration and Persistence Error

export default Header;