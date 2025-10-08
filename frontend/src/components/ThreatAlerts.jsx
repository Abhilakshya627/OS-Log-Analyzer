import React from 'react';

const ThreatAlerts = ({ threats }) => {
  if (!threats || threats.length === 0) {
    return (
      <div className="card">
        <h2>🚨 Threat Alerts</h2>
        <div className="empty-state">
          No active threats detected
        </div>
      </div>
    );
  }

  return (
    <div className="card">
      <h2>🚨 Threat Alerts</h2>
      <div>
        {threats.slice(0, 5).map((threat, index) => (
          <div key={threat.id || index} className="threat-alert">
            <div className="threat-type">
              🚨 {threat.type.replace(/_/g, ' ')}
            </div>
            <div className="threat-description">
              {threat.description}
            </div>
            <small>
              Confidence: {((threat.confidence || 0) * 100).toFixed(1)}% | 
              Severity: {threat.severity}
            </small>
          </div>
        ))}
      </div>
    </div>
  );
};

export default ThreatAlerts;