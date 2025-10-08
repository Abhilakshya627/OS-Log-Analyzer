import React from 'react';

const MLAnomalies = ({ anomalies }) => {
  if (!anomalies || anomalies.length === 0) {
    return (
      <div className="card">
        <h2>🤖 ML Anomalies</h2>
        <div className="empty-state">
          No anomalies detected
        </div>
      </div>
    );
  }

  return (
    <div className="card">
      <h2>🤖 ML Anomalies</h2>
      <div>
        {anomalies.map((anomaly, index) => (
          <div 
            key={index} 
            style={{
              padding: '0.5rem',
              margin: '0.5rem 0',
              background: 'rgba(255, 193, 7, 0.1)',
              borderLeft: '4px solid #ffc107',
              borderRadius: '4px'
            }}
          >
            <strong>Anomaly Score: {anomaly.anomaly_score?.toFixed(3) || 'N/A'}</strong>
            <br />
            <small>{anomaly.description}</small>
          </div>
        ))}
      </div>
    </div>
  );
};

export default MLAnomalies;