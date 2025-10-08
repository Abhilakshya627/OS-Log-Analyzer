import React, { useState } from 'react';

const ThreatAlerts = ({ threats }) => {
  const [expandedThreat, setExpandedThreat] = useState(null);

  if (!threats || threats.length === 0) {
    return (
      <div className="card">
        <h2>🚨 Threat Alerts</h2>
        <div className="empty-state">
          <div style={{ padding: '20px', textAlign: 'center', color: '#666' }}>
            <div style={{ fontSize: '48px', marginBottom: '10px' }}>🛡️</div>
            <div>No active threats detected</div>
            <small>System is monitoring for security threats...</small>
          </div>
        </div>
      </div>
    );
  }

  const getSeverityIcon = (severity) => {
    const icons = {
      'critical': '🔥',
      'high': '⚠️',
      'medium': '🟡',
      'low': '🔵'
    };
    return icons[severity?.toLowerCase()] || '🔍';
  };

  const getSeverityColor = (severity) => {
    const colors = {
      'critical': '#dc3545',
      'high': '#fd7e14',
      'medium': '#ffc107',
      'low': '#17a2b8'
    };
    return colors[severity?.toLowerCase()] || '#6c757d';
  };

  const formatTimestamp = (timestamp) => {
    if (!timestamp) return 'Unknown time';
    const date = new Date(timestamp);
    return date.toLocaleString();
  };

  const toggleExpanded = (index) => {
    setExpandedThreat(expandedThreat === index ? null : index);
  };

  return (
    <div className="card">
      <h2>🚨 Threat Alerts</h2>
      <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
        {threats.slice(0, 10).map((threat, index) => (
          <div 
            key={threat.id || index} 
            className="threat-alert"
            style={{
              border: `2px solid ${getSeverityColor(threat.severity)}`,
              borderRadius: '8px',
              margin: '8px 0',
              padding: '12px',
              backgroundColor: 'rgba(248, 249, 250, 0.5)',
              cursor: 'pointer',
              transition: 'all 0.2s ease'
            }}
            onClick={() => toggleExpanded(index)}
          >
            <div style={{ display: 'flex', alignItems: 'center', marginBottom: '8px' }}>
              <span style={{ fontSize: '20px', marginRight: '8px' }}>
                {getSeverityIcon(threat.severity)}
              </span>
              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: 'bold', color: getSeverityColor(threat.severity) }}>
                  {(threat.threat_type || threat.type || 'Unknown Threat').replace(/_/g, ' ')}
                </div>
                <div style={{ fontSize: '12px', color: '#666' }}>
                  {formatTimestamp(threat.first_seen || threat.timestamp)}
                </div>
              </div>
              <div style={{ 
                backgroundColor: getSeverityColor(threat.severity),
                color: 'white',
                padding: '2px 8px',
                borderRadius: '12px',
                fontSize: '11px',
                fontWeight: 'bold'
              }}>
                {(threat.severity || 'UNKNOWN').toUpperCase()}
              </div>
            </div>
            
            <div style={{ marginBottom: '8px', fontSize: '14px' }}>
              {threat.description || 'No description available'}
            </div>
            
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: '#666' }}>
              <span>Confidence: {((threat.confidence || 0) * 100).toFixed(1)}%</span>
              {threat.source_ip && <span>IP: {threat.source_ip}</span>}
              {threat.event_count && threat.event_count > 1 && (
                <span>Count: {threat.event_count}</span>
              )}
            </div>

            {expandedThreat === index && (
              <div style={{ 
                marginTop: '12px', 
                padding: '8px', 
                backgroundColor: 'rgba(255, 255, 255, 0.7)',
                borderRadius: '4px',
                fontSize: '12px'
              }}>
                <div><strong>Details:</strong></div>
                {threat.target_system && (
                  <div>• Target: {threat.target_system}</div>
                )}
                {threat.last_seen && threat.first_seen !== threat.last_seen && (
                  <div>• Last seen: {formatTimestamp(threat.last_seen)}</div>
                )}
                {threat.raw_evidence && threat.raw_evidence.length > 0 && (
                  <div style={{ marginTop: '8px' }}>
                    <strong>Evidence:</strong>
                    <div style={{ 
                      fontFamily: 'monospace', 
                      fontSize: '10px', 
                      backgroundColor: '#f8f9fa',
                      padding: '4px',
                      borderRadius: '2px',
                      marginTop: '4px',
                      maxHeight: '100px',
                      overflowY: 'auto'
                    }}>
                      {threat.raw_evidence[0]?.substring(0, 200)}
                      {threat.raw_evidence[0]?.length > 200 && '...'}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
        
        {threats.length > 10 && (
          <div style={{ 
            textAlign: 'center', 
            padding: '10px', 
            color: '#666', 
            fontSize: '12px' 
          }}>
            Showing 10 of {threats.length} threats
          </div>
        )}
      </div>
    </div>
  );
};

export default ThreatAlerts;