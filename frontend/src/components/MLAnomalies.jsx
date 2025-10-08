import React, { useState } from 'react';

const MLAnomalies = ({ anomalies }) => {
  const [expandedAnomaly, setExpandedAnomaly] = useState(null);
  const [filterMethod, setFilterMethod] = useState('all');

  if (!anomalies || anomalies.length === 0) {
    return (
      <div className="card">
        <h2>🤖 ML Anomalies</h2>
        <div className="empty-state">
          <div style={{ padding: '20px', textAlign: 'center', color: '#666' }}>
            <div style={{ fontSize: '48px', marginBottom: '10px' }}>🧠</div>
            <div>No anomalies detected</div>
            <small>Machine learning is analyzing patterns...</small>
          </div>
        </div>
      </div>
    );
  }

  const getMethodIcon = (method) => {
    const icons = {
      'Rule-based Analysis': '📋',
      'Statistical Analysis': '📊',
      'Pattern Analysis': '🔍',
      'Temporal Analysis': '⏰',
      'Activity Spike Analysis': '📈',
      'Error Rate Analysis': '⚠️',
      'Isolation Forest ML': '🤖',
      'Isolation Forest': '🌲'
    };
    return icons[method] || '🔬';
  };

  const getScoreColor = (score) => {
    if (score >= 0.8) return '#dc3545'; // Red for high score
    if (score >= 0.6) return '#fd7e14'; // Orange for medium-high
    if (score >= 0.4) return '#ffc107'; // Yellow for medium
    return '#28a745'; // Green for low score
  };

  const getScoreIntensity = (score) => {
    return Math.min(score * 100, 100);
  };

  const formatTimestamp = (timestamp) => {
    if (!timestamp) return 'Unknown time';
    const date = new Date(timestamp);
    return date.toLocaleString();
  };

  const toggleExpanded = (index) => {
    setExpandedAnomaly(expandedAnomaly === index ? null : index);
  };

  // Filter anomalies by detection method
  const filteredAnomalies = filterMethod === 'all' 
    ? anomalies 
    : anomalies.filter(anomaly => anomaly.detection_method === filterMethod);

  // Get unique detection methods for filter
  const detectionMethods = [...new Set(anomalies.map(a => a.detection_method))];

  return (
    <div className="card">
      <h2>🤖 ML Anomalies</h2>
      
      {/* Filter dropdown */}
      {detectionMethods.length > 1 && (
        <div style={{ marginBottom: '15px' }}>
          <select 
            value={filterMethod} 
            onChange={(e) => setFilterMethod(e.target.value)}
            style={{
              padding: '5px 10px',
              borderRadius: '4px',
              border: '1px solid #ddd',
              fontSize: '12px'
            }}
          >
            <option value="all">All Methods ({anomalies.length})</option>
            {detectionMethods.map(method => (
              <option key={method} value={method}>
                {method} ({anomalies.filter(a => a.detection_method === method).length})
              </option>
            ))}
          </select>
        </div>
      )}

      <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
        {filteredAnomalies.slice(0, 15).map((anomaly, index) => (
          <div 
            key={index} 
            style={{
              border: `2px solid ${getScoreColor(anomaly.anomaly_score)}`,
              borderRadius: '8px',
              margin: '8px 0',
              padding: '12px',
              backgroundColor: `rgba(${getScoreColor(anomaly.anomaly_score).replace('#', '')
                .match(/.{2}/g).map(x => parseInt(x, 16)).join(', ')}, 0.1)`,
              cursor: 'pointer',
              transition: 'all 0.2s ease'
            }}
            onClick={() => toggleExpanded(index)}
          >
            {/* Header */}
            <div style={{ display: 'flex', alignItems: 'center', marginBottom: '8px' }}>
              <span style={{ fontSize: '20px', marginRight: '8px' }}>
                {getMethodIcon(anomaly.detection_method)}
              </span>
              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: 'bold', fontSize: '14px' }}>
                  {anomaly.detection_method || 'ML Anomaly'}
                </div>
                <div style={{ fontSize: '11px', color: '#666' }}>
                  {formatTimestamp(anomaly.timestamp)}
                </div>
              </div>
              <div style={{ 
                display: 'flex',
                alignItems: 'center',
                gap: '8px'
              }}>
                {/* Score bar */}
                <div style={{
                  width: '60px',
                  height: '8px',
                  backgroundColor: '#e9ecef',
                  borderRadius: '4px',
                  overflow: 'hidden'
                }}>
                  <div style={{
                    width: `${getScoreIntensity(anomaly.anomaly_score)}%`,
                    height: '100%',
                    backgroundColor: getScoreColor(anomaly.anomaly_score),
                    transition: 'width 0.3s ease'
                  }} />
                </div>
                <span style={{ 
                  fontSize: '11px', 
                  fontWeight: 'bold',
                  color: getScoreColor(anomaly.anomaly_score),
                  minWidth: '35px'
                }}>
                  {(anomaly.anomaly_score || 0).toFixed(2)}
                </span>
              </div>
            </div>
            
            {/* Description */}
            <div style={{ 
              fontSize: '13px', 
              marginBottom: '8px',
              lineHeight: '1.4'
            }}>
              {anomaly.description || 'No description available'}
            </div>
            
            {/* Basic log info */}
            {anomaly.log_entry && (
              <div style={{ fontSize: '11px', color: '#666' }}>
                {anomaly.log_entry.source && (
                  <span>Source: {anomaly.log_entry.source} • </span>
                )}
                {anomaly.log_entry.level && (
                  <span>Level: {anomaly.log_entry.level} • </span>
                )}
                {anomaly.log_entry.message_length && (
                  <span>Msg Length: {anomaly.log_entry.message_length}</span>
                )}
              </div>
            )}

            {/* Expanded details */}
            {expandedAnomaly === index && (
              <div style={{ 
                marginTop: '12px', 
                padding: '10px', 
                backgroundColor: 'rgba(255, 255, 255, 0.8)',
                borderRadius: '6px',
                fontSize: '12px'
              }}>
                <div style={{ marginBottom: '8px' }}>
                  <strong>Detailed Analysis:</strong>
                </div>
                
                {/* Log entry details */}
                {anomaly.log_entry && (
                  <div style={{ marginBottom: '12px' }}>
                    {anomaly.log_entry.message && (
                      <div style={{ marginBottom: '6px' }}>
                        <strong>Message:</strong>
                        <div style={{ 
                          fontFamily: 'monospace', 
                          fontSize: '10px', 
                          backgroundColor: '#f8f9fa',
                          padding: '6px',
                          borderRadius: '3px',
                          marginTop: '3px',
                          maxHeight: '80px',
                          overflowY: 'auto',
                          wordBreak: 'break-all'
                        }}>
                          {anomaly.log_entry.message}
                        </div>
                      </div>
                    )}
                    
                    {/* Statistical data */}
                    {anomaly.log_entry.error_count && (
                      <div>
                        <strong>Error Analysis:</strong> {anomaly.log_entry.error_count} errors 
                        out of {anomaly.log_entry.total_count} total logs 
                        ({anomaly.log_entry.error_rate})
                      </div>
                    )}
                    
                    {/* Activity data */}
                    {anomaly.log_entry.log_count && (
                      <div>
                        <strong>Activity Analysis:</strong> {anomaly.log_entry.log_count} logs 
                        (average: {anomaly.log_entry.average_count})
                      </div>
                    )}
                    
                    {/* Pattern data */}
                    {anomaly.log_entry.pattern && (
                      <div>
                        <strong>Pattern:</strong> "{anomaly.log_entry.pattern}" 
                        (occurred {anomaly.log_entry.occurrence_count} times)
                      </div>
                    )}
                    
                    {/* Timing data */}
                    {anomaly.log_entry.unusual_rate && (
                      <div>
                        <strong>Timing Analysis:</strong> {anomaly.log_entry.unusual_rate} 
                        unusual activity ({anomaly.log_entry.unusual_activity_count}/{anomaly.log_entry.total_activity_count})
                      </div>
                    )}
                    
                    {/* ML features */}
                    {anomaly.log_entry.anomaly_features && (
                      <div style={{ marginTop: '6px' }}>
                        <strong>ML Features:</strong>
                        <div style={{ fontSize: '10px', marginTop: '3px' }}>
                          {Object.entries(anomaly.log_entry.anomaly_features).map(([key, value]) => (
                            <span key={key} style={{ marginRight: '12px' }}>
                              {key}: {value}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
        
        {filteredAnomalies.length > 15 && (
          <div style={{ 
            textAlign: 'center', 
            padding: '10px', 
            color: '#666', 
            fontSize: '12px' 
          }}>
            Showing 15 of {filteredAnomalies.length} anomalies
          </div>
        )}
      </div>
    </div>
  );
};

export default MLAnomalies;