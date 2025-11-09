import React, { useEffect, useRef, useState } from 'react';

const LogStream = ({ 
  logs, 
  allLogsCount, 
  isExpanded, 
  onToggleExpansion, 
  lastUpdateTime, 
  connectionStatus 
}) => {
  const logStreamRef = useRef(null);
  const [autoScroll, setAutoScroll] = useState(true);
  const [selectedLog, setSelectedLog] = useState(null);
  const normalizedStatus = (connectionStatus || '').toLowerCase();
  const connectionClass = ['connected', 'live', 'idle'].includes(normalizedStatus) ? 'connected' : 'disconnected';
  const connectionIcon = connectionClass === 'connected' ? '🟢' : '🔴';
  const totalAvailable = typeof allLogsCount === 'number' ? allLogsCount : logs.length;

  useEffect(() => {
    // Auto-scroll to bottom when new logs are added (if enabled)
    if (logStreamRef.current && autoScroll) {
      logStreamRef.current.scrollTop = logStreamRef.current.scrollHeight;
    }
  }, [logs, autoScroll]);

  const formatTimestamp = (timestamp) => {
    try {
      return new Date(timestamp).toLocaleString();
    } catch (e) {
      return timestamp;
    }
  };

  const formatShortTimestamp = (timestamp) => {
    try {
      return new Date(timestamp).toLocaleTimeString();
    } catch (e) {
      return timestamp;
    }
  };

  const getLevelColor = (level, severityColor) => {
    if (severityColor) return severityColor;
    
    const colors = {
      'CRITICAL': '#dc3545',
      'ERROR': '#fd7e14',
      'WARNING': '#ffc107',
      'INFO': '#17a2b8',
      'DEBUG': '#6c757d',
      'VERBOSE': '#6f42c1'
    };
    return colors[level?.toUpperCase()] || '#17a2b8';
  };

  const handleLogClick = (log) => {
    setSelectedLog(selectedLog?.id === log.id ? null : log);
  };

  const RulesEngineTooltip = ({ context }) => {
    if (!context) return null;
    
    return (
      <div className="rulesengine-tooltip">
        <strong>{context.type}</strong>
        <p>{context.explanation}</p>
        {context.scheduled_restart && (
          <p><strong>Scheduled:</strong> {context.scheduled_restart}</p>
        )}
      </div>
    );
  };

  return (
    <div className="card logs-container">
      <div className="logs-header">
        <div className="logs-title">
          <h2>📝 Live Log Stream</h2>
          <div className="logs-status">
            <span className={`connection-status ${connectionClass}`}>
              {connectionStatus} {connectionIcon}
            </span>
            {lastUpdateTime && (
              <span className="last-update">Last update: {lastUpdateTime}</span>
            )}
          </div>
        </div>
        <div className="logs-controls">
          <label className="auto-scroll-control">
            <input 
              type="checkbox" 
              checked={autoScroll}
              onChange={(e) => setAutoScroll(e.target.checked)}
            />
            Auto-scroll
          </label>
          <button 
            className="btn btn-expand"
            onClick={onToggleExpansion}
            title={isExpanded ? "Show latest 10 logs" : "Show all logs from session"}
          >
            {isExpanded ? "🔼 Collapse" : "🔽 Expand"} 
          </button>
          <span className="log-count">
            Showing: {logs.length} / Total: {totalAvailable}
          </span>
        </div>
      </div>

      <div className="log-stream-table" ref={logStreamRef}>
        {logs.length === 0 ? (
          <div className="no-logs">
            <div className="loading-spinner">⏳</div>
            <p>Waiting for log data...</p>
            <small>Make sure monitoring is started</small>
          </div>
        ) : (
          <table className="logs-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Level</th>
                <th>Type</th>
                <th>Source</th>
                <th>Event ID</th>
                <th>Message</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log, index) => {
                const isSelected = selectedLog?.id === log.id;
                const isRecent = log.is_recent;
                const isReplayed = Boolean(log.replayed);
                
                return (
                  <React.Fragment key={log.id || `${log.timestamp}-${index}`}>
                    <tr 
                      className={`log-row ${isRecent ? 'recent' : ''} ${isSelected ? 'selected' : ''} ${isReplayed ? 'replayed' : ''}`}
                      onClick={() => handleLogClick(log)}
                      title={isReplayed ? 'Replayed from historical backlog to maintain cadence' : undefined}
                    >
                      <td className="timestamp-cell">
                        <div className="timestamp-container">
                          <span className="short-time">{formatShortTimestamp(log.timestamp)}</span>
                          {log.time_ago && <span className="time-ago">{log.time_ago}</span>}
                        </div>
                      </td>
                      
                      <td className="level-cell">
                        <span 
                          className="level-badge"
                          style={{ 
                            backgroundColor: getLevelColor(log.level, log.severity_color),
                            color: 'white'
                          }}
                        >
                          {log.level || 'INFO'}
                        </span>
                      </td>
                      
                      <td className="type-cell">
                        <span className="type-badge">
                          {log.type_icon} {log.log_type}
                        </span>
                      </td>
                      
                      <td className="source-cell">
                        <span className="source-name">[{log.source}]</span>
                      </td>
                      
                      <td className="event-cell">
                        <span className="event-id">{log.event_id}</span>
                      </td>
                      
                      <td className="message-cell">
                        <div className="message-container">
                          <span className="message-text">{log.message}</span>
                          {isReplayed && (
                            <span className="replayed-badge" title="Historical log replayed for live stream cadence">Replayed</span>
                          )}
                          {log.has_rulesengine && (
                            <span className="rulesengine-indicator" title="Contains RulesEngine info">
                              🔧
                            </span>
                          )}
                        </div>
                      </td>
                    </tr>
                    
                    {isSelected && (
                      <tr className="log-details-row">
                        <td colSpan="6" className="log-details">
                          <div className="log-details-content">
                            <div className="detail-section">
                              <strong>Full Timestamp:</strong> {formatTimestamp(log.timestamp)}
                            </div>
                            {isReplayed && (
                              <div className="detail-section">
                                <strong>Replay Source:</strong> {log.original_id || 'Historical backlog'}
                              </div>
                            )}
                            <div className="detail-section">
                              <strong>Full Message:</strong>
                              <div className="full-message">{log.full_message || log.message}</div>
                            </div>
                            {log.rulesengine_context && (
                              <div className="detail-section">
                                <strong>RulesEngine Context:</strong>
                                <RulesEngineTooltip context={log.rulesengine_context} />
                              </div>
                            )}
                            <div className="detail-section">
                              <strong>Raw Data:</strong>
                              <pre className="raw-data">{log.raw_data}</pre>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};

export default LogStream;