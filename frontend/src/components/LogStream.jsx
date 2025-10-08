import React, { useEffect, useRef } from 'react';

const LogStream = ({ logs }) => {
  const logStreamRef = useRef(null);

  useEffect(() => {
    // Auto-scroll to bottom when new logs are added
    if (logStreamRef.current) {
      logStreamRef.current.scrollTop = logStreamRef.current.scrollHeight;
    }
  }, [logs]);

  const formatLogLevel = (level) => {
    return level ? level.toLowerCase() : 'info';
  };

  const formatTimestamp = (timestamp) => {
    try {
      return new Date(timestamp).toLocaleTimeString();
    } catch (e) {
      return timestamp;
    }
  };

  return (
    <div className="card logs-container">
      <h2>📝 Live Log Stream</h2>
      <div className="log-stream" ref={logStreamRef}>
        {logs.length === 0 ? (
          <div className="log-entry">
            <span className="log-timestamp">[System]</span>
            <span className="log-message">Waiting for log data...</span>
          </div>
        ) : (
          logs.map((log, index) => {
            const level = formatLogLevel(log.level);
            const timestamp = formatTimestamp(log.timestamp);
            
            return (
              <div key={`${log.timestamp}-${index}`} className="log-entry">
                <span className="log-timestamp">[{timestamp}]</span>
                <span className={`log-level-${level}`}>[{level.toUpperCase()}]</span>
                <span className="log-message">{log.message}</span>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};

export default LogStream;