import React from 'react';

const formatBytes = (bytes) => {
  if (typeof bytes !== 'number' || Number.isNaN(bytes)) {
    return '0 B';
  }
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let index = 0;
  let value = bytes;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index += 1;
  }
  return `${value.toFixed(1)} ${units[index]}`;
};

const SystemMetrics = ({ metrics, wsConnected }) => {
  return (
    <div className="card metrics-card">
      <div className="card-header">
        <h2>⚙️ System Metrics</h2>
        <span className={wsConnected ? 'badge badge-success' : 'badge badge-warning'}>
          {wsConnected ? 'Live Stream' : 'Polling'}
        </span>
      </div>
      {metrics && !metrics.error ? (
        <div className="metrics-grid">
          <div className="metric-item">
            <span className="metric-label">CPU</span>
            <span className="metric-value">{metrics.cpu_percent ?? 0}%</span>
          </div>
          <div className="metric-item">
            <span className="metric-label">Memory</span>
            <span className="metric-value">{metrics.memory_percent ?? 0}%</span>
            <small>{formatBytes(metrics.memory_used)} / {formatBytes(metrics.memory_total)}</small>
          </div>
          <div className="metric-item">
            <span className="metric-label">Disk</span>
            <span className="metric-value">{metrics.disk_percent ?? 0}%</span>
            <small>{formatBytes(metrics.disk_used)} / {formatBytes(metrics.disk_total)}</small>
          </div>
          <div className="metric-item">
            <span className="metric-label">Network Sent</span>
            <span className="metric-value">{formatBytes(metrics.bytes_sent || 0)}</span>
          </div>
          <div className="metric-item">
            <span className="metric-label">Network Received</span>
            <span className="metric-value">{formatBytes(metrics.bytes_recv || 0)}</span>
          </div>
        </div>
      ) : (
        <div className="empty-state">
          <p>Metrics unavailable. Ensure backend has system permissions.</p>
        </div>
      )}
    </div>
  );
};

export default SystemMetrics;
