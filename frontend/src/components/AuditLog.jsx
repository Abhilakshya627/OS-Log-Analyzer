import React from 'react';

const AuditLog = ({ entries }) => {
  return (
    <div className="card audit-log-card">
      <div className="card-header">
        <h2>📝 Audit Trail</h2>
        <span className="badge badge-muted">{entries.length} records</span>
      </div>
      <div className="table-wrapper small">
        <table className="data-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Actor</th>
              <th>Action</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {entries.slice(0, 20).map(entry => (
              <tr key={entry.id}>
                <td>{entry.created_at ? new Date(entry.created_at).toLocaleString() : 'N/A'}</td>
                <td>{entry.actor}</td>
                <td>{entry.action}</td>
                <td><pre>{entry.details}</pre></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default AuditLog;
