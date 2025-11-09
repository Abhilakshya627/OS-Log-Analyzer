import React, { useMemo } from 'react';

const STATUS_META = {
  open: { label: 'Open', className: 'status-open', description: 'Awaiting triage' },
  investigating: { label: 'Investigating', className: 'status-investigating', description: 'Analyst is collecting evidence' },
  contained: { label: 'Contained', className: 'status-contained', description: 'Immediate impact mitigated' },
  resolved: { label: 'Resolved', className: 'status-resolved', description: 'No further action required' },
  closed: { label: 'Closed', className: 'status-closed', description: 'Case archived' }
};

const STATUS_OPTIONS = Object.keys(STATUS_META);

const QUICK_ACTIONS = [
  { label: 'Acknowledge', target: 'investigating', appliesTo: ['open'] },
  { label: 'Contain', target: 'contained', appliesTo: ['open', 'investigating'] },
  { label: 'Resolve', target: 'resolved', appliesTo: ['open', 'investigating', 'contained'] },
  { label: 'Close', target: 'closed', appliesTo: ['resolved'] }
];

const formatDate = (value) => {
  if (!value) {
    return 'N/A';
  }
  const date = typeof value === 'string' ? new Date(value) : value;
  if (Number.isNaN(date.getTime())) {
    return 'N/A';
  }
  return date.toLocaleString();
};

const IncidentCenter = ({ incidents, onUpdate }) => {
  const sortedIncidents = useMemo(() => {
    return [...incidents].sort((a, b) => {
      const first = new Date(a.created_at || 0).getTime();
      const second = new Date(b.created_at || 0).getTime();
      return second - first;
    });
  }, [incidents]);

  const handleStatusChange = (incidentId, event) => {
    onUpdate(incidentId, { status: event.target.value });
  };

  const handleQuickAction = (incidentId, targetStatus) => {
    onUpdate(incidentId, { status: targetStatus });
  };

  return (
    <div className="card incident-card">
      <div className="card-header">
        <h2>📁 Incident Center</h2>
        <span className="badge badge-muted">{incidents.length} incidents</span>
      </div>
      <div className="table-wrapper small">
        <table className="data-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Summary</th>
              <th>Status</th>
              <th>Created</th>
              <th>Last Action</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {sortedIncidents.slice(0, 15).map(incident => {
              const currentStatus = incident.status || 'open';
              const meta = STATUS_META[currentStatus] || STATUS_META.open;
              const applicableActions = QUICK_ACTIONS.filter(action => action.appliesTo.includes(currentStatus));

              return (
                <tr key={incident.id}>
                  <td>{incident.id}</td>
                  <td>{incident.summary || '—'}</td>
                  <td>
                    <div className="incident-status-cell" title={meta.description}>
                      <span className={`status-pill ${meta.className}`}>{meta.label}</span>
                      <select
                        className="incident-status-select"
                        value={currentStatus}
                        onChange={(event) => handleStatusChange(incident.id, event)}
                      >
                        {STATUS_OPTIONS.map(option => (
                          <option key={option} value={option}>{STATUS_META[option].label}</option>
                        ))}
                      </select>
                    </div>
                  </td>
                  <td>{formatDate(incident.created_at)}</td>
                  <td>{incident.resolved_at ? `Resolved ${formatDate(incident.resolved_at)}` : (incident.updated_at ? formatDate(incident.updated_at) : 'Pending')}</td>
                  <td>
                    <div className="incident-actions">
                      {applicableActions.map(action => (
                        <button
                          key={action.label}
                          type="button"
                          className={`incident-action-btn action-${action.target}`}
                          onClick={() => handleQuickAction(incident.id, action.target)}
                          disabled={currentStatus === action.target}
                        >
                          {action.label}
                        </button>
                      ))}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default IncidentCenter;
