import React from 'react';

const ProcessManager = ({ processes, onAction }) => {
  const visibleGroups = processes.slice(0, 40);

  const formatStartTime = (iso) => {
    if (!iso) {
      return 'N/A';
    }
    try {
      return new Date(iso).toLocaleTimeString();
    } catch (_error) {
      return iso;
    }
  };

  const formatUsers = (users = []) => {
    if (!users || users.length === 0) {
      return 'Unknown';
    }
    if (users.length > 2) {
      return `${users[0]}, ${users[1]} +${users.length - 2}`;
    }
    return users.join(', ');
  };

  const formatPercent = (value) => {
    if (Number.isFinite(value)) {
      return Number(value).toFixed(2);
    }
    return value ?? '0.00';
  };

  const handleAction = (group, action) => {
    const promptLabel = action === 'blacklist' ? 'Provide reason for blacklisting (optional):' : `Provide reason for ${action} (optional):`;
    const reason = window.prompt(promptLabel, '') || undefined;
    onAction(group, action, reason);
  };

  return (
    <div className="card process-card">
      <div className="card-header">
        <h2>🧠 Process Manager</h2>
        <span className="badge badge-muted">{processes.length} apps tracked</span>
      </div>
      <div className="table-wrapper process-table">
        <table className="data-table">
          <thead>
            <tr>
              <th>App</th>
              <th>Instances</th>
              <th>Users</th>
              <th>CPU %</th>
              <th>Mem %</th>
              <th>Started</th>
              <th>PIDs</th>
              <th className="actions-header">Actions</th>
            </tr>
          </thead>
          <tbody>
            {visibleGroups.length === 0 ? (
              <tr>
                <td colSpan={8} className="empty-state">No active processes reported.</td>
              </tr>
            ) : (
              visibleGroups.map(group => (
                <tr key={group.app_id}>
                  <td title={group.exe || group.identifier}>
                    <div className="process-name">
                      <span>{group.display_name || group.name}</span>
                      {group.exe && <span className="process-subtitle">{group.exe}</span>}
                    </div>
                  </td>
                  <td>{group.instances}</td>
                  <td title={(group.usernames || []).join(', ') || 'Unknown'}>{formatUsers(group.usernames)}</td>
                  <td>{formatPercent(group.cpu)}</td>
                  <td>{formatPercent(group.memory)}</td>
                  <td>{formatStartTime(group.create_time)}</td>
                  <td title={(group.pids || []).join(', ')}>{(group.pids || []).slice(0, 3).join(', ')}{(group.pids || []).length > 3 ? '...' : ''}</td>
                  <td className="actions process-actions">
                    <button
                      className="btn-small btn-danger"
                      onClick={() => handleAction(group, 'kill')}
                    >
                      Kill App
                    </button>
                    <button
                      className="btn-small btn-warning"
                      onClick={() => handleAction(group, 'quarantine')}
                    >
                      Quarantine
                    </button>
                    <button
                      className="btn-small btn-secondary"
                      onClick={() => handleAction(group, 'blacklist')}
                    >
                      Blacklist App
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default ProcessManager;
