import React, { useMemo, useState } from 'react';

const BlacklistManager = ({ entries, onAdd, onRemove, onEnforce, enforcing = false, lastEnforced }) => {
  const [identifier, setIdentifier] = useState('');
  const [type, setType] = useState('process');
  const [reason, setReason] = useState('');
  const [search, setSearch] = useState('');
  const [filterType, setFilterType] = useState('all');
  const [showActiveOnly, setShowActiveOnly] = useState(false);

  const handleSubmit = (event) => {
    event.preventDefault();
    if (!identifier.trim()) {
      return;
    }
    onAdd({ identifier: identifier.trim(), type, reason: reason || undefined });
    setIdentifier('');
    setReason('');
  };

  const summary = useMemo(() => {
    const counts = entries.reduce(
      (acc, entry) => {
        const entryType = (entry.type || 'process').toLowerCase();
        acc.total += 1;
        acc[entryType] = (acc[entryType] || 0) + 1;
        if (entry.active === 0) {
          acc.inactive += 1;
        }
        return acc;
      },
      { total: 0, process: 0, path: 0, hash: 0, inactive: 0 }
    );
    return counts;
  }, [entries]);

  const filteredEntries = useMemo(() => {
    const searchValue = search.trim().toLowerCase();
    return entries
      .filter(entry => (filterType === 'all' ? true : entry.type === filterType))
      .filter(entry => (!showActiveOnly ? true : entry.active !== 0))
      .filter(entry => {
        if (!searchValue) {
          return true;
        }
        const identifierValue = (entry.identifier || '').toLowerCase();
        const reasonValue = (entry.reason || '').toLowerCase();
        return identifierValue.includes(searchValue) || reasonValue.includes(searchValue);
      })
      .slice(0, 30);
  }, [entries, filterType, search, showActiveOnly]);

  const handleClearFilters = () => {
    setSearch('');
    setFilterType('all');
    setShowActiveOnly(false);
  };

  const handleEnforceClick = () => {
    if (onEnforce) {
      onEnforce();
    }
  };

  const lastEnforcedLabel = useMemo(() => {
    if (!lastEnforced) {
      return null;
    }
    const value = typeof lastEnforced === 'string' ? new Date(lastEnforced) : lastEnforced;
    if (Number.isNaN(value.getTime())) {
      return null;
    }
    return value.toLocaleTimeString();
  }, [lastEnforced]);

  return (
    <div className="card blacklist-card">
      <div className="card-header">
        <h2>🚫 Blacklist Manager</h2>
        <span className="badge badge-muted">{entries.length} entries</span>
      </div>
      <div className="blacklist-toolbar">
        <div className="blacklist-summary">
          <div className="summary-chip">
            <span className="label">Total</span>
            <span className="value">{summary.total}</span>
          </div>
          <div className="summary-chip">
            <span className="label">Processes</span>
            <span className="value">{summary.process}</span>
          </div>
          <div className="summary-chip">
            <span className="label">Paths</span>
            <span className="value">{summary.path}</span>
          </div>
          <div className="summary-chip">
            <span className="label">Hashes</span>
            <span className="value">{summary.hash}</span>
          </div>
          {summary.inactive > 0 && (
            <div className="summary-chip warning">
              <span className="label">Inactive</span>
              <span className="value">{summary.inactive}</span>
            </div>
          )}
        </div>
        <div className="blacklist-actions">
          <button
            type="button"
            className={`btn ${enforcing ? 'loading' : ''}`}
            onClick={handleEnforceClick}
            disabled={enforcing || !onEnforce}
          >
            {enforcing ? 'Enforcing…' : 'Enforce Now'}
          </button>
          {lastEnforcedLabel && (
            <span className="timestamp">Last enforced {lastEnforcedLabel}</span>
          )}
        </div>
      </div>

      <form className="blacklist-form" onSubmit={handleSubmit}>
        <input
          type="text"
          placeholder="Identifier (process name, path, hash)"
          value={identifier}
          onChange={(e) => setIdentifier(e.target.value)}
        />
        <select value={type} onChange={(e) => setType(e.target.value)}>
          <option value="process">Process</option>
          <option value="path">Path</option>
          <option value="hash">Hash</option>
        </select>
        <input
          type="text"
          placeholder="Reason (optional)"
          value={reason}
          onChange={(e) => setReason(e.target.value)}
        />
        <button type="submit" className="btn">Add</button>
      </form>

      <div className="blacklist-filters">
        <input
          type="search"
          placeholder="Search identifier or reason"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
        />
        <select value={filterType} onChange={(event) => setFilterType(event.target.value)}>
          <option value="all">All types</option>
          <option value="process">Process</option>
          <option value="path">Path</option>
          <option value="hash">Hash</option>
        </select>
        <label className="checkbox">
          <input
            type="checkbox"
            checked={showActiveOnly}
            onChange={(event) => setShowActiveOnly(event.target.checked)}
          />
          <span>Active only</span>
        </label>
        <button type="button" className="btn btn-secondary" onClick={handleClearFilters}>
          Clear
        </button>
      </div>

      <div className="table-wrapper small blacklist-table">
        <table className="data-table">
          <thead>
            <tr>
              <th>Status</th>
              <th>Identifier</th>
              <th>Type</th>
              <th>Reason</th>
              <th>Created</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {filteredEntries.length === 0 ? (
              <tr>
                <td colSpan={6} className="empty-state">No blacklist entries match the current filters.</td>
              </tr>
            ) : (
              filteredEntries.map(entry => (
                <tr key={`${entry.id}-${entry.identifier}`}>
                  <td>
                    <span className={`status-dot ${entry.active === 0 ? 'inactive' : 'active'}`}></span>
                  </td>
                  <td>{entry.identifier}</td>
                  <td>{entry.type}</td>
                  <td>{entry.reason || '—'}</td>
                  <td>{entry.created_at ? new Date(entry.created_at).toLocaleString() : 'N/A'}</td>
                  <td className="actions">
                    <button className="btn-small btn-danger" onClick={() => onRemove(entry.identifier)}>
                      Remove
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

export default BlacklistManager;
