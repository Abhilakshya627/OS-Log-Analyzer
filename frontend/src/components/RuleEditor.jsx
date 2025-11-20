import React, { useState } from 'react';

const defaultRule = {
  name: '',
  pattern: '',
  severity: 'medium',
  action: 'alert'
};

const RuleEditor = ({ rules, onCreate, onUpdate, onDelete }) => {
  const [form, setForm] = useState(defaultRule);

  const handleChange = (event) => {
    const { name, value } = event.target;
    setForm(prev => ({ ...prev, [name]: value }));
  };

  const handleSubmit = (event) => {
    event.preventDefault();
    if (!form.name.trim() || !form.pattern.trim()) {
      return;
    }
    onCreate({ ...form, name: form.name.trim(), pattern: form.pattern.trim() });
    setForm(defaultRule);
  };

  const toggleRule = (rule) => {
    onUpdate(rule.id, { enabled: rule.enabled ? 0 : 1 });
  };

  return (
    <div className="card">
      <div className="card-header">
        <h2>🧩 Detection Rules</h2>
        <span className="badge badge-muted">{rules.length} rules</span>
      </div>

      <form className="rule-form" onSubmit={handleSubmit}>
        <input
          type="text"
          name="name"
          placeholder="Rule name"
          value={form.name}
          onChange={handleChange}
        />
        <input
          type="text"
          name="pattern"
          placeholder="Regex or keyword pattern"
          value={form.pattern}
          onChange={handleChange}
        />
        <select name="severity" value={form.severity} onChange={handleChange}>
          <option value="low">Low</option>
          <option value="medium">Medium</option>
          <option value="high">High</option>
          <option value="critical">Critical</option>
        </select>
        <select name="action" value={form.action} onChange={handleChange}>
          <option value="alert">Alert</option>
          <option value="block">Block</option>
        </select>
        <button type="submit" className="btn">Create Rule</button>
      </form>

      <div className="table-wrapper small">
        <table className="data-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Pattern</th>
              <th>Severity</th>
              <th>Action</th>
              <th>Status</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {rules.slice(0, 15).map(rule => (
              <tr key={rule.id}>
                <td>{rule.name}</td>
                <td><code>{rule.pattern}</code></td>
                <td>{rule.severity}</td>
                <td>{rule.action}</td>
                <td>
                  <button
                    type="button"
                    className={`btn-small ${rule.enabled ? 'btn-success' : 'btn-secondary'}`}
                    onClick={() => toggleRule(rule)}
                  >
                    {rule.enabled ? 'Enabled' : 'Disabled'}
                  </button>
                </td>
                <td>
                  <button className="btn-small btn-danger" onClick={() => onDelete(rule.id)}>Delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default RuleEditor;
