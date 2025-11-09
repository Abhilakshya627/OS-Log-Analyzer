import React, { useState, useEffect, useCallback, useRef } from 'react';
import Header from './components/Header';
import SystemStats from './components/SystemStats';
import MonitoringControls from './components/MonitoringControls';
import ThreatAlerts from './components/ThreatAlerts';
import MLAnomalies from './components/MLAnomalies';
import LogStream from './components/LogStream';
import SystemMetrics from './components/SystemMetrics';
import ProcessManager from './components/ProcessManager';
import BlacklistManager from './components/BlacklistManager';
import RuleEditor from './components/RuleEditor';
import IncidentCenter from './components/IncidentCenter';
import AuditLog from './components/AuditLog';
import { apiService } from './services/api';
import './enhanced-styles.css';

function App() {
  // State management
  const [systemStatus, setSystemStatus] = useState(null);
  const [connectionStatus, setConnectionStatus] = useState('Connecting...');
  const [allLogs, setAllLogs] = useState([]);
  const [totalLogsCount, setTotalLogsCount] = useState(0);
  const [displayLogs, setDisplayLogs] = useState([]);
  const [logViewExpanded, setLogViewExpanded] = useState(false);
  const [logsPerPage] = useState(30);
  const [threats, setThreats] = useState([]);
  const [anomalies, setAnomalies] = useState([]);
  const [stats, setStats] = useState({
    totalLogs: 0,
    threatsDetected: 0,
    anomaliesFound: 0,
    uptime: 0
  });
  const [activityData, setActivityData] = useState([]);
  const [startTime] = useState(new Date());
  const [buttonStates, setButtonStates] = useState({});
  const [lastUpdateTime, setLastUpdateTime] = useState(null);
  const [notifications, setNotifications] = useState([]);
  const [metrics, setMetrics] = useState(null);
  const [processes, setProcesses] = useState([]);
  const [blacklistEntries, setBlacklistEntries] = useState([]);
  const [enforcingBlacklist, setEnforcingBlacklist] = useState(false);
  const [lastBlacklistEnforce, setLastBlacklistEnforce] = useState(null);
  const [rules, setRules] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [wsConnected, setWsConnected] = useState(false);
  const wsRef = useRef(null);

  // Add notification helper
  const addNotification = useCallback((message, type = 'info') => {
    const id = Date.now();
    const notification = { id, message, type, timestamp: new Date() };
    setNotifications(prev => [notification, ...prev].slice(0, 2));

    // Auto-remove notification after 3 seconds
    setTimeout(() => {
      setNotifications(prev => prev.filter(n => n.id !== id));
    }, 3000);
  }, []);

  // Update stats based on current data
  const updateStats = useCallback(() => {
    const currentTime = new Date();
    const uptime = Math.floor((currentTime - startTime) / 1000);
    const logCount = totalLogsCount > 0 ? totalLogsCount : allLogs.length;
    
    setStats(prevStats => ({
      ...prevStats,
      totalLogs: logCount,
      threatsDetected: threats.length,
      anomaliesFound: anomalies.length,
      uptime: uptime
    }));

    // Update activity chart data
    const timeLabel = currentTime.toLocaleTimeString();
    setActivityData(prevData => {
      const newData = [...prevData, {
        time: timeLabel,
        logs: logCount,
        threats: threats.length,
        timestamp: currentTime
      }];
      return newData.slice(-30); // Keep last 30 data points
    });
  }, [totalLogsCount, allLogs.length, threats.length, anomalies.length, startTime]);

  // Enhanced error handling wrapper
  const withErrorHandling = useCallback((asyncFn, errorMessage) => {
    return async (...args) => {
      try {
        return await asyncFn(...args);
      } catch (error) {
        console.error(errorMessage, error);
        const message = error.response?.data?.error || error.message || errorMessage;
        addNotification(`❌ ${message}`, 'error');
        setConnectionStatus('Error');
        throw error;
      }
    };
  }, [addNotification]);

  // Fetch system status with error handling
  const fetchSystemStatus = useCallback(withErrorHandling(
    async () => {
      const response = await apiService.getSystemStatus();
      setSystemStatus(response.data);
      setConnectionStatus('Connected');
      return response.data;
    },
    'Failed to fetch system status'
  ), [withErrorHandling]);

  // Fetch live logs with error handling
  const fetchLogs = useCallback(withErrorHandling(
    async () => {
      const response = await apiService.getLiveLogs(100);
      const payload = response.data || {};
      const newLogs = Array.isArray(payload.logs) ? payload.logs : [];
      const normalizedLogs = newLogs.map(log => ({
        ...log,
        received_at: log.received_at || log.timestamp || new Date().toISOString(),
      }));
      const resolvedTotal = typeof payload.total === 'number'
        ? payload.total
        : typeof payload.total_logs === 'number'
          ? payload.total_logs
          : normalizedLogs.length;
      setTotalLogsCount(resolvedTotal);

      if (normalizedLogs.length > 0) {

        setAllLogs(prevAllLogs => {
          // Create a map to avoid duplicates
          const existingLogMap = new Map();
          prevAllLogs.forEach(log => {
            existingLogMap.set(log.id || log.timestamp, log);
          });
          
          // Add new unique logs
          const uniqueNewLogs = normalizedLogs.filter(log => {
            const logId = log.id || log.timestamp;
            return !existingLogMap.has(logId);
          });
          
          const realNewLogs = uniqueNewLogs.filter(log => !log.replayed);
          if (realNewLogs.length > 0) {
            addNotification(`📊 Added ${realNewLogs.length} new log entries`, 'success');
          }
          
          // Combine and sort
          const combinedLogs = [...prevAllLogs, ...uniqueNewLogs];
          const sortValue = (entry) => {
            const basis = entry.received_at || entry.timestamp;
            return basis ? new Date(basis).getTime() : 0;
          };
          return combinedLogs
            .sort((a, b) => sortValue(b) - sortValue(a))
            .slice(0, 1000);
        });
        
        setLastUpdateTime(new Date().toLocaleTimeString());
      }
      setConnectionStatus('Connected');
    },
    'Failed to fetch logs'
  ), [withErrorHandling, addNotification]);

  // Update display logs based on expansion state
  const updateDisplayLogs = useCallback(() => {
    if (logViewExpanded) {
      setDisplayLogs(allLogs);
    } else {
      setDisplayLogs(allLogs.slice(0, logsPerPage));
    }
  }, [allLogs, logViewExpanded, logsPerPage]);

  // Toggle log view expansion
  const toggleLogView = useCallback(() => {
    setLogViewExpanded(prev => !prev);
    addNotification(
      logViewExpanded ? '📋 Collapsed log view' : '📋 Expanded log view', 
      'info'
    );
  }, [logViewExpanded, addNotification]);

  // Fetch active threats with error handling
  const fetchThreats = useCallback(withErrorHandling(
    async () => {
      const response = await apiService.getActiveThreats();
      if (response.data.threats) {
        const newThreats = response.data.threats;
        setThreats(newThreats);
        
        if (newThreats.length > 0) {
          addNotification(`🚨 ${newThreats.length} threats detected`, 'warning');
        }
      }
    },
    'Failed to fetch threats'
  ), [withErrorHandling, addNotification]);

  // Fetch ML anomalies with error handling
  const fetchAnomalies = useCallback(withErrorHandling(
    async () => {
      const response = await apiService.getMLAnomalies();
      if (response.data.anomalies) {
        const newAnomalies = response.data.anomalies;
        setAnomalies(newAnomalies);
        
        if (newAnomalies.length > 0) {
          addNotification(`🔍 ${newAnomalies.length} anomalies found`, 'warning');
        }
      }
    },
    'Failed to fetch anomalies'
  ), [withErrorHandling, addNotification]);

  const fetchMetrics = useCallback(withErrorHandling(
    async () => {
      const response = await apiService.getSystemMetrics();
      if (response.data.metrics) {
        setMetrics(response.data.metrics);
      }
      if (response.data.processes) {
        setProcesses(response.data.processes);
      }
    },
    'Failed to fetch system metrics'
  ), [withErrorHandling]);

  const fetchProcesses = useCallback(withErrorHandling(
    async () => {
      const response = await apiService.getProcesses();
      if (response.data.processes) {
        setProcesses(response.data.processes);
      }
    },
    'Failed to fetch processes'
  ), [withErrorHandling]);

  const fetchBlacklist = useCallback(withErrorHandling(
    async () => {
      const response = await apiService.getBlacklist();
      if (response.data.blacklist) {
        setBlacklistEntries(response.data.blacklist);
      }
    },
    'Failed to fetch blacklist'
  ), [withErrorHandling]);

  const fetchRules = useCallback(withErrorHandling(
    async () => {
      const response = await apiService.getRules();
      if (response.data.rules) {
        setRules(response.data.rules);
      }
    },
    'Failed to fetch rules'
  ), [withErrorHandling]);

  const fetchIncidents = useCallback(withErrorHandling(
    async () => {
      const response = await apiService.getIncidents();
      if (response.data.incidents) {
        setIncidents(response.data.incidents);
      }
    },
    'Failed to fetch incidents'
  ), [withErrorHandling]);

  const fetchAuditLogs = useCallback(withErrorHandling(
    async () => {
      const response = await apiService.getAuditLogs();
      if (response.data.audit_logs) {
        setAuditLogs(response.data.audit_logs);
      }
    },
    'Failed to fetch audit logs'
  ), [withErrorHandling]);

  const appendUniqueLog = useCallback((incomingLog) => {
    const sourceLog = incomingLog || {};
    const { collection_total, ...log } = sourceLog;
    const normalizedLog = {
      ...log,
      received_at: log.received_at || log.timestamp || new Date().toISOString(),
    };
    let added = false;
    setAllLogs(prevAllLogs => {
      const existingMap = new Map();
      prevAllLogs.forEach(item => {
        existingMap.set(item.id || item.timestamp, item);
      });
      const logId = normalizedLog.id || normalizedLog.timestamp;
      if (!logId || existingMap.has(logId)) {
        return prevAllLogs;
      }
      added = true;
      const combined = [normalizedLog, ...prevAllLogs];
      const sortValue = (entry) => {
        const basis = entry.received_at || entry.timestamp;
        return basis ? new Date(basis).getTime() : 0;
      };
      return combined
        .sort((a, b) => sortValue(b) - sortValue(a))
        .slice(0, 1000);
    });

    if (typeof collection_total === 'number') {
      setTotalLogsCount(collection_total);
    } else if (added) {
      setTotalLogsCount(prev => prev + 1);
    }
  }, []);

  const handleWebSocketMessage = useCallback((event) => {
    try {
      const data = JSON.parse(event.data);
      const { type, payload } = data;
      switch (type) {
        case 'snapshot':
          if (payload.logs) {
            const normalizedSnapshot = payload.logs.map(log => ({
              ...log,
              received_at: log.received_at || log.timestamp || new Date().toISOString(),
            }));
            setAllLogs(normalizedSnapshot);
          }
          if (typeof payload.total_logs === 'number') {
            setTotalLogsCount(payload.total_logs);
          } else if (typeof payload.total === 'number') {
            setTotalLogsCount(payload.total);
          } else if (Array.isArray(payload.logs)) {
            setTotalLogsCount(payload.logs.length);
          }
          if (payload.threats) {
            setThreats(payload.threats);
          }
          if (payload.anomalies) {
            setAnomalies(payload.anomalies);
          }
          if (payload.metrics) {
            setMetrics(payload.metrics);
          }
          if (payload.processes) {
            setProcesses(payload.processes);
          }
          if (payload.blacklist) {
            setBlacklistEntries(payload.blacklist);
          }
          if (payload.rules) {
            setRules(payload.rules);
          }
          if (payload.incidents) {
            setIncidents(payload.incidents);
          }
          setConnectionStatus('Live');
          break;
        case 'log.new':
          appendUniqueLog(payload);
          setLastUpdateTime(new Date().toLocaleTimeString());
          break;
        case 'threat.detected':
          setThreats(prev => [payload, ...prev].slice(0, 200));
          addNotification(`🚨 ${payload.threat_type || 'Threat'} detected`, 'warning');
          break;
        case 'anomaly.detected':
          setAnomalies(prev => [payload, ...prev].slice(0, 200));
          addNotification('🔍 New anomaly detected', 'warning');
          break;
        case 'system.metrics':
          setMetrics(payload);
          break;
        case 'process.snapshot':
          setProcesses(payload.processes || []);
          break;
        case 'process.action':
          fetchProcesses();
          fetchAuditLogs();
          break;
        case 'blacklist.added':
        case 'blacklist.removed':
          fetchBlacklist();
          addNotification('🛡️ Blacklist updated', 'info');
          break;
        case 'blacklist.enforced': {
          fetchBlacklist();
          fetchProcesses();
          fetchAuditLogs();
          const timestamp = payload?.timestamp ? new Date(payload.timestamp) : new Date();
          setLastBlacklistEnforce(timestamp);
          const actionCount = Array.isArray(payload?.results) ? payload.results.length : 0;
          const message = actionCount > 0
            ? `🛡️ Blacklist enforced (${actionCount} actions)`
            : '🛡️ Blacklist enforced';
          addNotification(message, 'success');
          break;
        }
        case 'rule.created':
        case 'rule.updated':
        case 'rule.deleted':
          fetchRules();
          addNotification('🧩 Detection rules updated', 'info');
          break;
        case 'incident.updated':
          fetchIncidents();
          break;
        case 'threat.response':
          fetchIncidents();
          fetchProcesses();
          fetchAuditLogs();
          break;
        case 'monitoring.state':
          setConnectionStatus(payload.active ? 'Live' : 'Idle');
          break;
        case 'monitoring.error':
          addNotification(`⚠️ Monitoring error: ${payload.message}`, 'error');
          break;
        case 'monitoring.heartbeat':
          setConnectionStatus('Live');
          break;
        default:
          break;
      }
    } catch (error) {
      console.error('WebSocket message parsing error', error);
    }
  }, [
    addNotification,
    appendUniqueLog,
    fetchProcesses,
    fetchBlacklist,
    fetchRules,
    fetchIncidents,
    fetchAuditLogs
  ]);

  // Refresh all data
  const refreshData = useCallback(async () => {
    try {
      await Promise.all([
        fetchSystemStatus(),
        fetchLogs(),
        fetchThreats(),
        fetchAnomalies(),
        fetchMetrics(),
        fetchProcesses(),
        fetchBlacklist(),
        fetchRules(),
        fetchIncidents(),
        fetchAuditLogs()
      ]);
      addNotification('🔄 Data refreshed successfully', 'success');
    } catch (error) {
      // Error already handled in individual functions
    }
  }, [
    fetchSystemStatus,
    fetchLogs,
    fetchThreats,
    fetchAnomalies,
    fetchMetrics,
    fetchProcesses,
    fetchBlacklist,
    fetchRules,
    fetchIncidents,
    fetchAuditLogs,
    addNotification
  ]);

  // Enhanced button action handler with detailed feedback
  const handleButtonAction = async (buttonName, actionFunction, successMessage, loadingMessage) => {
    try {
      // Set button to loading state
      setButtonStates(prev => ({ ...prev, [buttonName]: 'loading' }));
      
      // Execute the action
      await actionFunction();
      
      // Set button to success state
      setButtonStates(prev => ({ ...prev, [buttonName]: 'success' }));
      addNotification(successMessage || `✅ ${buttonName} completed`, 'success');
      
      // Reset button state after 2 seconds
      setTimeout(() => {
        setButtonStates(prev => ({ ...prev, [buttonName]: null }));
      }, 2000);
      
    } catch (error) {
      // Set button to error state
      setButtonStates(prev => ({ ...prev, [buttonName]: 'error' }));
      
      // Reset button state after 3 seconds
      setTimeout(() => {
        setButtonStates(prev => ({ ...prev, [buttonName]: null }));
      }, 3000);
      
      // Don't throw - error already handled
    }
  };

  // Control functions with enhanced feedback
  const handleStartMonitoring = async () => {
    await handleButtonAction(
      'startMonitoring',
      async () => {
        await apiService.startMonitoring();
        await fetchSystemStatus();
      },
      '🚀 Log monitoring started successfully',
      'Starting monitoring...'
    );
  };

  const handleStopMonitoring = async () => {
    await handleButtonAction(
      'stopMonitoring',
      async () => {
        await apiService.stopMonitoring();
        await fetchSystemStatus();
      },
      '⏹️ Log monitoring stopped',
      'Stopping monitoring...'
    );
  };

  const handleExportLogs = async () => {
    await handleButtonAction(
      'exportLogs',
      async () => {
        const response = await apiService.exportLogs('xlsx');
        
        // Create download link
        const url = window.URL.createObjectURL(new Blob([response.data]));
        const link = document.createElement('a');
        link.href = url;
        link.setAttribute('download', `logs_export_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.xlsx`);
        document.body.appendChild(link);
        link.click();
        link.remove();
        window.URL.revokeObjectURL(url);
      },
      '📊 Logs exported successfully',
      'Exporting logs...'
    );
  };

  const handleRunThreatAnalysis = async () => {
    await handleButtonAction(
      'threatAnalysis',
      async () => {
        await fetchThreats();
        // Also run analysis on current logs if available
        if (allLogs.length > 0) {
          await apiService.analyzeThreats(allLogs.slice(0, 20)); // Analyze recent logs
        }
        await fetchThreats(); // Refresh threats after analysis
      },
      '🛡️ Threat analysis completed',
      'Analyzing threats...'
    );
  };

  const handleRunMLAnalysis = async () => {
    await handleButtonAction(
      'mlAnalysis',
      async () => {
        await fetchAnomalies();
        // Run comprehensive analysis if available
        if (allLogs.length > 10) {
          await apiService.comprehensiveAnalysis();
        }
        await fetchAnomalies(); // Refresh anomalies after analysis
      },
      '🤖 ML analysis completed',
      'Running ML analysis...'
    );
  };

  const handleComprehensiveAnalysis = async () => {
    await handleButtonAction(
      'comprehensiveAnalysis',
      async () => {
        await apiService.comprehensiveAnalysis();
        await refreshData(); // Refresh all data after comprehensive analysis
      },
      '🔍 Comprehensive analysis completed',
      'Running comprehensive analysis...'
    );
  };

  const handleProcessAction = useCallback(async (pid, action, reason) => {
    try {
      const response = await apiService.processAction(pid, action, reason);
      addNotification(`⚙️ ${action} executed for PID ${pid}`, 'success');
      if (response.data?.result?.status === 'access_denied') {
        addNotification('⚠️ Action denied. Try running the backend with elevated privileges.', 'warning');
      }
      await Promise.all([fetchProcesses(), fetchAuditLogs()]);
    } catch (error) {
      // Errors handled by interceptor
    }
  }, [addNotification, fetchProcesses, fetchAuditLogs]);

  const handleAddBlacklistEntry = useCallback(async (entry) => {
    try {
      await apiService.addBlacklistEntry(entry);
      addNotification('🛡️ Blacklist entry added', 'success');
      await fetchBlacklist();
    } catch (error) {
      // handled upstream
    }
  }, [addNotification, fetchBlacklist]);

  const handleRemoveBlacklistEntry = useCallback(async (identifier) => {
    try {
      await apiService.removeBlacklistEntry(identifier);
      addNotification('🧹 Blacklist entry removed', 'info');
      await fetchBlacklist();
    } catch (error) {
      // handled upstream
    }
  }, [addNotification, fetchBlacklist]);

  const handleEnforceBlacklist = useCallback(async () => {
    if (enforcingBlacklist) {
      return;
    }
    setEnforcingBlacklist(true);
    try {
      const response = await apiService.enforceBlacklist();
      const actionCount = response.data?.count ?? response.data?.results?.length ?? 0;
      const notification = actionCount > 0
        ? `🛡️ Manual enforcement executed (${actionCount} actions)`
        : '🛡️ Manual enforcement executed';
      addNotification(notification, 'success');
      const timestamp = response.data?.timestamp ? new Date(response.data.timestamp) : new Date();
      setLastBlacklistEnforce(timestamp);
      await Promise.all([fetchBlacklist(), fetchProcesses(), fetchAuditLogs()]);
    } catch (error) {
      // handled by interceptor and notifications
    } finally {
      setEnforcingBlacklist(false);
    }
  }, [addNotification, enforcingBlacklist, fetchBlacklist, fetchProcesses, fetchAuditLogs]);

  const handleCreateRule = useCallback(async (rule) => {
    try {
      await apiService.createRule(rule);
      addNotification('🧠 Detection rule created', 'success');
      await fetchRules();
    } catch (error) {
      // handled upstream
    }
  }, [addNotification, fetchRules]);

  const handleUpdateRule = useCallback(async (ruleId, updates) => {
    try {
      await apiService.updateRule(ruleId, updates);
      addNotification('🔧 Rule updated', 'success');
      await fetchRules();
    } catch (error) {
      // handled upstream
    }
  }, [addNotification, fetchRules]);

  const handleDeleteRule = useCallback(async (ruleId) => {
    try {
      await apiService.deleteRule(ruleId);
      addNotification('🗑️ Rule removed', 'info');
      await fetchRules();
    } catch (error) {
      // handled upstream
    }
  }, [addNotification, fetchRules]);

  const handleIncidentUpdate = useCallback(async (incidentId, updates) => {
    try {
      await apiService.updateIncident(incidentId, updates);
      addNotification('📌 Incident updated', 'success');
      await fetchIncidents();
    } catch (error) {
      // handled upstream
    }
  }, [addNotification, fetchIncidents]);

  // Effects
  useEffect(() => {
    // Initial data load
    refreshData();
  }, [refreshData]);

  useEffect(() => {
    const ws = apiService.connectWebSocket();
    wsRef.current = ws;
    ws.onopen = () => {
      setWsConnected(true);
      setConnectionStatus('Live');
      addNotification('🛰️ Live data stream connected', 'success');
    };
    ws.onmessage = handleWebSocketMessage;
    ws.onclose = () => {
      setWsConnected(false);
      setConnectionStatus('Disconnected');
      addNotification('⚠️ Live data stream disconnected', 'warning');
    };
    ws.onerror = (error) => {
      console.error('WebSocket error', error);
      addNotification('⚠️ Live data stream error', 'error');
    };
    return () => {
      ws.close();
      wsRef.current = null;
    };
  }, [addNotification, handleWebSocketMessage]);

  useEffect(() => {
    // Update display logs when allLogs or expansion state changes
    updateDisplayLogs();
  }, [updateDisplayLogs]);

  useEffect(() => {
    // Update stats whenever data changes
    updateStats();
  }, [updateStats]);

  useEffect(() => {
    // Set up periodic refresh
    const refreshInterval = setInterval(() => {
      fetchLogs();
      fetchThreats();
      fetchProcesses();
      fetchMetrics();
      fetchBlacklist();
    }, 5000);

    const governanceInterval = setInterval(() => {
      fetchRules();
      fetchIncidents();
      fetchAuditLogs();
    }, 15000);

    // Set up stats update interval
    const statsInterval = setInterval(updateStats, 1000);

    return () => {
      clearInterval(refreshInterval);
      clearInterval(governanceInterval);
      clearInterval(statsInterval);
    };
  }, [fetchLogs, fetchThreats, fetchProcesses, fetchMetrics, fetchBlacklist, fetchRules, fetchIncidents, fetchAuditLogs, updateStats]);

  return (
    <div className="App">
      {/* Notifications */}
      <div className="notifications">
        {notifications.map(notification => (
          <div 
            key={notification.id} 
            className={`notification notification-${notification.type}`}
            onClick={() => setNotifications(prev => prev.filter(n => n.id !== notification.id))}
          >
            <span>{notification.message}</span>
            <button className="notification-close">×</button>
          </div>
        ))}
      </div>

      <Header 
        systemStatus={systemStatus} 
        connectionStatus={connectionStatus} 
        wsConnected={wsConnected}
      />
      
      <div className="container">
        {/* System Statistics */}
        <SystemStats 
          stats={stats} 
          activityData={activityData} 
        />

        <SystemMetrics 
          metrics={metrics} 
          wsConnected={wsConnected} 
        />
        
        {/* Monitoring Controls */}
        <MonitoringControls
          onStartMonitoring={handleStartMonitoring}
          onStopMonitoring={handleStopMonitoring}
          onExportLogs={handleExportLogs}
          onRunThreatAnalysis={handleRunThreatAnalysis}
          onRunMLAnalysis={handleRunMLAnalysis}
          onRefreshData={refreshData}
          onComprehensiveAnalysis={handleComprehensiveAnalysis}
          buttonStates={buttonStates}
        />
        
        {/* Threat Alerts */}
        <ThreatAlerts threats={threats} />
        
        {/* ML Anomalies */}
        <MLAnomalies anomalies={anomalies} />

        <ProcessManager 
          processes={processes} 
          onAction={handleProcessAction} 
        />
        <BlacklistManager 
          entries={blacklistEntries} 
          onAdd={handleAddBlacklistEntry} 
          onRemove={handleRemoveBlacklistEntry} 
          onEnforce={handleEnforceBlacklist}
          enforcing={enforcingBlacklist}
          lastEnforced={lastBlacklistEnforce}
        />

        <RuleEditor 
          rules={rules} 
          onCreate={handleCreateRule} 
          onUpdate={handleUpdateRule} 
          onDelete={handleDeleteRule} 
        />
        <IncidentCenter 
          incidents={incidents} 
          onUpdate={handleIncidentUpdate} 
        />

        <AuditLog entries={auditLogs} />
        
        {/* Live Log Stream */}
        <LogStream 
          logs={displayLogs}
          allLogsCount={totalLogsCount}
          isExpanded={logViewExpanded}
          onToggleExpansion={toggleLogView}
          lastUpdateTime={lastUpdateTime}
          connectionStatus={connectionStatus}
        />
      </div>
    </div>
  );
}

export default App;