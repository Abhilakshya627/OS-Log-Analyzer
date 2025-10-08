import React, { useState, useEffect, useCallback } from 'react';
import Header from './components/Header';
import SystemStats from './components/SystemStats';
import MonitoringControls from './components/MonitoringControls';
import ThreatAlerts from './components/ThreatAlerts';
import MLAnomalies from './components/MLAnomalies';
import LogStream from './components/LogStream';
import { apiService } from './services/api';

function App() {
  // State management
  const [systemStatus, setSystemStatus] = useState(null);
  const [connectionStatus, setConnectionStatus] = useState('Connecting...');
  const [allLogs, setAllLogs] = useState([]);
  const [displayLogs, setDisplayLogs] = useState([]);
  const [logViewExpanded, setLogViewExpanded] = useState(false);
  const [logsPerPage] = useState(10);
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

  // Add notification helper
  const addNotification = useCallback((message, type = 'info') => {
    const id = Date.now();
    const notification = { id, message, type, timestamp: new Date() };
    setNotifications(prev => [...prev, notification]);
    
    // Auto-remove notification after 5 seconds
    setTimeout(() => {
      setNotifications(prev => prev.filter(n => n.id !== id));
    }, 5000);
  }, []);

  // Update stats based on current data
  const updateStats = useCallback(() => {
    const currentTime = new Date();
    const uptime = Math.floor((currentTime - startTime) / 1000);
    
    setStats(prevStats => ({
      ...prevStats,
      totalLogs: allLogs.length,
      threatsDetected: threats.length,
      anomaliesFound: anomalies.length,
      uptime: uptime
    }));

    // Update activity chart data
    const timeLabel = currentTime.toLocaleTimeString();
    setActivityData(prevData => {
      const newData = [...prevData, {
        time: timeLabel,
        logs: allLogs.length,
        threats: threats.length,
        timestamp: currentTime
      }];
      return newData.slice(-30); // Keep last 30 data points
    });
  }, [allLogs.length, threats.length, anomalies.length, startTime]);

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
      if (response.data.logs) {
        const newLogs = response.data.logs;
        
        setAllLogs(prevAllLogs => {
          // Create a map to avoid duplicates
          const existingLogMap = new Map();
          prevAllLogs.forEach(log => {
            existingLogMap.set(log.id || log.timestamp, log);
          });
          
          // Add new unique logs
          const uniqueNewLogs = newLogs.filter(log => {
            const logId = log.id || log.timestamp;
            return !existingLogMap.has(logId);
          });
          
          if (uniqueNewLogs.length > 0) {
            addNotification(`📊 Added ${uniqueNewLogs.length} new log entries`, 'success');
          }
          
          // Combine and sort
          const combinedLogs = [...prevAllLogs, ...uniqueNewLogs];
          return combinedLogs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)).slice(0, 1000);
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

  // Refresh all data
  const refreshData = useCallback(async () => {
    try {
      await Promise.all([
        fetchSystemStatus(),
        fetchLogs(),
        fetchThreats(),
        fetchAnomalies()
      ]);
      addNotification('🔄 Data refreshed successfully', 'success');
    } catch (error) {
      // Error already handled in individual functions
    }
  }, [fetchSystemStatus, fetchLogs, fetchThreats, fetchAnomalies, addNotification]);

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

  // Effects
  useEffect(() => {
    // Initial data load
    refreshData();
  }, [refreshData]);

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
    }, 5000);

    // Set up stats update interval
    const statsInterval = setInterval(updateStats, 1000);

    return () => {
      clearInterval(refreshInterval);
      clearInterval(statsInterval);
    };
  }, [fetchLogs, fetchThreats, updateStats]);

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
      />
      
      <div className="container">
        {/* System Statistics */}
        <SystemStats 
          stats={stats} 
          activityData={activityData} 
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
        
        {/* Live Log Stream */}
        <LogStream 
          logs={displayLogs}
          allLogsCount={allLogs.length}
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