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
  const [logs, setLogs] = useState([]);
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

  // Update stats based on current data
  const updateStats = useCallback(() => {
    const currentTime = new Date();
    const uptime = Math.floor((currentTime - startTime) / 1000);
    
    setStats(prevStats => ({
      ...prevStats,
      totalLogs: logs.length,
      threatsDetected: threats.length,
      anomaliesFound: anomalies.length,
      uptime: uptime
    }));

    // Update activity chart data
    const timeLabel = currentTime.toLocaleTimeString();
    setActivityData(prevData => {
      const newData = [...prevData, {
        time: timeLabel,
        logs: logs.length,
        threats: threats.length
      }];
      
      // Keep only last 20 data points
      return newData.slice(-20);
    });
  }, [logs.length, threats.length, anomalies.length, startTime]);

  // Fetch system status
  const fetchSystemStatus = useCallback(async () => {
    try {
      const response = await apiService.getSystemStatus();
      setSystemStatus(response.data);
      setConnectionStatus('Connected');
    } catch (error) {
      console.error('Failed to fetch system status:', error);
      setConnectionStatus('Disconnected');
    }
  }, []);

  // Fetch live logs
  const fetchLogs = useCallback(async () => {
    try {
      const response = await apiService.getLiveLogs(50);
      if (response.data.logs) {
        setLogs(response.data.logs);
      }
      setConnectionStatus('Connected');
    } catch (error) {
      console.error('Failed to fetch logs:', error);
      setConnectionStatus('Disconnected');
    }
  }, []);

  // Fetch active threats
  const fetchThreats = useCallback(async () => {
    try {
      const response = await apiService.getActiveThreats();
      if (response.data.threats) {
        setThreats(response.data.threats);
      }
    } catch (error) {
      console.error('Failed to fetch threats:', error);
    }
  }, []);

  // Fetch ML anomalies
  const fetchAnomalies = useCallback(async () => {
    try {
      const response = await apiService.getMLAnomalies();
      if (response.data.anomalies) {
        setAnomalies(response.data.anomalies);
      }
    } catch (error) {
      console.error('Failed to fetch anomalies:', error);
    }
  }, []);

  // Refresh all data
  const refreshData = useCallback(async () => {
    await Promise.all([
      fetchSystemStatus(),
      fetchLogs(),
      fetchThreats(),
      fetchAnomalies()
    ]);
  }, [fetchSystemStatus, fetchLogs, fetchThreats, fetchAnomalies]);

  // Control functions
  const handleStartMonitoring = async () => {
    try {
      await apiService.startMonitoring();
      console.log('Monitoring started');
      await fetchSystemStatus();
    } catch (error) {
      console.error('Failed to start monitoring:', error);
    }
  };

  const handleStopMonitoring = async () => {
    try {
      await apiService.stopMonitoring();
      console.log('Monitoring stopped');
      await fetchSystemStatus();
    } catch (error) {
      console.error('Failed to stop monitoring:', error);
    }
  };

  const handleExportLogs = async () => {
    try {
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
    } catch (error) {
      console.error('Failed to export logs:', error);
    }
  };

  const handleRunThreatAnalysis = async () => {
    await fetchThreats();
  };

  const handleRunMLAnalysis = async () => {
    await fetchAnomalies();
  };

  // Effects
  useEffect(() => {
    // Initial data load
    refreshData();
  }, [refreshData]);

  useEffect(() => {
    // Update stats whenever data changes
    updateStats();
  }, [updateStats]);

  useEffect(() => {
    // Set up periodic refresh
    const refreshInterval = setInterval(() => {
      fetchLogs();
      fetchThreats();
    }, 5000); // Refresh every 5 seconds

    // Set up stats update interval
    const statsInterval = setInterval(updateStats, 1000); // Update stats every second

    return () => {
      clearInterval(refreshInterval);
      clearInterval(statsInterval);
    };
  }, [fetchLogs, fetchThreats, updateStats]);

  return (
    <div className="App">
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
        />
        
        {/* Threat Alerts */}
        <ThreatAlerts threats={threats} />
        
        {/* ML Anomalies */}
        <MLAnomalies anomalies={anomalies} />
        
        {/* Live Log Stream */}
        <LogStream logs={logs} />
      </div>
    </div>
  );
}

export default App;