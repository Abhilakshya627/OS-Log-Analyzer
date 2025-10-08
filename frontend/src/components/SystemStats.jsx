import React from 'react';
import { Line } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
} from 'chart.js';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend
);

const SystemStats = ({ stats, activityData }) => {
  const formatUptime = (seconds) => {
    const minutes = Math.floor(seconds / 60);
    const secs = Math.floor(seconds % 60);
    return `${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  };

  const chartData = {
    labels: activityData.map(d => d.time),
    datasets: [
      {
        label: 'Logs',
        data: activityData.map(d => d.logs),
        borderColor: '#3498db',
        backgroundColor: 'rgba(52, 152, 219, 0.1)',
        tension: 0.4,
      },
      {
        label: 'Threats',
        data: activityData.map(d => d.threats),
        borderColor: '#e74c3c',
        backgroundColor: 'rgba(231, 76, 60, 0.1)',
        tension: 0.4,
      },
    ],
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    scales: {
      y: {
        beginAtZero: true,
      },
    },
    plugins: {
      legend: {
        position: 'top',
      },
    },
  };

  return (
    <div className="card">
      <h2>📊 System Statistics</h2>
      <div className="stats-grid">
        <div className="stat-item">
          <span className="stat-number">{stats.totalLogs || 0}</span>
          <span className="stat-label">Total Logs</span>
        </div>
        <div className="stat-item">
          <span className="stat-number">{stats.threatsDetected || 0}</span>
          <span className="stat-label">Threats</span>
        </div>
        <div className="stat-item">
          <span className="stat-number">{stats.anomaliesFound || 0}</span>
          <span className="stat-label">Anomalies</span>
        </div>
        <div className="stat-item">
          <span className="stat-number">{formatUptime(stats.uptime || 0)}</span>
          <span className="stat-label">Uptime</span>
        </div>
      </div>
      
      <div className="chart-container">
        <Line data={chartData} options={chartOptions} />
      </div>
    </div>
  );
};

export default SystemStats;