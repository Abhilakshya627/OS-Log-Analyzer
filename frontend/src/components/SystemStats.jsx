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

  // Calculate dynamic scales based on actual data
  const calculateDynamicScale = () => {
    if (!activityData || activityData.length === 0) {
      return { min: 0, max: 10 };
    }

    const logValues = activityData.map(d => d.logs || 0);
    const threatValues = activityData.map(d => d.threats || 0);
    const allValues = [...logValues, ...threatValues];
    
    const maxValue = Math.max(...allValues);
    const minValue = Math.min(...allValues);
    
    // Add some padding to the scale
    const padding = Math.max(1, Math.ceil((maxValue - minValue) * 0.1));
    
    return {
      min: Math.max(0, minValue - padding),
      max: Math.max(10, maxValue + padding) // Ensure minimum scale of 10
    };
  };

  const scaleInfo = calculateDynamicScale();

  const chartData = {
    labels: activityData.map(d => d.time),
    datasets: [
      {
        label: 'Logs',
        data: activityData.map(d => d.logs),
        borderColor: '#3498db',
        backgroundColor: 'rgba(52, 152, 219, 0.1)',
        tension: 0.4,
        fill: false,
        pointRadius: 3,
        pointHoverRadius: 5,
      },
      {
        label: 'Threats',
        data: activityData.map(d => d.threats),
        borderColor: '#e74c3c',
        backgroundColor: 'rgba(231, 76, 60, 0.1)',
        tension: 0.4,
        fill: false,
        pointRadius: 3,
        pointHoverRadius: 5,
      },
    ],
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    interaction: {
      intersect: false,
      mode: 'index',
    },
    scales: {
      x: {
        display: true,
        title: {
          display: true,
          text: 'Time'
        },
        ticks: {
          maxRotation: 45,
          minRotation: 0,
        }
      },
      y: {
        display: true,
        title: {
          display: true,
          text: 'Count'
        },
        min: scaleInfo.min,
        max: scaleInfo.max,
        ticks: {
          stepSize: Math.max(1, Math.ceil((scaleInfo.max - scaleInfo.min) / 10)),
        }
      },
    },
    plugins: {
      legend: {
        position: 'top',
        labels: {
          usePointStyle: true,
          padding: 20,
        }
      },
      tooltip: {
        backgroundColor: 'rgba(0, 0, 0, 0.8)',
        titleColor: 'white',
        bodyColor: 'white'
      }
    },
    animation: {
      duration: 750,
      easing: 'easeInOutQuart',
    }
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