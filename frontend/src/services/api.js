import axios from 'axios';

// Create axios instance with base configuration
const api = axios.create({
  baseURL: process.env.NODE_ENV === 'production' ? '/api' : 'http://localhost:5000/api',
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor
api.interceptors.request.use(
  (config) => {
    console.log(`Making ${config.method?.toUpperCase()} request to ${config.url}`);
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor
api.interceptors.response.use(
  (response) => {
    return response;
  },
  (error) => {
    console.error('API Error:', error.response?.data || error.message);
    return Promise.reject(error);
  }
);

// API service functions
export const apiService = {
  // System endpoints
  getSystemStatus: () => api.get('/system/status'),
  getHealth: () => api.get('/health'),

  // Log endpoints
  getLiveLogs: (limit = 100) => api.get(`/logs/live?limit=${limit}`),
  getRecentLogs: (limit = 50) => api.get(`/logs/recent/${limit}`),

  // Threat endpoints
  getActiveThreats: () => api.get('/threats/active'),
  analyzeThreats: (logs) => api.post('/threats/analyze', { logs }),

  // ML endpoints
  getMLAnomalies: () => api.get('/ml/anomalies'),

  // Monitoring endpoints
  startMonitoring: () => api.post('/monitoring/start'),
  stopMonitoring: () => api.post('/monitoring/stop'),

  // Export endpoints
  exportLogs: (format) => api.get(`/export/logs/${format}`, { responseType: 'blob' }),

  // Analysis endpoints
  comprehensiveAnalysis: (logs = null) => api.post('/analysis/comprehensive', logs ? { logs } : {}),
};

export default api;