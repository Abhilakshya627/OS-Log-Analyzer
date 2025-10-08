import axios from 'axios';

// Create axios instance with base configuration
const api = axios.create({
  baseURL: process.env.NODE_ENV === 'production' ? '/api' : 'http://localhost:5000/api',
  timeout: 30000, // Increased timeout for longer operations
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor with better logging
api.interceptors.request.use(
  (config) => {
    const timestamp = new Date().toLocaleTimeString();
    console.log(`[${timestamp}] API Request: ${config.method?.toUpperCase()} ${config.url}`);
    return config;
  },
  (error) => {
    console.error('Request interceptor error:', error);
    return Promise.reject(error);
  }
);

// Enhanced response interceptor with detailed error handling
api.interceptors.response.use(
  (response) => {
    const timestamp = new Date().toLocaleTimeString();
    console.log(`[${timestamp}] API Response: ${response.status} ${response.config.url}`);
    return response;
  },
  (error) => {
    const timestamp = new Date().toLocaleTimeString();
    
    if (error.response) {
      // Server responded with error status
      const status = error.response.status;
      const data = error.response.data;
      const url = error.config?.url || 'unknown';
      
      console.error(`[${timestamp}] API Error ${status} for ${url}:`, data);
      
      // Enhance error message based on status code
      let enhancedError = error;
      switch (status) {
        case 400:
          enhancedError.userMessage = data?.error || 'Invalid request. Please check your input.';
          break;
        case 404:
          enhancedError.userMessage = 'Service endpoint not found. The server may be outdated.';
          break;
        case 500:
          enhancedError.userMessage = data?.error || 'Server internal error. Please try again or check server logs.';
          break;
        case 503:
          enhancedError.userMessage = 'Service temporarily unavailable. Please try again in a moment.';
          break;
        default:
          enhancedError.userMessage = data?.error || `Server error (${status}). Please try again.`;
      }
      
      return Promise.reject(enhancedError);
    } else if (error.request) {
      // Request was made but no response received
      console.error(`[${timestamp}] Network Error: No response received`);
      error.userMessage = 'Unable to connect to server. Please check if the backend is running on port 5000.';
      return Promise.reject(error);
    } else {
      // Something else happened
      console.error(`[${timestamp}] Request Error:`, error.message);
      error.userMessage = error.message || 'An unexpected error occurred.';
      return Promise.reject(error);
    }
  }
);

// Helper function to handle API calls with consistent error handling
const handleApiCall = async (apiCall, operation = 'operation') => {
  try {
    const response = await apiCall();
    return response;
  } catch (error) {
    // Log the full error for debugging
    console.error(`Failed to ${operation}:`, error);
    
    // Re-throw with enhanced error information
    const enhancedError = new Error(error.userMessage || `Failed to ${operation}`);
    enhancedError.originalError = error;
    enhancedError.status = error.response?.status;
    enhancedError.data = error.response?.data;
    throw enhancedError;
  }
};

// Enhanced API service functions with better error handling and validation
export const apiService = {
  // System endpoints
  getSystemStatus: () => handleApiCall(
    () => api.get('/system/status'),
    'fetch system status'
  ),
  
  getHealth: () => handleApiCall(
    () => api.get('/health'),
    'check system health'
  ),

  // Log endpoints with validation
  getLiveLogs: (limit = 100) => {
    // Validate limit parameter
    const validLimit = Math.max(1, Math.min(limit, 1000)); // Between 1 and 1000
    return handleApiCall(
      () => api.get(`/logs/live?limit=${validLimit}`),
      'fetch live logs'
    );
  },
  
  getRecentLogs: (limit = 50) => {
    const validLimit = Math.max(1, Math.min(limit, 500));
    return handleApiCall(
      () => api.get(`/logs/recent/${validLimit}`),
      'fetch recent logs'
    );
  },

  // Threat endpoints
  getActiveThreats: () => handleApiCall(
    () => api.get('/threats/active'),
    'fetch active threats'
  ),
  
  analyzeThreats: (logs) => {
    if (!logs || !Array.isArray(logs)) {
      throw new Error('Invalid logs data provided for threat analysis');
    }
    return handleApiCall(
      () => api.post('/threats/analyze', { logs }),
      'analyze threats'
    );
  },

  // ML endpoints
  getMLAnomalies: () => handleApiCall(
    () => api.get('/ml/anomalies'),
    'fetch ML anomalies'
  ),

  // Monitoring endpoints
  startMonitoring: () => handleApiCall(
    () => api.post('/monitoring/start'),
    'start monitoring'
  ),
  
  stopMonitoring: () => handleApiCall(
    () => api.post('/monitoring/stop'),
    'stop monitoring'
  ),

  // Export endpoints with format validation
  exportLogs: (format) => {
    const validFormats = ['json', 'csv', 'xlsx'];
    if (!validFormats.includes(format)) {
      throw new Error(`Invalid export format: ${format}. Valid formats: ${validFormats.join(', ')}`);
    }
    return handleApiCall(
      () => api.get(`/export/logs/${format}`, { 
        responseType: 'blob',
        timeout: 60000 // Extended timeout for export operations
      }),
      `export logs as ${format}`
    );
  },

  // Analysis endpoints
  comprehensiveAnalysis: (logs = null) => handleApiCall(
    () => api.post('/analysis/comprehensive', logs ? { logs } : {}, {
      timeout: 120000 // Extended timeout for comprehensive analysis
    }),
    'run comprehensive analysis'
  ),
  
  quickAnalysis: (duration = 30) => {
    const validDuration = Math.max(10, Math.min(duration, 300)); // Between 10s and 5 minutes
    return handleApiCall(
      () => api.post('/analysis/quick', { duration: validDuration }, {
        timeout: (validDuration + 30) * 1000 // Timeout slightly longer than analysis duration
      }),
      'run quick analysis'
    );
  },

  // Utility functions for better UX
  checkConnection: async () => {
    try {
      const response = await api.get('/health', { timeout: 5000 });
      return {
        connected: true,
        status: response.data,
        message: 'Successfully connected to server'
      };
    } catch (error) {
      return {
        connected: false,
        error: error.userMessage || 'Failed to connect to server',
        message: 'Please ensure the backend server is running on port 5000'
      };
    }
  },

  // Batch operations for efficiency
  fetchAllData: async () => {
    try {
      const [systemStatus, logs, threats, anomalies] = await Promise.allSettled([
        apiService.getSystemStatus(),
        apiService.getLiveLogs(100),
        apiService.getActiveThreats(),
        apiService.getMLAnomalies()
      ]);

      return {
        systemStatus: systemStatus.status === 'fulfilled' ? systemStatus.value.data : null,
        logs: logs.status === 'fulfilled' ? logs.value.data : null,
        threats: threats.status === 'fulfilled' ? threats.value.data : null,
        anomalies: anomalies.status === 'fulfilled' ? anomalies.value.data : null,
        errors: [
          systemStatus.status === 'rejected' ? systemStatus.reason : null,
          logs.status === 'rejected' ? logs.reason : null,
          threats.status === 'rejected' ? threats.reason : null,
          anomalies.status === 'rejected' ? anomalies.reason : null,
        ].filter(Boolean)
      };
    } catch (error) {
      throw new Error('Failed to fetch all data');
    }
  }
};

// Export default for backward compatibility
export default api;