
import axios from 'axios';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000',
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const checkBackendHealth = async () => {
  const response = await api.get('/health');
  return response.data;
};

export const getScanHistory = async () => {
  const response = await api.get('/scan/history');
  return response.data.history;
};

export default api;
