import axios from 'axios';

// Use environment variable, fallback to Render URL or localhost
const apiUrl = import.meta.env.VITE_API_URL || 'https://time-tracker-4g19.onrender.com';

const API = axios.create({
  baseURL: apiUrl,
});

API.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export default API;