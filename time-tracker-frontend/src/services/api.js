import axios from 'axios';

const baseURL = import.meta.env.VITE_API_URL || 'https://time-tracker-4g19.onrender.com';

const API = axios.create({ baseURL });

API.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

export default API;
