import axios from 'axios';

const API = axios.create({
  baseURL: 'https://sadakk.netlify.app/', // Backend base URL
});

// Add a request interceptor to include the token in headers
API.interceptors.request.use((config) => {
  const token = localStorage.getItem('token'); // Get the token from localStorage
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export default API;
