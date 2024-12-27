import React from 'react';
import axios from 'axios'; 
import {jwtDecode} from 'jwt-decode'; 

export const BASE_URL = "http://localhost:8000/user";
const token = localStorage.getItem('token');

const isTokenExpired = (token) => {
  try {
    const decoded = jwtDecode(token);
    return decoded.exp * 1000 < Date.now(); 
  } catch (error) {
    return true; 
  }
};
if (token && isTokenExpired(token)) {
  localStorage.removeItem('token');
  window.location.href = '/'; 
}

const axiosInstance = axios.create({
  baseURL: BASE_URL,
  timeout: 1000,
  headers: {
    'Authorization': token && !isTokenExpired(token) ? `Bearer ${token}` : '',
  },
});

axiosInstance.interceptors.response.use(
  (response) => response, 
  (error) => {
    if (error.response && error.response.status === 403 && error.response.data.message === 'Token expired') {
      localStorage.removeItem('token'); 
      window.location.href = '/';
    }
    return Promise.reject(error); 
  }
);

const Config = () => {
  return (
    <>
      <p>Base URL: {BASE_URL}</p>
    </>
  );
};

export { Config, axiosInstance };
