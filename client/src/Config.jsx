import React from 'react';
import axios from 'axios'; 

export const BASE_URL = "http://localhost:8000/user";
const token = localStorage.getItem('token');
const axiosInstance = axios.create({
  baseURL: BASE_URL,
  timeout: 1000,
  headers: {
    'Authorization': token ? `Bearer ${token}` : '',
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
