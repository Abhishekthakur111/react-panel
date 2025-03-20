import React from 'react';
import axios from 'axios'; 

export const BASE_URL = "http://localhost:8000/user";

const axiosInstance = axios.create({
  baseURL: BASE_URL,
  timeout: 1000,
});

axiosInstance.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers['Authorization'] = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

axiosInstance.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response) {
      const { status } = error.response;

      if (status === 400) {
        localStorage.removeItem('token');
        window.location.replace('/');
      }
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
