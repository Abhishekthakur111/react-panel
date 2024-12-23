import React from 'react';
import axios from 'axios'; 

export const BASE_URL = "http://localhost:8000";
const token = localStorage.getItem('token');
const axiosInstance = axios.create({
  baseURL: BASE_URL,
  headers: {
    'Authorization': token ? `Bearer ${token}` : '',
  },
});

const Config = () => {
  return (
    <>
      <p>Base URL: {BASE_URL}</p>
    </>
  );
};
export { Config, axiosInstance };
