import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import axios from 'axios';
import { ToastContainer, toast } from 'react-toastify';
import ApexChart from './ApexChart';

const Dashboard = () => {
  const [users, setUsers] = useState(0);
  const [categories, setCategories] = useState(0);
  const [subCategories, setSubCategories] = useState(0);
  const [bookings, setBookings] = useState(0);
  
  const navigate = useNavigate();

  const fetchDashboardData = async () => {
    try {
      const token = localStorage.getItem('token');
      if (!token) {
        toast.error('Authentication token missing');
        navigate('/login'); 
        return;
      }

      const response = await axios.get('http://localhost:8000/dashboard', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.data.success) {
        setUsers(response.data.body.userCount);
        setCategories(response.data.body.data); 
        setSubCategories(response.data.body.subdata); 
        setBookings(response.data.body.databooking); 
      } else {
        toast.error('Failed to fetch dashboard data');
      }
    } catch (error) {
      toast.error('An error occurred while fetching the dashboard data');
    }
  };

  useEffect(() => {
    fetchDashboardData();
  }, []);

  return (
    <>
      <ToastContainer
        position="top-right"
        autoClose={5000}
        hideProgressBar={false}
        newestOnTop={false}
        closeOnClick
        rtl={false}
        pauseOnFocusLoss
        draggable
        pauseOnHover
      />
      <div className='container-fluid py-4'>
        <div className="row">
          <div className="col-xl-3 col-sm-6 mb-xl-0 mb-4">
            <Link to="/userlist" >
              <div className="card">
                <div className="card-header p-3 pt-2">
                  <div className="icon icon-lg icon-shape bg-gradient-primary shadow-primary text-center border-radius-xl mt-n4 position-absolute">
                    <i className="material-icons opacity-10">person</i>
                  </div>
                  <div className="text-end ">
                    <h4> Users</h4>
                    <h4  >{users}</h4>
                  </div>
                </div>
              </div>
            </Link>
          </div>
          <div className="col-xl-3 col-sm-6 mb-xl-0 mb-4">
            <Link to="/categorylist"> 
              <div className="card">
                <div className="card-header p-3 pt-2">
                  <div className="icon icon-lg icon-shape bg-gradient-dark shadow-dark text-center border-radius-xl mt-n4 position-absolute">
                    <i className="material-icons opacity-10">weekend</i>
                  </div>
                  <div className="text-end ">
                    <h4>Categories</h4>
                    <h4 className="mb-0">{categories}</h4>
                  </div>
                </div>
              </div>
            </Link>
          </div>
          <div className="col-xl-3 col-sm-6 mb-xl-0 mb-4">
            <Link to="/services">
              <div className="card">
                <div className="card-header p-3 pt-2">
                  <div className="icon icon-lg icon-shape bg-gradient-success shadow-success text-center border-radius-xl mt-n4 position-absolute">
                    <i className="material-icons opacity-10">list</i>
                  </div>
                  <div className="text-end pt-1">
                    <h4>Sub Categories</h4>
                    <h4 className="mb-0">{subCategories}</h4>
                  </div>
                </div>
              </div>
            </Link>
          </div>
          <div className="col-xl-3 col-sm-6">
            <Link to="/bookinglist">
              <div className="card">
                <div className="card-header p-3 pt-2">
                  <div className="icon icon-lg icon-shape bg-gradient-info shadow-info text-center border-radius-xl mt-n4 position-absolute">
                    <i className="material-icons opacity-10">calendar_today</i>
                  </div>
                  <div className="text-end pt-1">
                    <h4>Bookings</h4>
                    <h4 className="mb-0">{bookings}</h4>
                  </div>
                </div>
              </div>
            </Link>
          </div>
        </div>
      </div>
      <div className='container-fluid'>
        <ApexChart/>
      </div>
    </>
  );
};

export default Dashboard;
