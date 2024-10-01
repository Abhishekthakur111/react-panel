import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom'; 
import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import 'animate.css';
import axios from 'axios';

const Login = () => {
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const handleChangeEmail = (e) => {
    setEmail(e.target.value);
  };

  const handleChangePassword = (e) => {
    setPassword(e.target.value);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post('http://localhost:8000/login', { email, password });
      console.log(response);
      if (response.data.success) {
        localStorage.setItem('token', response.data.body.token);
        toast.success("Admin logged in successfully");
        navigate('/dashboard', { state: { message: 'Admin logged in successfully' } });
      } else {
        toast.error(response.data.message || "Login failed");
      }
    } catch (error) {
      toast.error('An error occurred while logging in. Please try again');
    }
  };

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
      <div className="bg-gray-200">
        <main className="main-content mt-0">
          <div className="page-header align-items-start min-vh-100" style={{ backgroundImage: "url('https://images.unsplash.com/photo-1497294815431-9365093b7331?ixlib=rb-1.2.1&ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=1950&q=80')" }}>
            <span className="mask bg-gradient-dark opacity-6"></span>
            <div className="container my-auto">
              <div className="row">
                <div className="col-lg-4 col-md-8 col-12 mx-auto">
                  <div className="card z-index-0 fadeIn3 fadeInBottom">
                    <div className="card-header p-0 position-relative mt-n4 mx-3 z-index-2">
                      <div className="bg-gradient-primary shadow-primary border-radius-lg py-3 pe-1">
                        <h4 className="text-white font-weight-bolder text-center mt-2 mb-0">Sign in</h4>
                        <div className="row mt-3">
                          <div className="col-2 text-center ms-auto">
                            <Link className="btn btn-link px-3" to="">
                              <i className="fa fa-facebook text-white text-lg"></i>
                            </Link>
                          </div>
                          <div className="col-2 text-center px-1">
                            <Link className="btn btn-link px-3" to="">
                              <i className="fa fa-github text-white text-lg"></i>
                            </Link>
                          </div>
                          <div className="col-2 text-center me-auto">
                            <Link className="btn btn-link px-3" to="">
                              <i className="fa fa-google text-white text-lg"></i>
                            </Link>
                          </div>
                        </div>
                      </div>
                    </div>
                    <div className="card-body">
                      <form onSubmit={handleSubmit} className="text-start">
                        <div className="input-group input-group-outline my-3">
                          <label className="form-label">Email</label>
                          <input
                            type="email"
                            className="form-control"
                            value={email}
                            onChange={handleChangeEmail}
                            required
                          />
                        </div>
                        <div className="input-group input-group-outline mb-3">
                          <label className="form-label">Password</label>
                          <input
                            type="password"
                            className="form-control"
                            value={password}
                            onChange={handleChangePassword}
                            required
                          />
                        </div>
                        <div className="form-check form-switch d-flex align-items-center mb-3">
                          <input className="form-check-input" type="checkbox" id="rememberMe" />
                          <label className="form-check-label mb-0 ms-3" htmlFor="rememberMe">Remember me</label>
                        </div>
                        <div className="text-center">
                          <button type="submit" className="btn bg-gradient-primary w-100 my-4 mb-2">Sign in</button>
                        </div>
                      </form>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </main>
      </div>
    </>
  );
};

export default Login;
