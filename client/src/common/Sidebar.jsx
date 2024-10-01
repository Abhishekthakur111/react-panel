import React from 'react';
import { NavLink } from 'react-router-dom';

const Sidebar = () => {
  return (
    <div>
      <aside className="sidenav navbar navbar-vertical navbar-expand-xs border-0 border-radius-xl my-3 fixed-start ms-3 bg-gradient-dark" id="sidenav-main">
        <div className="sidenav-header">
          <i className="fas fa-times p-3 cursor-pointer text-white opacity-5 position-absolute end-0 top-0 d-none d-xl-none" aria-hidden="true" id="iconSidenav"></i>
          <NavLink className="navbar-brand m-0" to="/dashboard">
            <img src="../assets/img/logo-ct.png" className="navbar-brand-img h-100" alt="main_logo" />
            <span className="ms-1 font-weight-bold text-white">Dashboard</span>
          </NavLink>
        </div>
        <hr className="horizontal light mt-0 mb-2" />
        <div className="collapse navbar-collapse w-auto" id="sidenav-collapse-main">
          <ul className="navbar-nav">
            <li className="nav-item">
              <NavLink
                className={({ isActive }) => `nav-link text-white ${isActive ? 'active bg-gradient-primary' : ''}`}
                to="/dashboard"
              >
                <div className="text-white text-center me-2 d-flex align-items-center justify-content-center">
                  <i className="material-icons opacity-10">dashboard</i>
                </div>
                <span className="nav-link-text ms-1">Dashboard</span>
              </NavLink>
            </li>
            <li className="nav-item">
              <NavLink
                className={({ isActive }) => `nav-link text-white ${isActive ? 'active bg-gradient-primary' : ''}`}
                to="/userlist"
              >
                <div className="text-white text-center me-2 d-flex align-items-center justify-content-center">
                  <i className="material-icons opacity-10">people</i>
                </div>
                <span className="nav-link-text ms-1">Users</span>
              </NavLink>
            </li>
            <li className="nav-item">
              <NavLink
                className={({ isActive }) => `nav-link text-white ${isActive ? 'active bg-gradient-primary' : ''}`}
                to="/categorylist"
              >
                <div className="text-white text-center me-2 d-flex align-items-center justify-content-center">
                  <i className="material-icons opacity-10">grid_view</i>
                </div>
                <span className="nav-link-text ms-1">Categories</span>
              </NavLink>
            </li>
            <li className="nav-item">
              <NavLink
                className={({ isActive }) => `nav-link text-white ${isActive ? 'active bg-gradient-primary' : ''}`}
                to="/services"
              >
                <div className="text-white text-center me-2 d-flex align-items-center justify-content-center">
                  <i className="material-icons opacity-10">list</i>
                </div>
                <span className="nav-link-text ms-1">Sub Categories</span>
              </NavLink>
            </li>
            <li className="nav-item">
              <NavLink
                className={({ isActive }) => `nav-link text-white ${isActive ? 'active bg-gradient-primary' : ''}`}
                to="/bookinglist"
              >
                <div className="text-white text-center me-2 d-flex align-items-center justify-content-center">
                  <i className="material-icons opacity-10">calendar_today</i>
                </div>
                <span className="nav-link-text ms-1">Bookings</span>
              </NavLink>
            </li>
            <li className="nav-item">
              <NavLink
                className={({ isActive }) => `nav-link text-white ${isActive ? 'active bg-gradient-primary' : ''}`}
                to="/privacy"
              >
                <div className="text-white text-center me-2 d-flex align-items-center justify-content-center">
                  <i className="material-icons opacity-10">shield</i>
                </div>
                <span className="nav-link-text ms-1">Privacy Policy</span>
              </NavLink>
            </li>
            <li className="nav-item">
              <NavLink
                className={({ isActive }) => `nav-link text-white ${isActive ? 'active bg-gradient-primary' : ''}`}
                to="/aboutus"
              >
                <div className="text-white text-center me-2 d-flex align-items-center justify-content-center">
                  <i className="material-icons opacity-10">info</i>
                </div>
                <span className="nav-link-text ms-1">About Us</span>
              </NavLink>
            </li>
            <li className="nav-item">
              <NavLink
                className={({ isActive }) => `nav-link text-white ${isActive ? 'active bg-gradient-primary' : ''}`}
                to="/terms"
              >
                <div className="text-white text-center me-2 d-flex align-items-center justify-content-center">
                  <i className="material-icons opacity-10">article</i>
                </div>
                <span className="nav-link-text ms-1">Terms & Conditions</span>
              </NavLink>
            </li>
            <li className="nav-item mt-3">
              <h6 className="ps-4 ms-2 text-uppercase text-xs text-white font-weight-bolder opacity-8">Account pages</h6>
            </li>
            <li className="nav-item">
              <NavLink
                className={({ isActive }) => `nav-link text-white ${isActive ? 'active bg-gradient-primary' : ''}`}
                to="/profile"
              >
                <div className="text-white text-center me-2 d-flex align-items-center justify-content-center">
                  <i className="material-icons opacity-10">person</i>
                </div>
                <span className="nav-link-text ms-1">Profile</span>
              </NavLink>
            </li>
            <li className="nav-item">
              <NavLink
                className={({ isActive }) => `nav-link text-white ${isActive ? 'active bg-gradient-primary' : ''}`}
                to="/changepassword"
              >
                <div className="text-white text-center me-2 d-flex align-items-center justify-content-center">
                  <i className="material-icons opacity-10">lock</i>
                </div>
                <span className="nav-link-text ms-1">Password</span>
              </NavLink>
            </li>
            <li className="nav-item">
              <NavLink
                className={({ isActive }) => `nav-link text-white ${isActive ? 'active bg-gradient-primary' : ''}`}
                to="/Map"
              >
                <div className="text-white text-center me-2 d-flex align-items-center justify-content-center">
                  <i className="material-icons opacity-10">map</i>
                </div>
                <span className="nav-link-text ms-1">Map</span>
              </NavLink>
            </li>
          </ul>
        </div>
      </aside>
    </div>
  );
};

export default Sidebar;
