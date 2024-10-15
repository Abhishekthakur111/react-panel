import React, { useState, useEffect, useRef } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import axios from 'axios';
import Swal from 'sweetalert2';

const Navbar = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [image, setImage] = useState('');
  const [name, setName] = useState('');
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const dropdownRef = useRef(null);

  const toggleDropdown = () => {
    setDropdownOpen(!dropdownOpen);
  };

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setDropdownOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [dropdownRef]);

  const closeDropdown = () => {
    setDropdownOpen(false);
  };

  const logout = async () => {
    const result = await Swal.fire({
      title: 'Are you sure?',
      text: 'You will be logged out of your account.',
      icon: 'warning',
      showCancelButton: true,
      confirmButtonColor: '#D81B60',
      cancelButtonColor: '#d33',
      confirmButtonText: 'Yes, log out!',
    });

    if (result.isConfirmed) {
      try {
        await axios.post('http://localhost:8000/logout');
        localStorage.removeItem('token');
        navigate('/');
        closeDropdown();
      } catch (error) {
        console.error('Error logging out:', error);
      }
    }
  };

  useEffect(() => {
    const fetchProfile = async () => {
      const token = localStorage.getItem('token');
      if (!token) {
        console.error("No token found in localStorage");
        return;
      }

      try {
        const response = await axios.get('http://localhost:8000/profile', {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
        if (response.data && response.data.body) {
          const { image, name } = response.data.body;
          setImage(`http://localhost:8000/${image}`);
          setName(name);
        }
      } catch (error) {
        console.error("Error fetching profile data", error);
      }
    };

    fetchProfile();
  }, []);

  const pathToTitleMap = {
    '/dashboard': 'Dashboard',
    '/userlist': 'Users',
    '/categorylist': 'Categories',
    '/privacy': 'Privacy Policy',
    '/aboutus': 'About Us',
    '/terms': 'Terms&Conditions',
    '/profile': 'Profile',
    '/changepassword': 'Change Password',
    '/categoryadd': 'Add New Category',
    '/services': 'Sub Categories',
    '/subcategoryadd': 'Add New Sub Category',
    '/bookinglist': 'Bookings',
    '/booking': 'Booking Details',
    '/viewuser': 'User Details',
    '/service': 'Sub Category Details',
    '/viewcategory': 'Category Details',
    '/Map': 'Map',
    
  };

  const currentPath = location.pathname;

  const currentTitle = pathToTitleMap[currentPath] ||
    (currentPath.startsWith('/viewuser') ? 'User Details' :
      currentPath.startsWith('/booking') ? 'Booking Details' :
        currentPath.startsWith('/service') ? 'Sub Category Details' :
          currentPath.startsWith('/viewcategeory') ? 'Category Details' : '');

  

  return (
    <nav className="navbar navbar-main navbar-expand-lg px-0 mx-4 mt-4 shadow-none border-radius-xl" id="navbarBlur" data-scroll="true" style={{ backgroundColor: 'white' }}>
      <div className="container-fluid py-1 px-3 d-flex justify-content-between align-items-center">
        <div aria-label="breadcrumb">
          <h2 className="font-weight-bolder mb-0">{currentTitle}</h2>
        </div>
        <ul className="navbar-nav navbar-right d-flex align-items-center">
          <li className="d-flex align-items-center">
            <h5 className="ml-2 mb-0 mr-3">{name}</h5>
            <div className="dropdown" ref={dropdownRef}>
              <Link
                to="#"
                onClick={toggleDropdown}
                className="nav-link  nav-link-lg nav-link-user d-flex align-items-center"
                style={{ position: 'relative' }}
              >
                <img
                  alt="avatar"
                  src={image || 'default_avatar.png'}
                  style={{ height: '50px', width: '50px', cursor: 'pointer' }}
                  className="rounded-circle mr-1"
                />
              </Link>
              {dropdownOpen && (
                <div
                  className={`dropdown-menu dropdown-menu-end ${dropdownOpen ? 'show' : ''}`}
                  style={{
                    backgroundColor: 'pink',
                    position: 'absolute',
                    top: '15px',  
                    borderRadius: '0.5rem',
                    minWidth: '170px',
                    zIndex: 1000,
                  }}
                >
                  <Link to="/profile" className="dropdown-item has-icon text-success" onClick={closeDropdown}>
                    <i className="far fa-user" /> Profile
                  </Link>
                  <Link to="/changepassword" className="dropdown-item has-icon text-info" onClick={closeDropdown}>
                    <i className="fas fa-lock" /> Change Password
                  </Link>
                  <Link to="#" onClick={logout} className="dropdown-item has-icon text-danger">
                    <i className="fas fa-sign-out-alt" /> Logout
                  </Link>
                </div>
              )}
            </div>
          </li>
        </ul>
      </div>
    </nav>
  );
};

export default Navbar;
