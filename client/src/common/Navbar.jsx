import React from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import axios from 'axios';
import Swal from 'sweetalert2';

const Navbar = () => {
  const navigate = useNavigate();
  const location = useLocation();

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
      } catch (error) {
        console.error('Error logging out:', error);
      }
    }
  };

  const pathToTitleMap = {
    '/dashboard': 'Dashboard',
    '/userlist': 'Users',
    '/categorylist': 'Categories',
    '/privacy': 'Privacy Policy',
    '/aboutus': 'About Us',
    '/terms': 'Terms & Conditions',
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
    '/Map': "Map"
  };

  const currentPath = location.pathname;

 
  const currentTitle = pathToTitleMap[currentPath] ||
    (currentPath.startsWith('/viewuser') ? 'User Details' : 
     currentPath.startsWith('/booking') ? 'Booking Details' : 
     currentPath.startsWith('/service') ? 'Sub Category Details' : 
     currentPath.startsWith('/viewcategeory') ? 'Category Details' : '');

  // const breadcrumbs = currentPath.split('/').filter((item) => item);
  // const uniqueBreadcrumbs = Array.from(new Set(breadcrumbs));
  // const breadcrumbItems = uniqueBreadcrumbs.map((item, index) => {
  //   const path = `/${uniqueBreadcrumbs.slice(0, index + 1).join('/')}`;
  //   return (
  //     <li key={index} className="breadcrumb-item text-sm">
  //       <Link to={path} className="opacity-5 text-dark">
  //         {item.charAt(0).toUpperCase() + item.slice(1)}
  //       </Link>
  //     </li>
  //   );
  // });

  return (
    <nav className="navbar navbar-main navbar-expand-lg px-0 mx-4 mt-4 shadow-none border-radius-xl" id="navbarBlur" data-scroll="true">
      <div className="container-fluid py-1 px-3">
        <Link to="/" aria-label="breadcrumb">
          <h2 className="font-weight-bolder mb-0">{currentTitle}</h2>
        </Link>
        <div className="collapse navbar-collapse mt-sm-0 mt-2 me-md-0 me-sm-4" id="navbar">
          <div className="ms-md-auto pe-md-3 d-flex align-items-center">
            <div className="input-group input-group-outline">
              <label className="form-label"></label>
            </div>
          </div>
          <ul className="navbar-nav justify-content-end">
            <li className="nav-item d-flex align-items-center">
              <Link to="#" onClick={logout} className="nav-link text-body font-weight-bold px-0">
                <h4 className="fa fa-sign-out-alt me-sm-1" style={{ color: '#D81B60' }}></h4>
                <h4 className="d-sm-inline d-none">Logout</h4>
              </Link>
            </li>
          </ul>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
