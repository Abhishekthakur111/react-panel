import React from 'react';
import Sidebar from './Sidebar';
import Navbar from './Navbar';
import Footer from './Footer';
import { Outlet } from 'react-router-dom';

const Layout = () => {
  return (
    <div className="container-fluid">
      <div className="row">
        <div className="col-2">
          <Sidebar />
        </div>
        <div className="col-10">
          <Navbar />
          <div className="py-2">
            <Outlet />
          </div>
          <Footer />
        </div>
      </div>
    </div>
  );
};

export default Layout;
