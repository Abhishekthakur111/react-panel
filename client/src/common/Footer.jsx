import React from 'react';
import { Link } from 'react-router-dom';

const Footer = () => {
  return (
    <footer className="footer py-4">
      <div className="container-fluid">
        <div className="row align-items-center justify-content-lg-between">
          <div className="col-lg-6 mb-lg-0 mb-4">
            <div className="copyright  text-sm text-muted text-lg-start">
             COPYRIGHT © {new Date().getFullYear()}{" "}
              <Link to="/dashboard" className="font-weight-bold" target="" rel="noopener noreferrer">React, </Link>
              All rights Reserved
            </div>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
