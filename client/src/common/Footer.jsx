import React from 'react';
import { Link } from 'react-router-dom';

const Footer = () => {
  return (
    <footer className="footer py-4">
      <div className="container-fluid">
        <div className="row align-items-center justify-content-lg-between">
          <div className="col-lg-6 mb-lg-0 mb-4">
            <div className="copyright text-center text-sm text-muted text-lg-start">
              © {new Date().getFullYear()}, made with <i className="fa fa-heart"></i> by
              <Link to="/dashboard" className="font-weight-bold" target="" rel="noopener noreferrer"> React theme </Link>
              for a better web.
            </div>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
