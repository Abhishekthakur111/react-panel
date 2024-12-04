import React, { useState, useEffect, useRef } from "react";
import { Link, useNavigate, useLocation } from "react-router-dom";
import axios from "axios";
import Swal from "sweetalert2";
import { BASE_URL } from "../Config";

const Navbar = ({ toggleSidebar, closeSidebar }) => {
  const navigate = useNavigate();
  const location = useLocation();
  const [image, setImage] = useState("");
  const [name, setName] = useState("");
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const dropdownRef = useRef(null);

  const toggleDropdown = () => {
    setDropdownOpen(!dropdownOpen);
  };

  const closeDropdown = () => {
    setDropdownOpen(false);
  };

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setDropdownOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
    };
  }, []);

  useEffect(() => {
    const fetchProfile = async () => {
      const token = localStorage.getItem("token");
      if (!token) {
        console.error("No token found in localStorage");
        return;
      }
      try {
        const response = await axios.get(`${BASE_URL}/profile`, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });
        if (response.data && response.data.body) {
          const { image, name } = response.data.body;
          setImage(`${BASE_URL}/${image}`);
          setName(name);
        }
      } catch (error) {
        console.error("Error fetching profile data", error);
      }
    };
  
    fetchProfile();
  
    if (location.state?.updated) {
      fetchProfile();
    }
  }, [location.state]);
  
  const logout = async () => {
    const result = await Swal.fire({
      title: "Are you sure?",
      text: "You will be logged out of your account.",
      icon: "warning",
      showCancelButton: true,
      confirmButtonColor: "#D81B60",
      cancelButtonColor: "#d33",
      confirmButtonText: "Yes, log out!",
    });

    if (result.isConfirmed) {
      try {
        await axios.post(`${BASE_URL}/logout`);
        localStorage.removeItem("token");
        navigate("/");
        closeDropdown();
      } catch (error) {
        console.error("Error logging out:", error);
      }
    }
  };

  const pathToTitleMap = {
    "/dashboard": "Dashboard",
    "/userlist": "Users",
    "/categorylist": "Categories",
    "/privacypolicy": "Privacy Policy",
    "/aboutus": "About Us",
    "/terms&conditions": "Terms&Conditions",
    "/subcategory": "Sub Categories",
    "/bookinglist": "Bookings",
    "/map": "Map",
    "/changepassword": "Change Password",
    "/profile":"Profile",
  };

  const currentPath = location.pathname;
  const currentTitle =
    pathToTitleMap[currentPath] ||
    (currentPath.startsWith("/viewuser")
      ? "User Detail"
      : currentPath.startsWith("/booking")
      ? "Booking Detail"
      : currentPath.startsWith("/subcategory")
      ? "Sub Category Detail"
      : currentPath.startsWith("/viewcategory")
      ? "Category Detail"
      : currentPath.startsWith("/updatecategory")
      ? "Edit Category"
      : currentPath.startsWith("/updatesubcategory")
      ? "Edit Sub Category"
      : "");

  const handleLinkClick = () => {
    closeSidebar(); 
  };

  return (
    <nav
      className="navbar navbar-main navbar-expand-lg px-0 mx-4 mt-3 shadow-none border-radius-xl"
      id="navbarBlur"
      data-scroll="true"
      style={{ backgroundColor: "white" }}
    >
      <div className="container-fluid d-flex justify-content-between align-items-center">
       
        <button
          onClick={toggleSidebar}
          className="navbar-toggler d-xl-none"
          type="button"
          style={{
            background: "none",
            border: "none",
            fontSize: "24px",
          }}
        >
          <i className="fas fa-bars"></i>
        </button>
        <div aria-label="breadcrumb">
          <h2 className="font-weight-bolder mb-0 d-none d-lg-block">{currentTitle}</h2>
        </div>

        <ul className="navbar-nav navbar-right d-flex align-items-center">
          <li className="d-flex align-items-center ms-auto">
            <h5 className="mb-0">{name}</h5>
            <div className="dropdown" ref={dropdownRef}>
              <Link
                to="#"
                onClick={toggleDropdown}
                className="nav-link nav-link-lg nav-link-user d-flex align-items-center"
                style={{ position: "relative" }}
              >
                <img
                  alt="avatar"
                  src={image || "default_avatar.png"}
                  style={{ height: "50px", width: "50px", cursor: "pointer" }}
                  className="rounded-circle mr-1"
                />
              </Link>
              {dropdownOpen && (
                <div
                  className={`dropdown-menu dropdown-menu-end ${
                    dropdownOpen ? "show" : ""
                  }`}
                  style={{
                    backgroundColor: "pink",
                    position: "absolute",
                    top: "15px",
                    borderRadius: "0.5rem",
                    minWidth: "130px",
                    zIndex: 1000,
                  }}
                >
                  <Link
                    to="/profile"
                    className="dropdown-item has-icon text-success"
                    onClick={() => {
                      closeDropdown();
                      handleLinkClick(); 
                    }}
                  >
                    <i className="far fa-user" /> Profile
                  </Link>
                  <Link
                    to="/changepassword"
                    className="dropdown-item has-icon text-info"
                    onClick={() => {
                      closeDropdown();
                      handleLinkClick(); 
                    }}
                  >
                    <i className="fas fa-cogs" /> Change Password
                  </Link>
                  <a
                    href="#"
                    className="dropdown-item has-icon text-danger"
                    onClick={logout}
                  >
                    <i className="fas fa-sign-out-alt" /> Log out
                  </a>
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
