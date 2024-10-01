import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import axios from 'axios';
import Swal from 'sweetalert2';
import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';

const BASE_URL = "http://localhost:8000";

const BookingList = () => {
  const [bookings, setBookings] = useState([]);
  const [searchTerm, setSearchTerm] = useState("");
  const [loading, setLoading] = useState(true);
  const [statusOptions] = useState([
    { value: "0", label: "Pending" },
    { value: "1", label: "Ongoing" },
    { value: "2", label: "Complete" }
  ]);
  const [pagination, setPagination] = useState({
    totalCount: 0,
    totalPages: 0,
    currentPage: 1,
    pageSize: 5
  });
  
  const navigate = useNavigate();

  useEffect(() => {
    fetchData(pagination.currentPage);
  }, [pagination.currentPage]);

  const fetchData = async (page) => {
    setLoading(true);
    try {
      const response = await axios.get(`${BASE_URL}/booking`, {
        params: {
          page: page,
          size: pagination.pageSize
        }
      });
      if (response.data.success) {
        setBookings(response.data.body.data);
        setPagination(response.data.body.pagination);
      } else {
        Swal.fire("Error", response.data.message || "Failed to load bookings", "error");
      }
    } catch (error) {
      console.error("Error fetching booking list", error);
      Swal.fire("Error", error.response?.data?.message || "An error occurred while fetching the booking list", "error");
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = (e) => {
    setSearchTerm(e.target.value);
  };

  const filteredBookings = bookings.filter(booking =>
    booking.booking_code.toLowerCase().includes(searchTerm.toLowerCase())
  );

 

  const handleStatusChange = async (bookingId, newStatus) => {
    try {
      const response = await axios.post(`${BASE_URL}/bookingstatus`, { id: bookingId, status: newStatus });
      if (response.data.success) {
        toast.success("Booking status updated successfully");
        fetchData(pagination.currentPage); 
      } else {
        Swal.fire("Error", response.data.message || "Failed to update status", "error");
      }
    } catch (error) {
      console.error("Error updating booking status", error);
      Swal.fire("Error", error.response?.data?.message || "An error occurred while updating the status", "error");
    }
  };

  const handlePageChange = (pageNumber) => {
    if (pageNumber >= 1 && pageNumber <= pagination.totalPages) {
      setPagination(prev => ({ ...prev, currentPage: pageNumber }));
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
      <div className="container-fluid py-2">
        <div className="row">
          <div className="col-12">
            <div className="card my-4">
              <div className="card-header p-0 position-relative mt-n4 mx-3 z-index-2">
              <div className="bg-gradient-primary shadow-primary border-radius-lg pt-3 pb-3 d-flex justify-content-between align-items-center ">
                  <h6 className="text-white text-capitalize ps-3">Bookings</h6>
                  <div className="mx-3">
                    <input
                      type="text"
                      className="form-control"
                      placeholder="Search by name..."
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                      style={{ backgroundColor: "white" ,paddingLeft:'10px'}} 
                    />
                  </div>
                </div>
              </div>
              <div className="section-body">
                <div className="card">
                  <div className="card-body">
                    {loading ? (
                      <p>Loading...</p> 
                    ) : (
                      <div className="table-responsive">
                        <table className="table text-center">
                          <thead>
                            <tr>
                              <th>Sr_No.</th>
                              <th>Customer Name</th>
                              <th>Category Name</th>
                              <th>Service Name</th>
                              <th>Booking Code</th>
                              <th>Amount</th>
                              <th>Status</th>
                              <th>Action</th>
                            </tr>
                          </thead>
                          <tbody>
                            {filteredBookings.length ? (
                              filteredBookings.map((booking, index) => (
                                <tr key={booking._id}>
                                  <td>{(pagination.currentPage - 1) * pagination.pageSize + index + 1}</td>
                                  <td>{booking.user_id?.name || "name"}</td>
                                  <td>{booking.cat_id?.name || "unknown"}</td>
                                  <td>{booking.service_id?.name || "unknown"}</td>
                                  <td>{booking.booking_code}</td>                       
                                  <td>${booking.amount}</td>
                                  <td>
                                    <select
                                      value={booking.status}
                                      onChange={(e) => handleStatusChange(booking._id, e.target.value)}
                                      className="form-select"
                                    >
                                      {statusOptions.map(option => (
                                        <option key={option.value} value={option.value}>
                                          {option.label}
                                        </option>
                                      ))}
                                    </select>
                                  </td>
                                  <td>
                                    <Link
                                      to={`/booking/${booking._id}`}
                                      className="has-icon btn btn-success m-1"
                                      style={{
                                        backgroundColor: "#D81B60",
                                        color: "white",
                                      }}
                                    >
                                      <i className="me-100 fas fa-eye" />                                    </Link>
                                  </td>
                                </tr>
                              ))
                            ) : (
                              <tr>
                                <td colSpan="8">No bookings found</td>
                              </tr>
                            )}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>
                  <div className="card-footer text-right">
                    <nav className="d-inline-block">
                      <ul className="pagination mb-0">
                        <li className={`page-item ${pagination.currentPage === 1 ? 'disabled' : ''}`}>
                          <a className="page-link" href="#" onClick={() => handlePageChange(pagination.currentPage - 1)}>
                            <i className="fas fa-chevron-left" />
                          </a>
                        </li>
                        {[...Array(pagination.totalPages).keys()].map(pageNumber => (
                          <li key={pageNumber + 1} className={`page-item ${pagination.currentPage === pageNumber + 1 ? 'active' : ''}`}>
                            <a className="page-link" href="#" onClick={() => handlePageChange(pageNumber + 1)}>
                              {pageNumber + 1}
                            </a>
                          </li>
                        ))}
                        <li className={`page-item ${pagination.currentPage === pagination.totalPages ? 'disabled' : ''}`}>
                          <a className="page-link" href="#" onClick={() => handlePageChange(pagination.currentPage + 1)}>
                            <i className="fas fa-chevron-right" />
                          </a>
                        </li>
                      </ul>
                    </nav>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}

export default BookingList;
