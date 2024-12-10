import React, { useEffect, useState } from "react";
import axios from "axios";
import Swal from "sweetalert2";
import { toast, ToastContainer } from "react-toastify";
import { Link } from "react-router-dom";
import { BASE_URL } from "../Config";
import '@fortawesome/fontawesome-free/css/all.min.css';

const ContactList = () => {
  const [data, setData] = useState([]);
  const [searchTerm, setSearchTerm] = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [pageSize, setPageSize] = useState(10);

  useEffect(() => {
    fetchData(currentPage);
  }, [currentPage]);

  const fetchData = async (page) => {
    try {
      const response = await axios.get(`${BASE_URL}/contactlist`, {
        params: { page, size: pageSize },
      });
      if (response.data.success) {
        setData(response.data.body.data);
        setTotalPages(response.data.body.pagination.totalPages);
      } else {
        Swal.fire(
          "Error",
          response.data.message || "Failed to load contacts",
          "error"
        );
      }
    } catch (error) {
      console.error("Error fetching contact list", error);
      Swal.fire(
        "Error",
        "An error occurred while fetching the contact list",
        "error"
      );
    }
  };

  const deleteUser = async (_id) => {
    const result = await Swal.fire({
      title: "Are you sure?",
      text: "You won't be able to revert this!",
      icon: "warning",
      showCancelButton: true,
      confirmButtonColor: "#3085d6",
      cancelButtonColor: "#d33",
      confirmButtonText: "Yes, delete it!",
    });

    if (result.isConfirmed) {
      try {
        await axios.delete(`${BASE_URL}/contactdelete/${_id}`);
        fetchData(currentPage); 
        Swal.fire("Deleted!", "Contact has been deleted.", "success");
      } catch (error) {
        Swal.fire(
          "Error!",
          error.response?.data?.message || "Error deleting contact",
          "error"
        );
      }
    } else {
      Swal.fire("Cancelled", "Contact deletion has been cancelled", "info");
    }
  };

  const filteredUsers = data.filter((user) =>
    user.name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handlePageChange = (page) => {
    if (page > 0 && page <= totalPages) {
      setCurrentPage(page);
    }
  };

  return (
    <>
      <ToastContainer
        position="top-right"
        autoClose={1000}
        hideProgressBar={false}
        newestOnTop={false}
        closeOnClick
        rtl={false}
        pauseOnFocusLoss
        draggable
        pauseOnHover
      />
      <div className="container-fluid">
        <div className="row">
          <div className="col-12">
            <div className="card my-4">
              <div className="card-header p-0 position-relative mt-n4 mx-3 z-index-2">
                <div className="bg-gradient-primary shadow-primary border-radius-lg pt-3 pb-3 d-flex justify-content-between align-items-center">
                  <h6 className="text-white text-capitalize ps-3">Contacts</h6>
                  <div className="mx-3">
                    <input
                      type="text"
                      className="form-control"
                      placeholder="Search by name..."
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                      style={{ backgroundColor: "white", paddingLeft: "10px" }}
                    />
                  </div>
                </div>
              </div>
              <div className="section-body">
                <div className="card">
                  <div className="card-body">
                    <div className="table-responsive">
                      <table className="table text-center">
                        <thead>
                          <tr>
                            <th>Sr_No.</th>
                            <th>Name</th>
                            <th>Email</th>
                            <th>Address</th>
                            <th>Phone No</th>
                            <th>Action</th>
                          </tr>
                        </thead>
                        <tbody>
                          {filteredUsers.map((user, index) => (
                            <tr key={user._id}>
                              <td>{index + 1}</td>
                              <td>{user.name || "no user"}</td>
                              <td>{user.email || "no email"}</td>
                              <td>{user.address || "no address"}</td>
                              <td>{user.phoneNumber || "no phone number"}</td>
                              <td>
                                <Link
                                  to={`/contactview/${user._id}`}
                                  className="has-icon btn btn-success m-1"
                                  style={{
                                    backgroundColor: "#D81B60",
                                    color: "white",
                                  }}
                                >
                                  <i className="me-100 fas fa-eye" />
                                </Link>
                                <button
                                  onClick={() => deleteUser(user._id)}
                                  className="has-icon btn m-1"
                                  style={{
                                    backgroundColor: "#D81B60",
                                    borderColor: "#D81B60",
                                    color: "#fff",
                                  }}
                                >
                                  <i className="me-100 fas fa-trash" />
                                </button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    <div className="card-footer text-right">
                      <nav className="d-inline-block">
                        <ul className="pagination mb-0">
                          <li
                            className={`page-item ${
                              currentPage === 1 ? "disabled" : ""
                            }`}
                          >
                            <a
                              className="page-link"
                              href="#"
                              onClick={() => handlePageChange(currentPage - 1)}
                            >
                              <i className="fas fa-chevron-left" />
                            </a>
                          </li>
                          {[...Array(totalPages).keys()].map((page) => (
                            <li
                              key={page}
                              className={`page-item ${
                                currentPage === page + 1 ? "active" : ""
                              }`}
                            >
                              <a
                                className="page-link"
                                href="#"
                                onClick={() => handlePageChange(page + 1)}
                              >
                                {page + 1}
                              </a>
                            </li>
                          ))}
                          <li
                            className={`page-item ${
                              currentPage === totalPages ? "disabled" : ""
                            }`}
                          >
                            <a
                              className="page-link"
                              href="#"
                              onClick={() => handlePageChange(currentPage + 1)}
                            >
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
      </div>
    </>
  );
};

export default ContactList;
