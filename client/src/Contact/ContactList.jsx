import React, { useEffect, useState } from "react";
import Swal from "sweetalert2";
import { ToastContainer } from "react-toastify";
import { Link } from "react-router-dom";
import { axiosInstance } from "../Config";
import "@fortawesome/fontawesome-free/css/all.min.css";
import Pagination from "@mui/material/Pagination";
import Stack from "@mui/material/Stack";

const ContactList = () => {
  const [data, setData] = useState([]);
  const [searchTerm, setSearchTerm] = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const limit = 10;

  useEffect(() => {
    fetchData(currentPage);
  }, [currentPage]);

  const fetchData = async () => {
    try {
      const response = await axiosInstance.get(
        `/contactlist?page=${currentPage}&limit=${limit}`
      );
      if (response.data.success) {
        setData(response.data.body.data);
        setTotalPages(response.data.body.totalPages);
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
      confirmButtonColor: "#D81B60",
      cancelButtonColor: "#d33",
      confirmButtonText: "Yes, delete it!",
    });

    if (result.isConfirmed) {
      try {
        await axiosInstance.delete(`/contactdelete/${_id}`);
        const response = await axiosInstance.get(
          `/contactlist?page=${currentPage}&limit=${limit}`
        );
        if (response.data.success) {
          const newTotalPages = response.data.body.totalPages;
          if (currentPage > newTotalPages) {
            setCurrentPage(newTotalPages || 1);
          }
          setTotalPages(newTotalPages);
        }
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
  const handlePageChange = (event, value) => {
    setCurrentPage(value);
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
                <div className="bg-gradient-primary shadow-primary border-radius-lg pt-2 pb-2">
                  <div className="d-flex justify-content-between align-items-center px-3 pt-1">
                    <h6 className="text-white text-capitalize">Contacts</h6>
                  </div>
                </div>
              </div>
              <div className="section-body">
                <div className="card">
                  <div className="card-body">
                    <div className="d-flex justify-content-end">
                      <div>
                        <input
                          type="text"
                          className="form-control"
                          placeholder="Search by name..."
                          value={searchTerm}
                          onChange={(e) => setSearchTerm(e.target.value)}
                          style={{ backgroundColor: "pink" }}
                        />
                      </div>
                    </div>
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
                    <Stack
                      spacing={2}
                      className="d-flex justify-content-center mt-3"
                    >
                      <Pagination
                        count={totalPages}
                        page={currentPage}
                        onChange={handlePageChange}
                        color="primary"
                      />
                    </Stack>
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
