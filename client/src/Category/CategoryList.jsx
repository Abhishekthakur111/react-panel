import React, { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import axios from "axios";
import Swal from "sweetalert2";
import { ToastContainer, toast } from "react-toastify";
import { BASE_URL } from "../Config";



const CategoryList = () => {
  const [categories, setCategories] = useState([]);
  const [searchTerm, setSearchTerm] = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [pageSize] = useState(10);
  const navigate = useNavigate();

  useEffect(() => {
    fetchData();
  }, [currentPage]);

  const fetchData = async () => {
    try {
      const response = await axios.get(`${BASE_URL}/categorylist`, {
        params: {
          page: currentPage,
          size: pageSize,
        },
      });

      if (response.data.success) {
        setCategories(response.data.body.data);
        setTotalPages(response.data.body.pagination.totalPages);
      } else {
        Swal.fire(
          "Error",
          response.data.message || "Failed to load categories",
          "error"
        );
      }
    } catch (error) {
      console.error("Error fetching category list", error);
      Swal.fire(
        "Error",
        "An error occurred while fetching the category list",
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
        await axios.delete(`${BASE_URL}/deletecategory/${_id}`);
        fetchData();
        Swal.fire("Deleted!", "Category has been deleted.", "success");
      } catch (error) {
        Swal.fire(
          "Error!",
          error.response?.data?.message || "Error deleting category",
          "error"
        );
      }
    } else {
      Swal.fire("Cancelled", "Category deletion has been cancelled", "info");
    }
  };

  const [isToastActive, setIsToastActive] = useState(false);

const toggleStatus = async (id, currentStatus) => {
  const newStatus = currentStatus === "0" ? "1" : "0";

  try {
    const response = await axios.post(`${BASE_URL}/categorystatus`, {
      id,
      status: newStatus,
    });

    if (response.data.success) {
      fetchData();
      if (!isToastActive) {
        setIsToastActive(true);
        toast.success(
          `Category status changed to ${
            newStatus === "0" ? "Active" : "Inactive"
          }`
        );
        setTimeout(() => {
          setIsToastActive(false);
        }, 2000);
      }
    } else {
      toast.error(response.data.message || "Failed to change status");
    }
  } catch (error) {
    toast.error("An error occurred while changing category status");
  }
};


  const filteredCategories = categories.filter((category) =>
    category.name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handlePageChange = (page) => {
    setCurrentPage(page);
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
      <div className="container-fluid ">
        <div className="row">
          <div className="col-12">
            <div className="card my-4">
              <div className="card-header p-0 position-relative mt-n4 mx-3 z-index-2">
                <div className="bg-gradient-primary shadow-primary border-radius-lg pt-2 pb-2">
                  <div className="d-flex justify-content-between align-items-center px-3">
                    <h6 className="text-white text-capitalize">Categories</h6>
                    <div className="d-flex align-items-center">
                      <div className="mx-3">
                        <input
                          type="text"
                          className="form-control"
                          placeholder="Search by name..."
                          value={searchTerm}
                          onChange={(e) => setSearchTerm(e.target.value)}
                          style={{
                            backgroundColor: "white",
                            paddingLeft: "10px",
                          }}
                        />
                      </div>
                     <div className="mt-1">
                     <Link
                        to="/categoryadd"
                        className="btn btn-light"
                        style={{  marginTop: "10px" }}
                      >
                        Add
                      </Link>
                     </div>
                    </div>
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
                            <th>Image</th>
                            <th>Status</th>
                            <th>Action</th>
                          </tr>
                        </thead>
                        <tbody>
                          {filteredCategories.map((category, index) => (
                            <tr key={category._id}>
                              <td>
                                {(currentPage - 1) * pageSize + index + 1}
                              </td>
                              <td>{category.name || 'no category'}</td>
                              <td>
                                {category.image ? (
                                  <img
                                    src={`${BASE_URL}/${category.image}`}
                                    alt={category.name}
                                    style={{
                                      width: "50px",
                                      height: "50px",
                                      borderRadius: "50%",
                                    }}
                                  />
                                ) : (
                                  "No Image"
                                )}
                              </td>
                              <td>
                                <div className="form-check form-switch d-flex align-items-center justify-content-center">
                                  <input
                                    className="form-check-input"
                                    type="checkbox"
                                    id={`statusSwitch-${category._id}`}
                                    checked={category.status === "0"}
                                    onChange={() =>
                                      toggleStatus(
                                        category._id,
                                        category.status
                                      )
                                    }
                                    style={{
                                      backgroundColor:
                                        category.status === "0"
                                          ? "#D81B60"
                                          : "lightgray",
                                      borderColor:
                                        category.status === "0"
                                          ? "#D81B60"
                                          : "lightgray",
                                    }}
                                  />
                                </div>
                              </td>

                              <td>
                                <Link
                                  to={`/viewcategory/${category._id}`}
                                  className="has-icon btn btn-success m-1"
                                  style={{
                                    backgroundColor: "#D81B60",
                                    color: "white",
                                  }}
                                >
                                  <i className="me-100 fas fa-eye" />
                                </Link>
                                <Link
                                  to={`/updatecategory/${category._id}`}
                                  className="has-icon btn btn-success m-1"
                                  style={{
                                    backgroundColor: "#D81B60",
                                    color: "white",
                                  }}
                                >
                                  <i className="me-100 fas fa-edit" />
                                </Link>
                                <button
                                  onClick={() => deleteUser(category._id)}
                                  className="has-icon btn  m-1 "
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
    </>
  );
};

export default CategoryList;
