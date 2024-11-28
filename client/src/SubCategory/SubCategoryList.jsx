import React, { useState, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import axios from "axios";
import Swal from "sweetalert2";
import { ToastContainer, toast } from "react-toastify";
import { BASE_URL } from "../Config";

const SubCategoryList = () => {
  const [services, setServices] = useState([]);
  const [searchTerm, setSearchTerm] = useState("");
  const [loading, setLoading] = useState(true);
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [pageSize, setPageSize] = useState(10);
  const navigate = useNavigate();

  useEffect(() => {
    fetchData();
  }, [currentPage]);

  const fetchData = async () => {
    setLoading(true);
    try {
      const response = await axios.get(`${BASE_URL}/services`, {
        params: { page: currentPage, size: pageSize },
      });
      if (response.data.success) {
        setServices(response.data.body.data);
        setTotalPages(response.data.body.pagination.totalPages);
      } else {
        Swal.fire(
          "Error",
          response.data.message || "Failed to load sub category",
          "error"
        );
      }
    } catch (error) {
      console.error("Error fetching sub category list", error);
      Swal.fire(
        "Error",
        error.response?.data?.message ||
          "An error occurred while fetching the Sub Category list",
        "error"
      );
    } finally {
      setLoading(false);
    }
  };

  const toggleStatus = async (id, currentStatus) => {
    const newStatus = currentStatus === "0" ? "1" : "0";

    try {
      const response = await axios.post(`${BASE_URL}/status`, {
        id,
        status: newStatus,
      });

      if (response.data.success) {
        fetchData();
        toast.success(
          `Sub Category status changed to ${
            newStatus === "0" ? "Active" : "Inactive"
          }`
        );
      } else {
        toast.error(response.data.message || "Failed to change status");
      }
    } catch (error) {
      toast.error("An error occurred while changing status");
    }
  };

  const deleteService = async (_id) => {
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
        await axios.delete(`${BASE_URL}/delete_service/${_id}`);
        fetchData();
        Swal.fire("Deleted!", "Sub Category has been deleted.", "success");
      } catch (error) {
        Swal.fire(
          "Error!",
          error.response?.data?.message || "Error deleting Sub Category",
          "error"
        );
      }
    } else {
      Swal.fire(
        "Cancelled",
        "Sub Category deletion has been cancelled",
        "info"
      );
    }
  };

  const handleSearch = (e) => {
    setSearchTerm(e.target.value);
  };

  const filteredServices = services.filter((service) =>
    service.name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handlePageChange = (pageNumber) => {
    setCurrentPage(pageNumber);
  };

  return (
    <>
      <ToastContainer position="top-right" autoClose={5000} />
      <div className="container-fluid ">
        <div className="row">
          <div className="col-12">
            <div className="card my-3">
              <div className="card-header p-0 position-relative mt-n4 mx-3 z-index-2 ">
                <div className="bg-gradient-primary shadow-primary border-radius-lg pt-2 pb-1">
                  <div className="d-flex justify-content-between align-items-center px-3">
                    <h6 className="text-white text-capitalize ">
                      Sub Categories
                    </h6>
                    <div className="d-flex align-items-center">
                      <div className="mx-3">
                        <input
                          type="text"
                          className="form-control"
                          placeholder="Search by name..."
                          value={searchTerm}
                          onChange={handleSearch}
                          style={{
                            backgroundColor: "white",
                            paddingLeft: "10px",
                          }}
                        />
                      </div>
                      <Link
                        to="/subcategoryadd"
                        className="btn btn-light "
                        style={{ marginTop: "10px" }}
                      >
                        Add
                      </Link>
                    </div>
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
                              <th>Category Name</th>
                              <th>Name</th>
                              <th>Price</th>
                              <th>Image</th>
                              <th>Status</th>
                              <th>Action</th>
                            </tr>
                          </thead>
                          <tbody>
                            {filteredServices.length ? (
                              filteredServices.map((service, index) => (
                                <tr key={service._id}>
                                  <td>
                                    {(currentPage - 1) * pageSize + index + 1}
                                  </td>
                                  <td>
                                    {service.cat_id?.status === "0"
                                      ? service.cat_id?.name 
                                      : "No Category"}
                                  </td>
                                  <td>{service.name}</td>
                                  <td>${service.price}</td>
                                  <td>
                                    {service.image ? (
                                      <img
                                        src={`${BASE_URL}/${service.image}`}
                                        alt={service.name}
                                        onError={(e) =>
                                          (e.target.src =
                                            "path/to/default/image.jpg")
                                        }
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
                                        id={`statusSwitch-${service._id}`}
                                        checked={service.status === "0"}
                                        onChange={() =>
                                          toggleStatus(
                                            service._id,
                                            service.status
                                          )
                                        }
                                        style={{
                                          backgroundColor:
                                            service.status === "0"
                                              ? "#D81B60"
                                              : "lightgray",
                                          borderColor:
                                            service.status === "0"
                                              ? "#D81B60"
                                              : "lightgray",
                                        }}
                                      />
                                    </div>
                                  </td>
                                  <td>
                                    <Link
                                      to={`/subcategory/${service._id}`}
                                      className="has-icon btn btn-success m-1"
                                      style={{
                                        backgroundColor: "#D81B60",
                                        color: "white",
                                      }}
                                    >
                                      <i className="me-100 fas fa-eye" />
                                    </Link>
                                    <Link
                                      to={`/updatesubcategory/${service._id}`}
                                      className="has-icon btn btn-success m-1"
                                      style={{
                                        backgroundColor: "#D81B60",
                                        color: "white",
                                      }}
                                    >
                                      <i className="me-100 fas fa-edit" />
                                    </Link>
                                    <button
                                      onClick={() => deleteService(service._id)}
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
                              ))
                            ) : (
                              <tr>
                                <td colSpan="7">No services found</td>
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
                        <li
                          className={`page-item ${
                            currentPage === 1 ? "disabled" : ""
                          }`}
                        >
                          <button
                            className="page-link"
                            onClick={() => handlePageChange(currentPage - 1)}
                          >
                            <i className="fas fa-chevron-left" />
                          </button>
                        </li>
                        {Array.from({ length: totalPages }, (_, index) => (
                          <li
                            key={index}
                            className={`page-item ${
                              currentPage === index + 1 ? "active" : ""
                            }`}
                          >
                            <button
                              className="page-link"
                              onClick={() => handlePageChange(index + 1)}
                            >
                              {index + 1}
                              {currentPage === index + 1 && (
                                <span className="sr-only">(current)</span>
                              )}
                            </button>
                          </li>
                        ))}
                        <li
                          className={`page-item ${
                            currentPage === totalPages ? "disabled" : ""
                          }`}
                        >
                          <button
                            className="page-link"
                            onClick={() => handlePageChange(currentPage + 1)}
                          >
                            <i className="fas fa-chevron-right" />
                          </button>
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

export default SubCategoryList;
