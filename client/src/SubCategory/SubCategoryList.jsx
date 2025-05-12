import React, { useState, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import Swal from "sweetalert2";
import { ToastContainer, toast } from "react-toastify";
import { axiosInstance, BASE_URL } from "../Config";
import Pagination from "@mui/material/Pagination";
import Stack from "@mui/material/Stack";

const SubCategoryList = () => {
  const [services, setServices] = useState([]);
  const [filteredServices, setFilteredServices] = useState([]);
  const [searchTerm, setSearchTerm] = useState("");
  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const limit = 10
  const navigate = useNavigate();

  useEffect(() => {
    fetchData(currentPage);
  }, [currentPage]);

  useEffect(() => {
    filterServicesByDate();
  }, [startDate, endDate, services]);

  useEffect(() => {
    handleSearch();
  }, [searchTerm, services]);

  const fetchData = async () => {
    try {
      const response = await axiosInstance.get(`/services?page=${currentPage}&limit=${limit}`);
      if (response.data.success) {
        setServices(response.data.body.data);
        setFilteredServices(response.data.body.data);
        setTotalPages(response.data.body.totalPages);
      } else {
        Swal.fire(
          "Error",
          response.data.message || "Failed to load sub category",
          "error"
        );
      }
    } catch (error) {
      Swal.fire(
        "Error",
        error.response?.data?.message ||
          "An error occurred while fetching the Sub Category list",
        "error"
      );
    }
  };
  const handlePageChange = (event, value) => {
    setCurrentPage(value);
  };
  const filterServicesByDate = () => {
    let filtered = [...services];

    if (startDate && endDate) {
      filtered = filtered.filter((service) => {
        const serviceDate = new Date(service.createdAt);
        return (
          serviceDate >= new Date(startDate) && serviceDate <= new Date(endDate)
        );
      });
    }

    setFilteredServices(filtered);
  };

  const handleSearch = () => {
    const filtered = services.filter((service) =>
      service.name.toLowerCase().includes(searchTerm.toLowerCase())
    );
    setFilteredServices(filtered);
  };

  const toggleStatus = async (id, currentStatus) => {
    const newStatus = currentStatus === "0" ? "1" : "0";

    try {
      const response = await axiosInstance.post(`/subcategorystatus`, {
        id,
        status: newStatus,
      });

      if (response.data.success) {
        fetchData(currentPage);
        toast.success("Status updated successfully");
      } else {
        toast.error(response.data.message || "Failed to change status");
      }
    } catch (error) {
      toast.error("An error occurred while changing subcategory status");
    }
  };

  const deleteService = async (_id) => {
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
        await axiosInstance.delete(`/delete_service/${_id}`);
          const response = await axiosInstance.get(`/services?page=${currentPage}&limit=${limit}`);
                if (response.data.success) {
                  setServices(response.data.body.data);
                  const newTotalPages = response.data.body.totalPages;
                  if (currentPage > newTotalPages) {
                    setCurrentPage(newTotalPages || 1);
                  }
                  setTotalPages(newTotalPages);
                }
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

  return (
    <>
      <ToastContainer position="top-right" autoClose={5000} />
      <div className="container-fluid ">
        <div className="row">
          <div className="col-12">
            <div className="card my-3">
              <div className="card-header p-0 position-relative mt-n4 mx-3 z-index-2 ">
                <div className="bg-gradient-primary shadow-primary border-radius-lg pt-2 pb-1">
                  <div className="d-flex justify-content-between align-items-center px-3 pt-1">
                    <h6 className="text-white text-capitalize ">
                      Sub Categories
                    </h6>
                  </div>
                </div>
              </div>
              <div className="section-body">
                <div className="card">
                  <div className="card-body">
                    <div className="d-flex justify-content-end">
                      <div className="me-2">
                        <input
                          type="text"
                          className="form-control"
                          placeholder="Search by name..."
                          value={searchTerm}
                          onChange={(e) => setSearchTerm(e.target.value)}
                          style={{
                            backgroundColor: "pink",
                            paddingLeft: "10px",
                          }}
                        />
                      </div>
                      <div className="me-2">
                        <input
                          type="date"
                          className="form-control"
                          value={startDate}
                          onChange={(e) => setStartDate(e.target.value)}
                          style={{
                            backgroundColor: "pink",
                          }}
                        />
                      </div>
                      <div className="me-2">
                        <input
                          type="date"
                          className="form-control"
                          value={endDate}
                          onChange={(e) => setEndDate(e.target.value)}
                          style={{
                            backgroundColor: "pink",
                          }}
                        />
                      </div>
                      <div className="jus">
                        <Link
                          to="/subcategoryadd"
                          className="btn btn-light"
                          style={{ backgroundColor: "pink" }}
                        >
                          Add
                        </Link>
                      </div>
                    </div>
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
                                <td>{(currentPage - 1) * limit + index + 1}</td>
                                <td>
                                  {service.cat_id?.name
                                    ? service.cat_id.name
                                    : "No Category"}
                                </td>
                                <td>{service.name || "no sub category"}</td>
                                <td>${service.price || "no price"}</td>
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
                              <td colSpan="7">No Sub Category found</td>
                            </tr>
                          )}
                        </tbody>
                      </table>
                    </div>
                    <Stack spacing={2} className="d-flex justify-content-center mt-3">
                  <Pagination count={totalPages} page={currentPage} onChange={handlePageChange} color="primary" />
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

export default SubCategoryList;
