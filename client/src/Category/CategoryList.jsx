import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import Swal from "sweetalert2";
import { ToastContainer, toast } from "react-toastify";
import { axiosInstance, BASE_URL } from "../Config";
import Pagination from "@mui/material/Pagination";
import Stack from "@mui/material/Stack";

const CategoryList = () => {
  const [categories, setCategories] = useState([]);
  const [searchTerm, setSearchTerm] = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const limit = 10;
  
  useEffect(() => {
    fetchData(currentPage);
  }, [currentPage]);

  const fetchData = async (page) => {
    try {
      const response = await axiosInstance.get(`/categorylist?page=${page}&limit=${limit}`);
      if (response.data.success) {
        setCategories(response.data.body.data);
        setTotalPages(response.data.body.totalPages);
      } else {
        Swal.fire("Error", response.data.message || "Failed to load categories", "error");
      }
    } catch (error) {
      Swal.fire("Error", "An error occurred while fetching the category list", "error");
    }
  };

  const handlePageChange = (event, value) => {
    setCurrentPage(value);
  };

  const deleteCategory = async (_id) => {
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
        await axiosInstance.delete(`/deletecategory/${_id}`);
        const response = await axiosInstance.get(`/categorylist?page=${currentPage}&limit=${limit}`);
        if (response.data.success) {
          setCategories(response.data.body.data);
          const newTotalPages = response.data.body.totalPages;
          if (currentPage > newTotalPages) {
            setCurrentPage(newTotalPages || 1);
          }
          setTotalPages(newTotalPages);
        }
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

  const toggleStatus = async (id, currentStatus) => {
    const newStatus = currentStatus === "0" ? "1" : "0";
  
    try {
      const response = await axiosInstance.post(`/categorystatus`, {
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
      toast.error("An error occurred while changing category status");
    }
  };
  
  
  const filteredCategories = categories.filter((category) =>
    category.name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <>
      <ToastContainer
        position="top-right"
        autoClose={1000}
        hideProgressBar={false}
      />
      <div className="container-fluid">
        <div className="row">
          <div className="col-12">
            <div className="card my-4">
              <div className="card-header p-0 position-relative mt-n4 mx-3 z-index-2">
                <div className="bg-gradient-primary shadow-primary border-radius-lg pt-2 pb-2">
                  <div className="d-flex justify-content-between align-items-center px-3 pt-1">
                    <h6 className="text-white text-capitalize">Categories</h6>
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
                      <div className="">
                        <Link
                          to="/categoryadd"
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
                            <th>Name</th>
                            <th>Image</th>
                            <th>Status</th>
                            <th>Action</th>
                          </tr>
                        </thead>
                        <tbody>
                          {filteredCategories.map((category, index) => (
                            <tr key={category._id}>
                              <td>{(currentPage - 1) * limit + index + 1}</td>
                              <td>{category.name || "no category"}</td>
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
                                  className="btn btn-success m-1"
                                  style={{
                                    backgroundColor: "#D81B60",
                                    color: "white",
                                  }}
                                >
                                  <i className="fas fa-eye" />
                                </Link>
                                <Link
                                  to={`/updatecategory/${category._id}`}
                                  className="btn btn-success m-1"
                                  style={{
                                    backgroundColor: "#D81B60",
                                    color: "white",
                                  }}
                                >
                                  <i className="fas fa-edit" />
                                </Link>
                                <button
                                  onClick={() => deleteCategory(category._id)}
                                  className="btn m-1"
                                  style={{
                                    backgroundColor: "#D81B60",
                                    borderColor: "#D81B60",
                                    color: "#fff",
                                  }}
                                >
                                  <i className="fas fa-trash" />
                                </button>
                              </td>
                            </tr>
                          ))}
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

export default CategoryList;
