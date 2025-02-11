import React, { useEffect, useState } from "react";
import Swal from "sweetalert2";
import { useSelector, useDispatch } from "react-redux";
import { fetchUsers, deleteUser, toggleUserStatus } from "../redux/UserSlice";
import { toast, ToastContainer } from "react-toastify";
import { Link } from "react-router-dom";
import { BASE_URL } from "../Config";
import "@fortawesome/fontawesome-free/css/all.min.css";

const UserList = () => {
  const [searchTerm, setSearchTerm] = useState("");

  const dispatch = useDispatch();
  const { users } = useSelector((state) => state.users);

  useEffect(() => {
    dispatch(fetchUsers());
  }, [dispatch]);

  const deleteUserHandler = async (_id) => {
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
        dispatch(deleteUser(_id));
        Swal.fire("Deleted!", "User has been deleted.", "success");
      } catch (error) {
        Swal.fire(
          "Error!",
          error.response?.data?.message || "Error deleting user",
          "error"
        );
      }
    } else {
      Swal.fire("Cancelled", "User deletion has been cancelled", "info");
    }
  };

  const toggleStatus = async (id, currentStatus) => {
    dispatch(toggleUserStatus({ id, currentStatus }));
    toast.success("Status updated successfully");
  };
  

  const filteredUsers = users.filter((user) =>
    user.name.toLowerCase().includes(searchTerm.toLowerCase())
  );

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
                    <h6 className="text-white text-capitalize">Users</h6>
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
                          style={{ backgroundColor: "pink", paddingLeft: "10px" }}
                        />
                      </div>
                    </div>
                    <div className="table-responsive">
                      <table className="table text-center">
                        <thead>
                          <tr>
                            <th>Sr_No.</th>
                            <th>Image</th>
                            <th>Name</th>
                            <th>Email</th>
                            <th>Address</th>
                            <th>Phone No</th>
                            <th>Status</th>
                            <th>Action</th>
                          </tr>
                        </thead>
                        <tbody>
                          {filteredUsers.map((user, index) => (
                            <tr key={user._id}>
                              <td>{index + 1}</td>
                              <td>
                                {user.image ? (
                                  <img
                                    src={`${BASE_URL}/${user.image}`}
                                    alt={user.image}
                                    style={{ width: "50px", height: "50px", borderRadius: "50%" }}
                                  />
                                ) : (
                                  "No Image"
                                )}
                              </td>
                              <td>{user.name || "no user"}</td>
                              <td>{user.email || "no email"}</td>
                              <td>{user.address || "no address"}</td>
                              <td>{user.phone_no || "no phone number"}</td>
                              <td>
                                <div className="form-check form-switch d-flex align-items-center justify-content-center">
                                  <input
                                    className="form-check-input"
                                    type="checkbox"
                                    id={`toggleStatus${user._id}`}
                                    checked={user.status === "0"}
                                    onChange={() => toggleStatus(user._id, user.status)}
                                    style={{
                                      backgroundColor: user.status === "0" ? "#D81B60" : "lightgray",
                                      borderColor: user.status === "0" ? "#D81B60" : "lightgray",
                                    }}
                                  />
                                </div>
                              </td>
                              <td>
                                <Link
                                  to={`/viewuser/${user._id}`}
                                  className="has-icon btn btn-success m-1"
                                  style={{ backgroundColor: "#D81B60", color: "white" }}
                                >
                                  <i className="me-100 fas fa-eye" />
                                </Link>
                                <button
                                  onClick={() => deleteUserHandler(user._id)}
                                  className="has-icon btn m-1"
                                  style={{ backgroundColor: "#D81B60", borderColor: "#D81B60", color: "#fff" }}
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
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

export default UserList;