import React, { useState, useEffect } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";
import { ToastContainer, toast } from "react-toastify";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faPenNib } from "@fortawesome/free-solid-svg-icons";
import { BASE_URL } from "../Config";

const Profile = () => {
  const [data, setData] = useState({
    name: "",
    email: "",
    phone_no: "",
    address: "",
    image: "",
  });
  const [imagePreview, setImagePreview] = useState(null);
  const [selectedImage, setSelectedImage] = useState(null);
  const [errors, setErrors] = useState({});
  const navigate = useNavigate();

  useEffect(() => {
    const fetchProfileData = async () => {
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
          setData(response.data.body);
          const imageUrl = response.data.body.image.startsWith("http")
            ? response.data.body.image
            : `${BASE_URL}/${response.data.body.image}`;
          setImagePreview(imageUrl);
        }
      } catch (error) {
        console.error("Error fetching profile data", error);
        toast.error("Error fetching profile data");
      }
    };

    fetchProfileData();
  }, []);

  const handleImageChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      setSelectedImage(file);
      setImagePreview(URL.createObjectURL(file));
    }
  };

  const validateForm = () => {
    let formErrors = {};
    if (!data.name) formErrors.name = "Name is required";
    if (!data.phone_no) formErrors.phone_no = "Phone number is required";
    if (!data.address) formErrors.address = "Address is required";
    return formErrors;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const formErrors = validateForm();
    if (Object.keys(formErrors).length > 0) {
      setErrors(formErrors);
      return;
    }

    const token = localStorage.getItem("token");
    if (!token) {
      console.error("No token found in localStorage");
      return;
    }

    const formData = new FormData();
    formData.append("name", data.name);
    formData.append("email", data.email);
    formData.append("phone_no", data.phone_no);
    formData.append("address", data.address);
    if (selectedImage) {
      formData.append("image", selectedImage);
    }

    try {
      await axios.post(`${BASE_URL}/profileupdate`, formData, {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "multipart/form-data",
        },
      });
      toast.success("Profile updated successfully");
      navigate("/profile");
    } catch (error) {
      console.error("Error updating profile", error);
      toast.error("Error updating profile");
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
      <div className="container-fluid ">
        <div className="row">
          <div className="col-12">
            <div className="card my-4">
              <div className="card-header p-0 position-relative mt-n4 mx-3 z-index-2">
                <div className="bg-gradient-primary shadow-primary border-radius-lg pt-4 pb-3">
                  <h6 className="text-white text-capitalize ps-3">Profile</h6>
                </div>
              </div>
              <form
                onSubmit={handleSubmit}
                className="form-validate"
                noValidate
                encType="multipart/form-data"
              >
                <div className="row">
                  <div className="col-md-12">
                    <div className="card">
                      <div className="card-body py-4">
                        <div className="tab-content">
                          <div
                            className="tab-pane active"
                            id="account"
                            aria-labelledby="account-tab"
                            role="tabpanel"
                          >
                            <div
                              style={{
                                display: "flex",
                                alignItems: "flex-start",
                              }}
                            >
                              <div
                                style={{
                                  flex: "0 0 auto",
                                  position: "relative",
                                }}
                              >
                                {imagePreview && (
                                  <>
                                    <img
                                      src={imagePreview}
                                      alt="Preview"
                                      style={{
                                        marginTop: "10px",
                                        marginBottom: "20px",
                                        width: "300px",
                                        height: "300px",
                                        objectFit: "cover",
                                        borderRadius: "20px",
                                      }}
                                    />
                                    <label
                                      htmlFor="image"
                                      style={{
                                        position: "absolute",
                                        bottom: "15px",
                                        right: "10px",
                                        cursor: "pointer",
                                        backgroundColor:
                                          "rgba(255, 255, 255, 0.7)", 
                                        borderRadius: "10%", 
                                        padding: "5px",
                                      }}
                                    >
                                      <FontAwesomeIcon
                                        icon={faPenNib}
                                        size="lg"
                                        color="red"
                                      />
                                    </label>
                                  </>
                                )}
                                <input
                                  type="file"
                                  style={{ display: "none" }}
                                  id="image"
                                  onChange={handleImageChange}
                                />
                              </div>

                              <div style={{ flex: "1", marginLeft: "16px" }}>
                                {["name", "phone_no"].map((field, index) => (
                                  <div
                                    key={index}
                                    style={{ marginBottom: "16px" }}
                                  >
                                    <label
                                      style={{
                                        display: "block",
                                        marginBottom: "8px",
                                      }}
                                      htmlFor={field}
                                    >
                                      {field.charAt(0).toUpperCase() +
                                        field.slice(1).replace("_", " ")}
                                    </label>
                                    <input
                                      type={
                                        field === "email" ? "email" : "text"
                                      }
                                      required
                                      style={{
                                        width: "100%",
                                        padding: "8px",
                                        borderRadius: "4px",
                                        border: "1px solid #ced4da",
                                        backgroundColor: "lightpink",
                                      }}
                                      placeholder={
                                        field.charAt(0).toUpperCase() +
                                        field.slice(1).replace("_", " ")
                                      }
                                      name={field}
                                      id={field}
                                      value={data[field]}
                                      onChange={(e) =>
                                        setData((prevData) => ({
                                          ...prevData,
                                          [field]: e.target.value,
                                        }))
                                      }
                                    />
                                    {errors[field] && (
                                      <p style={{ color: "red" }}>
                                        {errors[field]}
                                      </p>
                                    )}
                                  </div>
                                ))}
                                <div style={{ marginBottom: "16px" }}>
                                  <label
                                    style={{
                                      display: "block",
                                      marginBottom: "8px",
                                    }}
                                    htmlFor="email"
                                  >
                                    Email
                                  </label>
                                  <input
                                    type="email"
                                    required
                                    readOnly
                                    style={{
                                      width: "100%",
                                      padding: "8px",
                                      borderRadius: "4px",
                                      border: "1px solid #ced4da",
                                      backgroundColor: "lightgrey",
                                    }}
                                    placeholder="Email"
                                    name="email"
                                    id="email"
                                    value={data.email}
                                  />
                                </div>

                                <div
                                  style={{
                                    display: "flex",
                                    justifyContent: "flex-end",
                                    marginTop: "16px",
                                  }}
                                >
                                  <button
                                    type="submit"
                                    className="btn"
                                    style={{
                                      backgroundColor: "#D81B60",
                                      color: "white",
                                    }}
                                  >
                                    Update
                                  </button>
                                </div>
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </form>
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

export default Profile;
