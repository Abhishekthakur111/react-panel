import React, { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { axiosInstance, BASE_URL } from "../Config";
import { toast, ToastContainer } from "react-toastify";

const CategoryEdit = () => {
  const { _id } = useParams();
  const [data, setData] = useState({ name: "", image: "" });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [imagePreview, setImagePreview] = useState(null);
  const navigate = useNavigate();
  const [newImage, setNewImage] = useState(null);
  const [nameError, setNameError] = useState("");
  const [imageError, setImageError] = useState("");

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await axiosInstance.get(`/viewcategory/${_id}`);
        if (response.data.success) {
          setData(response.data.body);
          setImagePreview(
            response.data.body.image
              ? `${BASE_URL}/${response.data.body.image}`
              : null
          );
        } else {
          setError("Failed to fetch category data.");
        }
      } catch (err) {
        setError("Error fetching category data.");
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [_id]);

  const handleChange = (e) => {
    const { name, value, files } = e.target;

    if (name === "name") {
      const nameRegex = /^[a-zA-Z\s]*$/;
      if (!nameRegex.test(value)) {
        setNameError(
          "Name must contain only alphabetic characters and spaces."
        );
      } else {
        setNameError("");
      }
    }

    if (name === "image" && files.length > 0) {
      const file = files[0];
      const validFormats = ["image/jpeg", "image/png"];

      if (!validFormats.includes(file.type)) {
        toast.error("Only JPG and PNG files are allowed.");
        return;
      }

      setNewImage(file);
      setImagePreview(URL.createObjectURL(file));
    } else {
      setData((prevData) => ({
        ...prevData,
        [name]: value,
      }));
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
      if (!data.image) {
         toast.error("Category image is required!");
         return;
       }
       if (!data.name.trim()) {
         toast.error("Category name is required!");
         return;
       }
       if (nameError) {
         toast.error("Please fix the name error before submitting!");
         return;
       }
       if (imageError) {
         toast.error("Please fix the image error before submitting!");
         return;
       }

    const formData = new FormData();
    formData.append("name", data.name);
    if (newImage) {
      formData.append("image", newImage);
    }

    try {
      const response = await axiosInstance.post(
        `/updatecategory/${_id}`,
        formData
      );
      if (response.data.success) {
        toast.success("Category updated successfully");
        setTimeout(() => {
          navigate("/categorylist");
        }, 1000);
      } else {
        setError("Failed to update category.");
      }
    } catch (err) {
      setError("Error updating category.");
    }
  };

  const handleBack = () => {
    navigate("/categorylist");
  };

  if (loading) return <div>Loading...</div>;
  if (error) return <div>{error}</div>;

  return (
    <>
      <ToastContainer position="top-right" autoClose={5000} hideProgressBar={false} />
      <div className="container-fluid">
        <div className="row">
          <div className="col-12">
            <div className="card my-4">
              <div className="card-header p-0 position-relative mt-n4 mx-3 z-index-2">
                <div className="bg-gradient-primary shadow-primary border-radius-lg pt-2 pb-2">
                  <div className="d-flex justify-content-between align-items-center px-3 pt-1">
                    <h6 className="text-white text-capitalize">Edit Category</h6>
                  </div>
                </div>
              </div>
              <div className="section-body">
                <div className="row">
                  <div className="col-12 col-md-12 col-lg-12">
                    <div className="card">
                      <div className="card-body">
                        <form onSubmit={handleSubmit}>
                          <div className="form-group col-3">
                            <div className="admin_profile" data-aspect="1/1">
                              {imagePreview && (
                                <img
                                  src={imagePreview}
                                  alt="Preview"
                                  style={{
                                    borderRadius: "10px",
                                    width: "290px",
                                    height: "200px",
                                    marginBottom: "5px",
                                  }}
                                />
                              )}
                              <input
                                type="file"
                                name="image"
                                className="form-control"
                                onChange={handleChange}
                                accept="image/jpeg, image/png"
                                style={{
                                  paddingLeft: "10px",
                                  backgroundColor: "lightpink",
                                }}
                              />
                            </div>
                          </div>
                          <div className="form-group mt-3">
                            <label>Name</label>
                            <input
                              type="text"
                              name="name"
                              className="form-control"
                              value={data.name || ""}
                              onChange={handleChange}
                              style={{
                                paddingLeft: "10px",
                                backgroundColor: "lightpink",
                              }}
                            />
                            {nameError && (
                              <div style={{ color: "red", fontSize: "12px" }}>
                                {nameError}
                              </div>
                            )}
                          </div>
                          <div className="text-end mt-4">
                            <button
                              type="submit"
                              className="btn btn-primary"
                              style={{ marginRight: "10px" }}
                              disabled={nameError}
                            >
                              Update
                            </button>
                            <button
                              type="button"
                              className="btn btn-primary"
                              onClick={handleBack}
                            >
                              Back
                            </button>
                          </div>
                        </form>
                      </div>
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

export default CategoryEdit;
