import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import { toast, ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import { BASE_URL } from "../Config";

const AddCategory = () => {
  const [data, setData] = useState({
    name: "",
    image: null,
  });
  const [imagePreview, setImagePreview] = useState(null);
  const navigate = useNavigate();

  const handleChange = (e) => {
    const { id, value, files } = e.target;
    if (id === "image" && files.length > 0) {
      setData((prevData) => ({
        ...prevData,
        [id]: files[0],
      }));
      setImagePreview(URL.createObjectURL(files[0]));
    } else {
      setData((prevData) => ({
        ...prevData,
        [id]: value,
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

    const formData = new FormData();
    if (data.image) {
      formData.append("image", data.image);
    }
    formData.append("name", data.name);

    try {
      const response = await axios.post(
        `${BASE_URL}/createcategory`,
        formData,
        {
          headers: {
            "Content-Type": "multipart/form-data",
          },
        }
      );

      if (response.status === 200 && response.data.success) {
        toast.success("Category added successfully!");
        navigate("/categorylist");
      } else {
        toast.error("Category creation failed: " + response.data.message);
      }
    } catch (error) {
      console.error("Error:", error);
      toast.error("Request failed: " + error.message);
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
      <div className="container-fluid">
        <div className="row">
          <div className="col-12">
            <div className="card my-4">
              <div className="card-header p-0 position-relative mt-n4 mx-3 z-index-2">
                <div className="bg-gradient-primary shadow-primary border-radius-lg pt-4 pb-3">
                  <div className="d-flex justify-content-between align-items-center px-3">
                    <h6 className="text-white text-capitalize">
                      Add New Category
                    </h6>
                  </div>
                </div>
              </div>
              <form onSubmit={handleSubmit}>
                <div className="card-body">
                  <div className="form-group col-3 mb-2 mx-auto bg-lightpink">
                    <div className="admin_profile mt-2" data-aspect="1/1">
                      {imagePreview && (
                        <img
                          src={imagePreview}
                          alt="Preview"
                          style={{
                            borderRadius: "10px",
                            width: "330px",
                            height: "200px",
                            marginBottom: "5px",
                          }}
                        />
                      )}
                      <input
                        type="file"
                        id="image"
                        className="form-control"
                        onChange={handleChange}
                        style={{
                          paddingLeft: "10px",
                          backgroundColor: "lightpink",
                        }}
                      />
                    </div>
                  </div>
                  <div className="form-group">
                    <label htmlFor="name">Category Name</label>
                    <input
                      type="text"
                      className="form-control"
                      id="name"
                      value={data.name}
                      onChange={handleChange}
                      style={{
                        paddingLeft: "10px",
                        backgroundColor: "lightpink",
                      }}
                    />
                  </div>
                </div>
                <div className="mx-4 text-end">
                  <button
                    type="submit"
                    className="btn btn-primary"
                    style={{ marginRight: "10px" }}
                  >
                    Add
                  </button>
                  <button
                    type="button"
                    className="btn btn-primary"
                    onClick={() => navigate("/categorylist")}
                  >
                    Back
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

export default AddCategory;
