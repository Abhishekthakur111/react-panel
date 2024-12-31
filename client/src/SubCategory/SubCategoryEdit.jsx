import React, { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { axiosInstance, BASE_URL } from "../Config";
import { toast, ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";

const SubCategoryEdit = () => {
  const { _id } = useParams();
  const [subcategory, setSubcategory] = useState({});
  const [categories, setCategories] = useState([]);
  const [imagePreview, setImagePreview] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchSubcategoryData = async () => {
      try {
        const response = await axiosInstance.get(`/editget/${_id}`);
        if (response.data.success) {
          setSubcategory(response.data.body);
          setImagePreview(
            response.data.body.image
              ? `${BASE_URL}/${response.data.body.image}`
              : null
          );
        } else {
          setError("Failed to fetch subcategory data.");
        }

        const categoryResponse = await axiosInstance.get(`/categorylist`);
        if (categoryResponse.data.success) {
          const activeCategories = categoryResponse.data.body.data.filter(
            (category) => category.status == 0
          );
          setCategories(activeCategories);
        } else {
          setError("Failed to fetch categories.");
        }
      } catch (err) {
        setError("Error fetching data.");
      } finally {
        setLoading(false);
      }
    };

    fetchSubcategoryData();
  }, [_id]);

  const handleChange = (e) => {
    const { name, value, files } = e.target;
    if (name === "name" && !/^[A-Za-z\s]*$/.test(value)) {
      toast.error("Name should only contain alphabetic characters.");
      return;
    }
    if (name === "image" && files.length > 0) {
      const file = files[0];
      if (!file.type.startsWith("image/")) {
        toast.error("Please select a valid image file.");
        return;
      }
      setSubcategory((prevData) => ({
        ...prevData,
        [name]: file,
      }));
      setImagePreview(URL.createObjectURL(file));
    } else {
      setSubcategory((prevData) => ({
        ...prevData,
        [name]: value,
      }));
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!subcategory.cat_id || !subcategory.name || !subcategory.price) {
      toast.error("Please fill in all required fields.");
      return;
    }
    const selectedCategory = categories.find(
      (category) => category._id === subcategory.cat_id
    );
    
    if (!selectedCategory || selectedCategory.status == 1) {
      toast.error("Cannot update with an inactive category.");
      return;
    }
    const formData = new FormData();
    formData.append("cat_id", subcategory.cat_id);
    formData.append("name", subcategory.name);
    formData.append("price", subcategory.price);
    if (subcategory.image) {
      formData.append("image", subcategory.image);
    }
    try {
      const response = await axiosInstance.post(
        `/updatesubcategory/${_id}`,
        formData,
        {
          headers: {
            "Content-Type": "multipart/form-data",
          },
        }
      );
      if (response.data.success) {
        toast.success("Subcategory updated successfully!");
        setTimeout(() => {
          navigate("/subcategory");
        }, 1000);
      } else {
        toast.error(
          `Update failed: ${response.data.message || "Unknown error"}`
        );
      }
    } catch (error) {
      toast.error(`Request failed: ${error.message}`);
    }
  };
  

  if (loading) return <div>Loading...</div>;
  if (error) return <div>{error}</div>;

  const selectedCategory = categories.find(
    (category) => category._id === subcategory.cat_id
  );

  return (
    <>
      <ToastContainer
        position="top-right"
        autoClose={5000}
        hideProgressBar={false}
      />
      <div className="container-fluid">
        <div className="row">
          <div className="col-12">
            <div className="card my-4">
              <div className="card-header p-0 position-relative mt-n4 mx-3 z-index-2">
                <div className="bg-gradient-primary shadow-primary border-radius-lg pt-4 pb-3">
                  <h6 className="text-white text-capitalize ps-3">
                    Edit Sub Category
                  </h6>
                </div>
              </div>
              <form onSubmit={handleSubmit}>
                <div className="card-body">
                  <div className="form-group col-3 mx-auto">
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
                        style={{
                          paddingLeft: "10px",
                          backgroundColor: "lightpink",
                        }}
                      />
                    </div>
                  </div>

                  <div className="form-group mb-2">
                    <label htmlFor="cat_id">Category</label>
                    <select
                      name="cat_id"
                      className="form-control"
                      required
                      value={subcategory.cat_id || "no category"}
                      onChange={handleChange}
                      style={{
                        paddingLeft: "10px",
                        backgroundColor: "lightpink",
                      }}
                    >
                      {categories.map((category) => (
                        <option key={category._id} value={category._id}>
                          {category.name}
                        </option>
                      ))}
                      {!categories.some(
                        (category) => category._id === subcategory.cat_id
                      ) &&
                        subcategory.cat_id && (
                          <option value={subcategory.cat_id}>
                            {selectedCategory?.name || "Inactive Category"}
                          </option>
                        )}
                    </select>
                  </div>

                  <div className="form-group mb-2">
                    <label htmlFor="name">Subcategory Name</label>
                    <input
                      type="text"
                      className="form-control"
                      required
                      name="name"
                      value={subcategory.name || ""}
                      onChange={handleChange}
                      style={{
                        paddingLeft: "10px",
                        backgroundColor: "lightpink",
                      }}
                    />
                  </div>

                  <div className="form-group mb-2">
                    <label htmlFor="price">Price</label>
                    <input
                      type="number"
                      className="form-control"
                      required
                      name="price"
                      value={subcategory.price || ""}
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
                    Update
                  </button>
                  <button
                    type="button"
                    className="btn btn-primary"
                    onClick={() => navigate("/subcategory")}
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

export default SubCategoryEdit;
