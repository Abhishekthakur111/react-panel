import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import axios from 'axios';
import { BASE_URL } from '../Config';
import { toast, ToastContainer } from 'react-toastify';

const CategoryEdit = () => {
  const { _id } = useParams();
  const [data, setData] = useState({ name: '', image: '' });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const navigate = useNavigate();
  const [newImage, setNewImage] = useState(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await axios.get(`${BASE_URL}/viewcategory/${_id}`);
        if (response.data.success) {
          setData(response.data.body);
        } else {
          setError("Failed to fetch category data.");
        }
      } catch (err) {
        setError("Error fetching category data.");
        console.error("Error fetching category:", err);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [_id]);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setData((prevData) => ({
      ...prevData,
      [name]: value,
    }));
  };

  const handleImageChange = (e) => {
    setNewImage(e.target.files[0]);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const formData = new FormData();
    formData.append('name', data.name);
    if (newImage) {
      formData.append('image', newImage);
    }

    try {
      const response = await axios.post(`${BASE_URL}/updatecategory/${_id}`, formData);
      if (response.data.success) {
        toast.success('Category updated successfully');
        navigate('/categorylist'); 
      } else {
        setError("Failed to update category.");
      }
    } catch (err) {
      setError("Error updating category.");
      console.error("Error updating category:", err);
    }
  };

  const handleBack = () => {
    navigate('/categorylist');
  };

  if (loading) return <div>Loading...</div>;
  if (error) return <div>{error}</div>;

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
                <div className="bg-gradient-primary shadow-primary border-radius-lg pt-3 pb-3">
                  <h6 className="text-white text-capitalize ps-3">Edit Category</h6>
                </div>
              </div>
              <div className="section-body">
                <div className="row">
                  <div className="col-12 col-md-12 col-lg-12">
                    <div className="card">
                      <div className="card-body">
                        <form onSubmit={handleSubmit}>
                          <div className="form-group mx-auto text-center">
                            {data.image && (
                              <div className="image-container">
                                <img
                                  src={data.image.startsWith("http") ? data.image : `${BASE_URL}${data.image}`}
                                  alt="Category"
                                  style={{
                                    width: "200px",
                                    height: "200px",
                                    objectFit: "cover",
                                    borderRadius: "20%",
                                  }}
                                />
                              </div>
                            )}
                            <input
                              type="file"
                              className="form-control mt-3"
                              onChange={handleImageChange}
                              style={{ paddingLeft: '500px' }}
                            />
                          </div>
                          <div className="form-group mt-3">
                            <label>Name</label>
                            <input
                              type="text"
                              name="name"
                              className="form-control"
                              value={data.name || ""}
                              onChange={handleChange}
                              style={{ paddingLeft: '10px', backgroundColor: 'lightpink' }}
                            />
                          </div>
                          <div className="text-right mt-4">
                            <button 
                              type="button" 
                              className="btn btn-secondary" 
                              style={{ marginRight: '10px' }} 
                              onClick={handleBack} 
                            >
                              Back
                            </button>
                            <button type="submit" className="btn btn-success">
                              Update
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
