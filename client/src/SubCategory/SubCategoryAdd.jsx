import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { toast, ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import { BASE_URL } from '../Config';


const SubCategoryAdd = () => {
  const [data, setData] = useState({
    cat_id: '',
    name: '',
    price: '',
    image: null,
  });
  const [categories, setCategories] = useState([]); 
  const [imagePreview, setImagePreview] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    return () => {
      if (imagePreview) {
        URL.revokeObjectURL(imagePreview);
      }
    };
  }, [imagePreview]);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const response = await axios.get(`${BASE_URL}/catergeorylist`, {
      });
      if (response.data.success) {
        setCategories(response.data.body.data);
      } 
    } catch (error) {
      console.error("Error fetching category list", error);
     
    }
  };

  const handleChange = (e) => {
    const { name, value, files } = e.target;
    if (name === 'image' && files.length > 0) {
      const file = files[0];
      if (!file.type.startsWith('image/')) {
        toast.error('Please select a valid image file.');
        return;
      }
      setData((prevData) => ({
        ...prevData,
        [name]: file,
      }));
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
    const formData = new FormData();
    formData.append('cat_id', data.cat_id); 
    formData.append('name', data.name);
    formData.append('price', data.price);
    if (data.image) {
      formData.append('image', data.image);
    }

    try {
      const response = await axios.post(`${BASE_URL}/createservice`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });

      if (response.data.success) {
        setData({
          cat_id: '',
          name: '',
          price: '',
          image: null,
        });
        setImagePreview(null);
        toast.success('Service added successfully!');
        navigate('/services');
      } else {
        toast.error(`Service creation failed: ${response.data.message}`);
      }
    } catch (error) {
      toast.error(`Request failed: ${error.message}`);
    }
  };

  return (
    <>
      <ToastContainer position="top-right" autoClose={5000} hideProgressBar={false} />
      <div className="container-fluid">
        <div className="row">
          <div className="col-12">
            <div className="card my-4">
              <div className="card-header p-0 position-relative mt-n4 mx-3 z-index-2">
                <div className="bg-gradient-primary shadow-primary border-radius-lg pt-4 pb-3">
                  <div className="d-flex justify-content-between align-items-center px-3">
                    <h6 className="text-white text-capitalize">Add New Sub Category</h6>
                  </div>
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
                            borderRadius:'10px',
                           width: '330px',
                           height: '200px',
                           marginBottom:'5px'
                         }}
                        />
                      )}
                      <input
                        type="file"
                        name="image"
                        className="form-control"
                        onChange={handleChange}
                        style={{ paddingLeft: '10px', backgroundColor: 'lightpink' }}
                      />
                    </div>
                  </div>

                  <div className="form-group mb-2">
                    <label htmlFor="cat_id">Category</label>
                    <select
                      name="cat_id"
                      className="form-control"
                      required
                      value={data.cat_id}
                      onChange={handleChange}
                      style={{ paddingLeft: '10px', backgroundColor: 'lightpink' }}
                    >
                      <option value="">Select Category</option>
                      {categories.map((category) => (
                        <option key={category._id} value={category._id}>
                          {category.name}
                        </option>
                      ))}
                    </select>
                  </div>

                  <div className="form-group mb-2">
                    <label htmlFor="name">Subcategory Name</label>
                    <input
                      type="text"
                      className="form-control"
                      required
                      name="name"
                      value={data.name}
                      onChange={handleChange}
                      style={{ paddingLeft: '10px', backgroundColor: 'lightpink' }}
                    />
                  </div>

                  <div className="form-group mb-2">
                    <label htmlFor="price">Price</label>
                    <input
                      type="number"
                      className="form-control"
                      required
                      name="price"
                      value={data.price}
                      onChange={handleChange}
                      style={{ paddingLeft: '10px', backgroundColor: 'lightpink' }}
                    />
                  </div>
                </div>

                <div className="mx-4 text-right">
                  <button
                    type="button"
                    className="btn btn-primary"
                    onClick={() => navigate(-1)}
                    style={{ marginRight: '10px' }}
                  >
                    Back
                  </button>
                  <button type="submit" className="btn btn-primary">
                    Add
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

export default SubCategoryAdd;
