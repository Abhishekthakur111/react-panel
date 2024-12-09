import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import axios from 'axios';
import { BASE_URL } from '../Config';



const SubCategoryView = () => {
  const { _id } = useParams();
  const [service, setService] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    async function fetchService() {
      try {
        const response = await axios.get(`${BASE_URL}/service/${_id}`);
        console.log(response,'//////////');
        if (response.data.success) {
          setService(response.data.body);
        } else {
          setError("Failed to fetch service data.");
        }
      } catch (err) {
        setError("Error fetching service data.");
        console.error("Error fetching service:", err);
      } finally {
        setLoading(false);
      }
    }

    fetchService();
  }, [_id]);

  if (loading) return <div>Loading...</div>;
  if (error) return <div>{error}</div>;

  return (
    <div className="container-fluid ">
      <div className="row">
        <div className="col-12">
          <div className="card my-4">
            <div className="card-header p-0 position-relative mt-n4 mx-3 z-index-2">
              <div className="bg-gradient-primary shadow-primary border-radius-lg pt-4 pb-3">
                <h6 className="text-white text-capitalize ps-3"> Detail</h6>
              </div>
            </div>
            <div className="section-body">
              <div className="row">
                <div className="col-12 col-md-12 col-lg-12">
                  <div className="card">
                    <div className="card-body">
                      <div className="form-group mx-auto">
                        {service.image ? (
                          <div className="image-container">
                            <img
                              src={`${BASE_URL}/${service.image}`}
                              alt={service.name}
                              style={{
                                marginLeft: "auto",
                                marginRight: "auto",
                                width: "200px",
                                height: "200px",
                                objectFit: "cover",
                                borderRadius: "50%",
                                display: "block",
                              }}
                            />
                          </div>
                        ) : (
                          <p>No image available</p>
                        )}
                      </div>
                      <div className="form-group mb-2">
                        <label>Category</label>
                        <input
                          type="text"
                          id="category"
                          className="form-control"
                          value={service.cat_id?.name || "Unknown"}
                          readOnly
                          style={{ paddingLeft: '10px', backgroundColor: 'lightpink' }}
                        />
                      </div>
                      <div className="form-group mb-2">
                        <label>Name</label>
                        <input
                          type="text"
                          className="form-control"
                          id="name"
                          value={service.name || ""}
                          readOnly
                          style={{ paddingLeft: '10px', backgroundColor: 'lightpink' }}
                        />
                      </div>
                     
                      <div className="form-group">
                        <label>Price</label>
                        <input
                          type="text"
                          id="price"
                          className="form-control"
                          value={`$${service.price || "N/A"}`}
                          readOnly
                          style={{ paddingLeft: '10px', backgroundColor: 'lightpink' }}
                        />
                      </div>
                    </div>
                    <div className="text-end mx-4 ">
                      <button
                        type="button"
                        className="btn btn-primary"
                        onClick={() => navigate("/subcategory")}
                      >
                        Back
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
  );
};

export default SubCategoryView;
