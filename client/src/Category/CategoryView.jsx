import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import axios from 'axios';
import { BASE_URL } from '../Config';



const CategoryView = () => {
  const { _id } = useParams();
  const [data, setData] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const navigate = useNavigate();
  
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

  if (loading) return <div>Loading...</div>;
  if (error) return <div>{error}</div>;

  return (
    <div className="container-fluid ">
      <div className="row">
        <div className="col-12">
          <div className="card my-4">
            <div className="card-header p-0 position-relative mt-n4 mx-3 z-index-2">
              <div className="bg-gradient-primary shadow-primary border-radius-lg pt-3 pb-3">
                <h6 className="text-white text-capitalize ps-3"> Detail</h6>
              </div>
            </div>
            <div className="section-body">
              <div className="row">
                <div className="col-12 col-md-12 col-lg-12">
                  <div className="card">
                    <div className="card-body">
                      <div className="form-group mx-auto">
                        {data.image && (
                          <div className="image-container text-center">
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
                      </div>
                      <div className="form-group ">
                        <label>Name</label>
                        <input
                          type="text"
                          className="form-control"
                          value={data.name || ""}
                          readOnly
                          style={{ paddingLeft: '10px', backgroundColor: 'lightpink' }}
                        />
                      </div>
                      

                    </div>
                    <div className="text-end mx-4">
                      <button
                        type="button"
                        className="btn btn-primary"
                        onClick={() => navigate("/categorylist")}
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

export default CategoryView;
