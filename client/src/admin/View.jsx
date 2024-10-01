import React, { useState, useEffect } from "react";
import axios from "axios";
import { useParams, useNavigate } from "react-router-dom";

const BASE_URL = "http://localhost:8000";

function View() {
  const { _id } = useParams();
  const [data, setData] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    async function fetchData() {
      try {
        const response = await axios.get(`${BASE_URL}/view/${_id}`);
        if (response.data.success) {
          setData(response.data.body);
        } else {
          setError("Failed to fetch user data.");
        }
      } catch (error) {
        setError("Error fetching user data.");
        console.error("Error fetching user:", error);
      } finally {
        setLoading(false);
      }
    }

    fetchData();
  }, [_id]);

  if (loading) return <div>Loading...</div>;
  if (error) return <div>{error}</div>;

  return (
    <>
     <div className="container-fluid ">
      <div className="row">
        <div className="col-12">
          <div className="card my-4">
            <div className="card-header p-0 position-relative mt-n4 mx-3 z-index-2">
              <div className="bg-gradient-primary shadow-primary border-radius-lg pt-4 pb-3">
                <h6 className="text-white text-capitalize ps-3">View</h6>
              </div>
            </div>
            <div className="section-body">
              <div className="row">
                <div className="col-12 col-md-12 col-lg-12">
                  <div className="card">
                    <div className="card-body">
                    <div className="form-group mx-auto">               
                        {data.image && (
                          <div className="image-container">
                            <img
                              src={`${BASE_URL}${data.image}`}
                              alt="User"
                              style={{
                                marginLeft: "500px",
                                width: "200px",
                                height: "200px",
                                objectFit: "cover",
                                borderRadius:"50%",
                              }}
                            
                            />
                          </div>
                        )}
                        </div>
                      <div className="form-group">
                        <label>Name</label>
                        <input
                          type="text"
                          className="form-control"
                          id="name"
                          value={data.name || ""}
                          readOnly
                        />
                      </div>
                     
                      <div className="form-group">
                        <label>Email</label>
                        <input
                          type="email"
                          id="email"
                          className="form-control"
                          value={data.email || ""}
                          readOnly
                        />
                      </div>
                      <div className="form-group">
                        <label>Address</label>
                        <input
                          type="text"
                          id="address"
                          className="form-control"
                          value={data.address || ""}
                          readOnly
                        />
                      </div>
                      <div className="form-group">
                        <label>Phone Number</label>
                        <input
                          type="text"
                          id="phone_no"
                          className="form-control"
                          value={data.phone_no || ""}
                          readOnly
                        />
                      </div>
                    </div>
                    <div className="card-footer text-right">
                      <button
                        type="button"
                        className="btn btn-primary"
                        onClick={() => navigate(-1)}
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
    </>
  );
}

export default View;
