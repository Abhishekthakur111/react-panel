import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { axiosInstance } from '../Config';



const ContactView = () => {
  const { _id } = useParams();
  const [data, setData] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    async function fetchData() {
      try {
        const response = await axiosInstance.get(`/contactview/${_id}`);
       
        if (response.data.data)
             {
            setData(response.data.data);
        } else {
          setError("Failed to fetch contact data.");
        }
      } catch (error) {
        setError("Error fetching contact data.");
      } finally {
        setLoading(false);
      }
    }

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
              <div className="bg-gradient-primary shadow-primary border-radius-lg pt-2 pb-2">
                <div className="d-flex justify-content-between align-items-center px-3 pt-1">
                  <h6 className="text-white text-capitalize">
                    Contact Detail
                  </h6>
                </div>
              </div>
            </div>
            <div className="section-body">
              <div className="row">
                <div className="col-12 col-md-12 col-lg-12">
                  <div className="card">
                    <div className="card-body">
                      <div className="form-group mb-2">
                        <label>Name</label>
                        <input
                          type="text"
                          className="form-control"
                          id="name"
                          value={data.name || ""}
                          readOnly
                          style={{paddingLeft:'10px',backgroundColor:'lightpink'}}
                        />
                      </div>
                      <div className="form-group mb-2">
                        <label>Email</label>
                        <input
                          type="email"
                          id="email"
                          className="form-control"
                          value={data.email || ""}
                          readOnly
                          style={{paddingLeft:'10px',backgroundColor:'lightpink'}}
                        />
                      </div>
                      <div className="form-group mb-2">
                        <label>Address</label>
                        <input
                          type="text"
                          id="address"
                          className="form-control"
                          value={data.address || ""}
                          readOnly
                          style={{paddingLeft:'10px',backgroundColor:'lightpink'}}
                        />
                      </div>
                      <div className="form-group ">
                        <label>Phone Number</label>
                        <input
                          type="text"
                          id="phone_no"
                          className="form-control"
                          value={data.phoneNumber || ""}
                          readOnly
                          style={{paddingLeft:'10px',backgroundColor:'lightpink'}}
                        />
                      </div>
                    </div>
                    <div className=" text-end mx-4">
                      <button
                        type="button"
                        className="btn btn-primary"
                        onClick={() => navigate('/contacts')}
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
}

export default ContactView;
