import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import axios from 'axios';
import { BASE_URL } from '../Config';



const BookingView = () => {
  const { _id } = useParams(); 
  const [booking, setBooking] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchBooking = async () => {
      setLoading(true);
      try {
        const response = await axios.get(`${BASE_URL}/booking/${_id}`);
        if (response.data.success) {
          setBooking(response.data.body);
        } else {
          setError("Failed to fetch booking data.");
        }
      } catch (err) {
        setError("Error fetching booking data.");
        console.error("Error fetching booking:", err);
      } finally {
        setLoading(false);
      }
    };

    fetchBooking();
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
                <h6 className="text-white text-capitalize ps-3">Booking Details</h6>
              </div>
            </div>
            <div className="section-body">
              <div className="row">
                <div className="col-12">
                  <div className="card">
                    <div className="card-body">
                      <div className="form-group mb-2">
                        <label>Customer Name</label>
                        <input
                          type="text"
                          id="userName"
                          className="form-control"
                          value={booking.user_id?.name || "Unknown"}
                          readOnly
                          style={{ paddingLeft: '10px', backgroundColor: 'lightpink' }}
                        />
                      </div>
                      <div className="form-group mb-2">
                        <label>Category Name</label>
                        <input
                          type="text"
                          id="carName"
                          className="form-control"
                          value={booking.cat_id?.name || "Unknown"}
                          readOnly
                          style={{ paddingLeft: '10px', backgroundColor: 'lightpink' }}
                        />
                      </div>
                      <div className="form-group mb-2">
                        <label>Sub Category Name</label>
                        <input
                          type="text"
                          id="serviceName"
                          className="form-control"
                          value={booking.service_id?.name || "Unknown"}
                          readOnly
                          style={{ paddingLeft: '10px', backgroundColor: 'lightpink' }}
                        />
                      </div>
                      <div className="form-group mb-2">
                        <label>Booking Code</label>
                        <input
                          type="text"
                          className="form-control"
                          id="bookingCode"
                          value={booking.booking_code || "N/A"}
                          readOnly
                          style={{ paddingLeft: '10px', backgroundColor: 'lightpink' }}
                        />
                      </div>
                      <div className="form-group mb-2">
                        <label>No of Booking</label>
                        <input
                          type="text"
                          id="noOfBooking"
                          className="form-control"
                          value={booking.no_of_booking || "N/A"}
                          readOnly
                          style={{ paddingLeft: '10px', backgroundColor: 'lightpink' }}
                        />
                      </div>
                      <div className="form-group mb-2">
                        <label>Date</label>
                        <input
                          type="text"
                          id="date"
                          className="form-control"
                          value={booking.date ? new Date(booking.date).toLocaleDateString() : "N/A"}
                          readOnly
                          style={{ paddingLeft: '10px', backgroundColor: 'lightpink' }}
                        />
                      </div>
                      <div className="form-group mb-2">
                        <label>Location</label>
                        <input
                          type="text"
                          id="location"
                          className="form-control"
                          value={booking.location || "N/A"}
                          readOnly
                          style={{ paddingLeft: '10px', backgroundColor: 'lightpink' }}
                        />
                      </div>
                      <div className="form-group mb-2">
                        <label>Description</label>
                        <textarea
                          id="description"
                          className="form-control"
                          value={booking.description || "N/A"}
                          readOnly
                          style={{ paddingLeft: '10px', backgroundColor: 'lightpink' }}
                        />
                      </div>
                      <div className="form-group ">
                        <label>Amount</label>
                        <input
                          type="text"
                          id="amount"
                          className="form-control"
                          value={`$${booking.amount || "N/A"}`}
                          readOnly
                          style={{ paddingLeft: '10px', backgroundColor: 'lightpink' }}
                        />
                      </div>
                    </div>
                    <div className="mx-4 text-right">
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
  );
}

export default BookingView;
