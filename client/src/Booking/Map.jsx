import React, { useEffect, useState } from 'react';
import { MapContainer, TileLayer, Marker, Popup } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';
import L from 'leaflet';


delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: require('leaflet/dist/images/marker-icon-2x.png'),
  iconUrl: require('leaflet/dist/images/marker-icon.png'),
  shadowUrl: require('leaflet/dist/images/marker-shadow.png'),
});

const Map = () => {
  const [position, setPosition] = useState([51.505, -0.09]); 
  const [loading, setLoading] = useState(true); 

  useEffect(() => {
    
    if (navigator.geolocation) {
      navigator.geolocation.getCurrentPosition(
        (position) => {
          const { latitude, longitude } = position.coords;
          setPosition([latitude, longitude]); 
          setLoading(false); 
        },
        () => {
          console.error("Error getting location");
          setLoading(false); 
        }
      );
    } else {
      console.error("Geolocation is not supported by this browser.");
      setLoading(false); 
    }
  }, []);

  if (loading) {
    return <div>Loading your location...</div>; 
  }

  return (
    <MapContainer center={position} zoom={13} style={{ height: "630px", width: "97%", marginLeft: '20px', borderRadius: '10px',  }}>
      <TileLayer
        url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
        attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
      />
      <Marker position={position}>
        <Popup>
          You are here! <br /> {`Latitude: ${position[0]}, Longitude: ${position[1]}`}
        </Popup>
      </Marker>
    </MapContainer>
  );
};

export default Map;
