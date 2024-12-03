import React, { useEffect, useState } from "react";
import { MapContainer, TileLayer, Marker, Popup } from "react-leaflet";
import "leaflet/dist/leaflet.css";
import L from "leaflet";

// Configure Leaflet's default icon
delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: require("leaflet/dist/images/marker-icon-2x.png"),
  iconUrl: require("leaflet/dist/images/marker-icon.png"),
  shadowUrl: require("leaflet/dist/images/marker-shadow.png"),
});

const Map = () => {
  const defaultPosition = [51.505, -0.09]; // Default location
  const [position, setPosition] = useState(defaultPosition);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (navigator.geolocation) {
      navigator.geolocation.getCurrentPosition(
        (pos) => {
          const { latitude, longitude } = pos.coords;
          setPosition([latitude, longitude]);
          setLoading(false);
        },
        (err) => {
          console.error("Geolocation error:", err.message);
          setError("Unable to retrieve your location. Using default position.");
          setLoading(false);
        }
      );
    } else {
      console.error("Geolocation not supported.");
      setError("Geolocation is not supported by your browser.");
      setLoading(false);
    }
  }, []);

  if (loading) {
    return (
      <div style={styles.loader}>
        Loading your location...
      </div>
    );
  }

  return (
    <div style={styles.container}>
      {error && <div style={styles.error}>{error}</div>}
      <MapContainer
        center={position}
        zoom={13}
        style={styles.map}
      >
        <TileLayer
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
        />
        <Marker position={position}>
          <Popup>
            You are here! <br />
            {`Latitude: ${position[0]}, Longitude: ${position[1]}`}
          </Popup>
        </Marker>
      </MapContainer>
    </div>
  );
};

const styles = {
  container: {
    margin: "20px",
    borderRadius: "10px",
    overflow: "hidden",
  },
  map: {
    height: "630px",
    width: "100%",
  },
  loader: {
    textAlign: "center",
    padding: "20px",
    fontSize: "18px",
    color: "#555",
  },
  error: {
    color: "red",
    marginBottom: "10px",
    textAlign: "center",
  },
};

export default Map;
