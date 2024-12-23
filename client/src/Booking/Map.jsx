import React, { useEffect, useState, useRef } from "react";
import { MapContainer, TileLayer, Marker, Popup, useMap } from "react-leaflet";
import "leaflet/dist/leaflet.css";
import L from "leaflet";
import { FaExpand, FaCompress } from "react-icons/fa";

delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: require("leaflet/dist/images/marker-icon-2x.png"),
  iconUrl: require("leaflet/dist/images/marker-icon.png"),
  shadowUrl: require("leaflet/dist/images/marker-shadow.png"),
});

const ResizeMap = () => {
  const map = useMap();
  useEffect(() => {
    map.invalidateSize();
  }, [map]);
  return null;
};

const Map = () => {
  const defaultPosition = [51.505, -0.09];
  const [position, setPosition] = useState(defaultPosition);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const mapRef = useRef();
  const [isFullscreen, setIsFullscreen] = useState(false);

  useEffect(() => {
    if (navigator.geolocation) {
      navigator.geolocation.getCurrentPosition(
        (pos) => {
          const { latitude, longitude } = pos.coords;
          setPosition([latitude, longitude]);
          setLoading(false);
        },
        (err) => {
          setError("Unable to retrieve your location. Using default position.");
          setLoading(false);
        }
      );
    } else {
      setError("Geolocation is not supported by your browser.");
      setLoading(false);
    }
  }, []);

  const toggleFullscreen = () => {
    if (!isFullscreen) {
      mapRef.current?.requestFullscreen?.();
    } else {
      document.exitFullscreen?.();
    }
    setIsFullscreen(!isFullscreen);
  };

  if (loading) {
    return <div style={styles.loader}>Loading your location...</div>;
  }

  return (
    <div style={styles.container}>
      <h5>Google Map</h5>
      {error && <div style={styles.error}>{error}</div>}
      <div
        ref={mapRef}
        style={{
          ...styles.mapContainer,
          ...(isFullscreen ? styles.fullscreen : {}),
          height: "100vh",
        }}
      >
        <button
          style={styles.fullscreenButton}
          onClick={toggleFullscreen}
          title={isFullscreen ? "Exit Fullscreen" : "Enter Fullscreen"} 
        >
          {isFullscreen ? <FaCompress /> : <FaExpand />}
        </button>

        <MapContainer
          center={position}
          zoom={13}
          style={{
            ...styles.map,
            ...(isFullscreen ? styles.mapFullscreen : {}),
            height: "100%",
          }}
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
          <ResizeMap />
        </MapContainer>
      </div>
    </div>
  );
};

const styles = {
  container: {
    margin: "20px",
  },
  mapContainer: {
    position: "relative",
    borderRadius: "10px",
    overflow: "hidden",
    transition: "all 0.3s ease",
  },
  fullscreen: {
    position: "fixed",
    top: 0,
    left: 0,
    width: "100vw",
    height: "100vh",
    zIndex: 9999,
    borderRadius: 0,
    overflow: "hidden",
  },
  map: {
    height: "500px",
    width: "100%",
  },
  mapFullscreen: {
    height: "100vh",
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
  fullscreenButton: {
    position: "absolute",
    top: "10px",
    right: "10px",
    zIndex: 1000,
    padding: "8px 15px",
    fontSize: "20px",
    backgroundColor: "white",
    color: "black",
    border: "none",
    borderRadius: "5px",
    cursor: "pointer",
    boxShadow: "0 2px 5px rgba(0, 0, 0, 0.3)",
  },
};

export default Map;
