import React from "react";
import { useNavigate } from "react-router-dom";
import 'bootstrap-icons/font/bootstrap-icons.css';

const RoleSelector = () => {
  const navigate = useNavigate();

  const handleSelect = (role) => {
    // ✅ store the selected role locally
    localStorage.setItem("selectedRole", role);

    if (role === "donor") {
      navigate("/donor"); // Go to donor form
    } else if (role === "recipient") {
      navigate("/recipient"); // Go to recipient form
    }
  };

  return (
    <div
      className="d-flex justify-content-center align-items-center"
      style={{
        backgroundImage: "url('/bgimage.jpg')",
        backgroundSize: "cover",
        backgroundPosition: "center",
        minHeight: "100vh",
      }}
    >
      <div
        className="card shadow-lg p-5 text-center"
        style={{
          width: "100%",
          maxWidth: "450px",
          backgroundColor: "rgba(255, 255, 255, 0.95)",
          borderRadius: "20px",
        }}
      >
        <img src="/logo.png" alt="OrganHub Logo" style={{ width: "100px", marginBottom: "20px" }} />
        <h2 className="mb-3 text-primary">
          <i className="bi bi-person-lines-fill"></i> Select Your Role
        </h2>
        <p className="mb-4">Please choose your role to continue:</p>

        <div className="d-flex flex-column gap-3">
          <button
            className="btn btn-success btn-lg d-flex align-items-center justify-content-center"
            onClick={() => handleSelect("donor")}
          >
            <i className="bi bi-droplet-half me-2"></i> Donor
          </button>
          <button
            className="btn btn-primary btn-lg d-flex align-items-center justify-content-center"
            onClick={() => handleSelect("recipient")}
          >
            <i className="bi bi-heart-pulse me-2"></i> Recipient
          </button>
        </div>
      </div>
    </div>
  );
};

export default RoleSelector;
