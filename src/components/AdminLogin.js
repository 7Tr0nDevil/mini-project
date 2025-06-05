import React, { useState } from "react";
import API from "../api";
import { useNavigate, Link } from "react-router-dom";
import { jwtDecode } from 'jwt-decode';

const AdminLogin = () => {
  const [formData, setFormData] = useState({ username: "", password: "" });
  const [message, setMessage] = useState("");
  const navigate = useNavigate();

  const handleChange = (e) => {
    setFormData(prev => ({
      ...prev,
      [e.target.name]: e.target.value
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setMessage("Logging in as admin...");

    try {
      const cleanData = {
        username: formData.username.trim(),
        password: formData.password.trim(),
        loginAs: "admin"  // Hardcoded to admin login
      };

      const res = await API.post("/api/auth/login", cleanData);
      const { token, role, message: successMessage } = res.data;

      localStorage.setItem("token", token);
      localStorage.setItem("userRole", role);

      const decoded = jwtDecode(token);
      console.log("✅ Admin logged in:", decoded);

      setMessage(successMessage);

      if (role === "admin") {
        navigate("/admin-dashboard");
      } else {
        setMessage("Access denied: This login is for admin only.");
      }

    } catch (error) {
      console.error("Admin Login Error:", error);
      setMessage(error.response?.data?.message || "Login failed. Server error.");
    }
  };

  return (
    <div className="container d-flex justify-content-center align-items-center" style={{ minHeight: "100vh" }}>
      <div className="card shadow p-4" style={{ width: "100%", maxWidth: "500px", backgroundColor: "rgba(255, 255, 255, 0.9)" }}>
        <h2 className="text-center mb-4 text-danger">Admin Login</h2>
        <form onSubmit={handleSubmit}>
          <div className="mb-3">
            <label className="form-label">Username</label>
            <input
              type="text"
              className="form-control"
              name="username"
              value={formData.username}
              onChange={handleChange}
              required
            />
          </div>

          <div className="mb-3">
            <label className="form-label">Password</label>
            <input
              type="password"
              className="form-control"
              name="password"
              value={formData.password}
              onChange={handleChange}
              required
            />
          </div>

          <button className="btn btn-danger w-100" type="submit">
            Admin Login
          </button>
        </form>

        {message && <div className="alert alert-info mt-3">{message}</div>}

        <div className="mt-3 text-center">
          <Link to="/login">Back to User Login</Link>
        </div>
      </div>
    </div>
  );
};

export default AdminLogin;
