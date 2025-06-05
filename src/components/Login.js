import React, { useState } from "react";
import API from "../api";
import { useNavigate, Link } from "react-router-dom";
import { jwtDecode } from 'jwt-decode';

const Login = () => {
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
        setMessage("Logging in...");

        try {
            const cleanData = {
                username: formData.username.trim(),
                password: formData.password.trim(),
                loginAs: "user"
            };

            const res = await API.post("/api/auth/login", cleanData);
            const { token, role, message: successMessage } = res.data;

            localStorage.setItem("token", token);
            localStorage.setItem("userRole", role.trim().toLowerCase());

            const decoded = jwtDecode(token);
            console.log("✅ Logged in as:", decoded);

            setMessage(successMessage);

            // ✅ Always navigate to role selector (let them pick donor or recipient)
            navigate("/select-role");

        } catch (error) {
            console.error("Login Error:", error);
            setMessage(error.response?.data?.message || "Login failed. Server error.");
        }
    };

    return (
        <div className="container d-flex justify-content-center align-items-center" style={{ minHeight: "100vh" }}>
            <div className="card shadow p-4" style={{ width: "100%", maxWidth: "500px", backgroundColor: "rgba(255, 255, 255, 0.9)" }}>
                <h2 className="text-center mb-4 text-primary">User Login</h2>
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

                    <button className="btn btn-primary w-100" type="submit">
                        Login
                    </button>
                </form>

                {message && <div className="alert alert-info mt-3">{message}</div>}

                <div className="mt-3 text-center">
                    <Link to="/register" className="d-block mb-2">New user? Register here</Link>
                    <Link to="/forgot-password">Forgot Password?</Link>
                    <div className="mt-2">
                        <Link to="/admin-login">Admin Login</Link>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Login;

