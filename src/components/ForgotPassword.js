import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import API from "../api";
import { toast, ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";

export default function ForgotPassword() {
  const [email, setEmail] = useState("");
  const [message, setMessage] = useState("");
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await API.post("/api/users/forgot-password", { email });

      if (res.status === 200) {
        setMessage("OTP sent successfully to your email.");
        toast.success("OTP sent successfully");
       localStorage.setItem("resetEmail", email);
localStorage.setItem("resetUsername", res.data.username); // 👈 You must return username from backend


        // ✅ Delay before navigation so toast can be seen
        setTimeout(() => {
          navigate("/verify-otp");
        }, 2000);
      } else {
        setMessage("Failed to send OTP");
        toast.error("Failed to send OTP");
      }
    } catch (error) {
      console.error(error);
      setMessage("Failed to send OTP");
      toast.error("Error sending OTP");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container mt-5">
      <h2>Forgot Password</h2>
      <form onSubmit={handleSubmit}>
        <input
          type="email"
          className="form-control mb-3"
          placeholder="Enter your registered email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />
        <button className="btn btn-primary" disabled={loading}>
          {loading ? "Sending..." : "Send OTP"}
        </button>
      </form>
      {message && <p className="mt-3 text-info">{message}</p>}
      <ToastContainer position="top-center" />
    </div>
  );
}
