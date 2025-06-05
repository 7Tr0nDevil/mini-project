import React, { useState, useEffect } from "react";
import API from "../api";

export default function Register() {
  const [form, setForm] = useState({
    name: "",
    address: "",
    gender: "",
    age: "",
    phone: "",
    email: "",
    username: "",
    password: "",
  });

  const [otp, setOtp] = useState("");
  const [step, setStep] = useState("register");
  const [message, setMessage] = useState("");
  const [timer, setTimer] = useState(60);

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    try {
      const res = await API.post("/api/auth/register", form);
      setMessage(res.data.message);
      setStep("verify");
      setTimer(60);
    } catch (err) {
      setMessage(err.response?.data?.message || "Registration failed");
    }
  };

  const handleVerifyOtp = async (e) => {
    e.preventDefault();
    try {
      const res = await API.post("/api/auth/verify-otp", {
        username: form.username,
        otp,
      });
      setMessage(res.data.message);
      setTimeout(() => (window.location.href = "/login"), 2000);
    } catch (err) {
      setMessage(err.response?.data?.message || "Invalid OTP");
    }
  };

  const handleResendOtp = async () => {
    try {
      const res = await API.post("/api/auth/resend-otp", {
        username: form.username,
        email: form.email,
      });
      setMessage(res.data.message);
      setTimer(60);
    } catch (err) {
      setMessage(err.response?.data?.message || "Failed to resend OTP");
    }
  };

  useEffect(() => {
    let interval;
    if (step === "verify" && timer > 0) {
      interval = setInterval(() => setTimer((prev) => prev - 1), 1000);
    }
    return () => clearInterval(interval);
  }, [step, timer]);

  return (
    <div className="container d-flex justify-content-center align-items-center" style={{ minHeight: "100vh" }}>
      <div className="card shadow p-4" style={{ width: "100%", maxWidth: "500px", backgroundColor: "rgba(255, 255, 255, 0.9)" }}>

        <h2 className="text-center mb-4 text-success">User Registration</h2>

        {step === "register" ? (
          <form onSubmit={handleRegister}>
            <div className="mb-2">
              <input name="name" placeholder="Full Name" className="form-control" onChange={handleChange} required />
            </div>
            <div className="mb-2">
              <input name="address" placeholder="Address" className="form-control" onChange={handleChange} required />
            </div>
            <div className="mb-2">
              <select name="gender" className="form-control" onChange={handleChange} required>
                <option value="">Select Gender</option>
                <option value="Male">Male</option>
                <option value="Female">Female</option>
                <option value="Others">Others</option>
              </select>
            </div>
            <div className="mb-2">
              <input name="age" placeholder="Age" type="number" className="form-control" onChange={handleChange} required />
            </div>
            <div className="mb-2">
              <input name="phone" placeholder="Phone Number" className="form-control" onChange={handleChange} required />
            </div>
            <div className="mb-2">
              <input name="email" type="email" placeholder="Email ID" className="form-control" onChange={handleChange} required />
            </div>
            <div className="mb-2">
              <input name="username" placeholder="Username" className="form-control" onChange={handleChange} required />
            </div>
            <div className="mb-3">
              <input name="password" type="password" placeholder="Password" className="form-control" onChange={handleChange} required />
            </div>
            <button type="submit" className="btn btn-success w-100">Register</button>
          </form>
        ) : (
          <form onSubmit={handleVerifyOtp}>
            <div className="mb-3">
              <input name="otp" placeholder="Enter OTP" className="form-control" value={otp} onChange={(e) => setOtp(e.target.value)} required />
            </div>
            <button type="submit" className="btn btn-primary w-100">Verify OTP</button>
            <button type="button" className="btn btn-link mt-2" onClick={handleResendOtp} disabled={timer > 0}>
              {timer > 0 ? `Resend OTP in ${timer}s` : "Resend OTP"}
            </button>
          </form>
        )}

        {message && <div className="alert alert-info mt-3">{message}</div>}
      </div>
    </div>
  );
}
