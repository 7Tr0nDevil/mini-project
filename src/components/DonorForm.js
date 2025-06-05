import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import API from "../api";
import { saveAs } from "file-saver";

export default function DonorForm() {
  const [form, setForm] = useState({
    name: "",
    address: "",
    gender: "",
    age: "",
    phone_no: "",
    bloodType: "",
    organ: "",
  });

  const navigate = useNavigate();

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const token = localStorage.getItem("token");
      if (!token) {
        alert("Session expired. Please log in again.");
        navigate("/login");
        return;
      }

      const res = await API.post("/api/donor", form);

      alert("✅ Donor registered successfully!");


      const donorData = res.data.donor;
      const certificateText = `Certificate of Appreciation\n\nThis is to certify that ${donorData.name} has registered as a donor with OrganHub.\nThank you for your selfless contribution!`;

      const blob = new Blob([certificateText], { type: "application/pdf" });
      saveAs(blob, `donor_certificate_${donorData.name}.pdf`);

      navigate("/donor-dashboard");
    } catch (err) {
      console.error("🚨 Donor submit error:", err.response?.data || err.message);
      alert("Error: " + (err.response?.data?.message || err.message));
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
        className="card shadow p-4"
        style={{ width: "100%", maxWidth: "500px", backgroundColor: "rgba(255, 255, 255, 0.9)" }}
      >
        <h2 className="text-center mb-4 text-success">Donor Registration</h2>
        <form onSubmit={handleSubmit}>
          <div className="mb-2">
            <input name="name" placeholder="Name" className="form-control" onChange={handleChange} required />
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
            <input name="age" type="number" placeholder="Age" className="form-control" onChange={handleChange} required />
          </div>
          <div className="mb-2">
            <input name="phone_no" placeholder="Phone Number" className="form-control" onChange={handleChange} required />
          </div>
          <div className="mb-2">
            <select name="bloodType" className="form-control" onChange={handleChange} required>
              <option value="">Select Blood Type</option>
              <option value="A+">A+</option>
              <option value="A-">A-</option>
              <option value="B+">B+</option>
              <option value="B-">B-</option>
              <option value="O+">O+</option>
              <option value="O-">O-</option>
              <option value="AB+">AB+</option>
              <option value="AB-">AB-</option>
            </select>
          </div>
          <div className="mb-2">
            <select name="organ" className="form-control" onChange={handleChange} required>
              <option value="">Select Organ</option>
              <option value="Kidney">Kidney</option>
              <option value="Liver">Liver</option>
              <option value="Heart">Heart</option>
              <option value="Lung">Lung</option>
              <option value="Pancreas">Pancreas</option>
              <option value="Intestine">Intestine</option>
              <option value="Eye (Cornea)">Eye (Cornea)</option>
              <option value="Skin">Skin</option>
              <option value="Bone">Bone</option>
              <option value="Tendons">Tendons</option>
              <option value="Veins">Veins</option>
              <option value="Heart Valves">Heart Valves</option>
              <option value="Hands">Hands</option>
              <option value="Face">Face</option>
            </select>
          </div>
          <button className="btn btn-success w-100">Submit</button>
        </form>
      </div>
    </div>
  );
}
