import React, { useEffect, useState } from "react";
import API from "../api";

export default function DonorProfile() {
  const [profile, setProfile] = useState(null);
  const [message, setMessage] = useState("Loading...");

  useEffect(() => {
    const fetchProfile = async () => {
      try {
        const token = localStorage.getItem("token");
        const res = await API.get("/api/donor/me", {
          headers: { Authorization: `Bearer ${token}` },
        });
        setProfile(res.data);
        setMessage("");
      } catch (error) {
        console.error("Error fetching donor profile:", error);
        setMessage("Failed to load profile.");
      }
    };
    fetchProfile();
  }, []);

  if (message) return <div className="container mt-5">{message}</div>;

  return (
    <div className="container mt-5">
      <h2 className="mb-4">Donor Profile Details</h2>
      <div className="card p-4 shadow-sm">
        <p><strong>Name:</strong> {profile.name}</p>
        <p><strong>Age:</strong> {profile.age}</p>
        <p><strong>Gender:</strong> {profile.gender}</p>
        <p><strong>Phone Number:</strong> {profile.phone_no}</p>
        <p><strong>Address:</strong> {profile.address}</p>
        <p><strong>Blood Type:</strong> {profile.bloodType}</p>
        <p><strong>Organ to Donate:</strong> {profile.organ}</p>
      </div>
    </div>
  );
}
