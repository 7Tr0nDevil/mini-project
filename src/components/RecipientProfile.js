import React, { useEffect, useState } from "react";
import API from "../api";

export default function RecipientProfile() {
  const [profile, setProfile] = useState({
    name: "",
    age: "",
    gender: "",
    phone_no: "",
    address: "",
    bloodType: "",
    organNeeded: "",
  });
  const [message, setMessage] = useState("Loading...");
  const [isEditing, setIsEditing] = useState(false);

  useEffect(() => {
    const fetchProfile = async () => {
      try {
        const token = localStorage.getItem("token");
        const res = await API.get("/api/recipients/me", {
          headers: { Authorization: `Bearer ${token}` },
        });
        setProfile(res.data);
        setMessage("");
      } catch (error) {
        console.error("Error fetching recipient profile:", error);
        setMessage("Failed to load profile.");
      }
    };
    fetchProfile();
  }, []);

  const handleChange = (e) => {
    setProfile({ ...profile, [e.target.name]: e.target.value });
  };

  const handleEditToggle = () => {
    setIsEditing(!isEditing);
  };

  const handleSave = async () => {
    try {
      const token = localStorage.getItem("token");
      await API.put("/api/recipients/me", profile, {
        headers: { Authorization: `Bearer ${token}` },
      });
      alert("Profile updated successfully.");
      setIsEditing(false);
    } catch (error) {
      console.error("Error updating profile:", error);
      alert("Failed to update profile.");
    }
  };

  if (message) return <div className="container mt-5">{message}</div>;

  return (
    <div className="container mt-5">
      <h2 className="mb-4">Recipient Profile Details</h2>
      <div className="card p-4 shadow-sm">
        <div className="mb-3">
          <label>Name:</label>
          {isEditing ? (
            <input
              name="name"
              value={profile.name}
              onChange={handleChange}
              className="form-control"
            />
          ) : (
            <p>{profile.name}</p>
          )}
        </div>
        <div className="mb-3">
          <label>Age:</label>
          {isEditing ? (
            <input
              name="age"
              type="number"
              value={profile.age}
              onChange={handleChange}
              className="form-control"
            />
          ) : (
            <p>{profile.age}</p>
          )}
        </div>
        <div className="mb-3">
          <label>Gender:</label>
          {isEditing ? (
            <select
              name="gender"
              value={profile.gender}
              onChange={handleChange}
              className="form-control"
            >
              <option value="">Select Gender</option>
              <option value="Male">Male</option>
              <option value="Female">Female</option>
              <option value="Others">Others</option>
            </select>
          ) : (
            <p>{profile.gender}</p>
          )}
        </div>
        <div className="mb-3">
          <label>Phone Number:</label>
          {isEditing ? (
            <input
              name="phone_no"
              value={profile.phone_no}
              onChange={handleChange}
              className="form-control"
            />
          ) : (
            <p>{profile.phone_no}</p>
          )}
        </div>
        <div className="mb-3">
          <label>Address:</label>
          {isEditing ? (
            <input
              name="address"
              value={profile.address}
              onChange={handleChange}
              className="form-control"
            />
          ) : (
            <p>{profile.address}</p>
          )}
        </div>
        <div className="mb-3">
          <label>Blood Type:</label>
          {isEditing ? (
            <select
              name="bloodType"
              value={profile.bloodType}
              onChange={handleChange}
              className="form-control"
            >
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
          ) : (
            <p>{profile.bloodType}</p>
          )}
        </div>
        <div className="mb-3">
          <label>Organ Needed:</label>
          {isEditing ? (
            <select
              name="organNeeded"
              value={profile.organNeeded}
              onChange={handleChange}
              className="form-control"
            >
              <option value="">Select Organ Needed</option>
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
          ) : (
            <p>{profile.organNeeded}</p>
          )}
        </div>
        <div className="d-flex gap-3">
          {isEditing ? (
            <>
              <button className="btn btn-success" onClick={handleSave}>
                Save
              </button>
              <button className="btn btn-secondary" onClick={handleEditToggle}>
                Cancel
              </button>
            </>
          ) : (
            <button className="btn btn-primary" onClick={handleEditToggle}>
              Edit Profile
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

