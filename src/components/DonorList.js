import React, { useEffect, useState } from "react";
import API from "../api";
import Sidebar from "./Sidebar";

export default function DonorList() {
  const [donors, setDonors] = useState([]);
  const [filter, setFilter] = useState({ bloodType: "", organ: "" });

  useEffect(() => {
    API.get("/api/donor")
      .then((res) => setDonors(res.data))
      .catch(() => alert("Error loading donors"));
  }, []);

  const filteredDonors = donors.filter((d) =>
    (filter.bloodType === "" || d.bloodType === filter.bloodType) &&
    (filter.organ === "" || d.organ === filter.organ)
  );

  // ✅ Function to get icon path
  const getOrganImage = (organ) => {
    if (!organ) return null;
    const fileName = organ.toLowerCase().replace(/\s|\(|\)/g, "_") + ".png";
    return `/organs/${fileName}`;
  };

  return (
    <div style={{ display: "flex" }}>
      <Sidebar />
      <div className="container mt-4" style={{ marginLeft: "260px" }}>
        <h2 className="mb-4">Donor List</h2>

        {/* Filter controls */}
        <div className="row mb-3">
          <div className="col-md-6">
            <select
              className="form-control"
              onChange={(e) => setFilter({ ...filter, bloodType: e.target.value })}
            >
              <option value="">All Blood Types</option>
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
          <div className="col-md-6">
            <select
              className="form-control"
              onChange={(e) => setFilter({ ...filter, organ: e.target.value })}
            >
              <option value="">All Organs</option>
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
        </div>

        {/* Table Display */}
        <div className="card shadow p-3">
          <table className="table table-bordered table-striped">
            <thead className="table-light">
              <tr>
                <th>Name</th>
                <th>Gender</th>
                <th>Age</th>
                <th>Phone</th>
                <th>Blood Type</th>
                <th>Organ</th>
                
              </tr>
            </thead>
            <tbody>
              {filteredDonors.map((d, i) => (
                <tr key={i}>
                  <td>{d.name}</td>
                  <td>{d.gender}</td>
                  <td>{d.age}</td>
                  <td>{d.phone_no}</td>
                  <td>{d.bloodType}</td>
                  <td>
  <img
    src={`/organs/${d.organ.toLowerCase().replace(/\s+/g, '-').replace(/[()]/g, '')}.png`}
    alt={d.organ}
    style={{ width: '24px', height: '24px', marginRight: '8px' }}
  />
  {d.organ}
</td>

                  
                </tr>
              ))}
              {filteredDonors.length === 0 && (
                <tr>
                  <td colSpan="7" className="text-center text-muted">No donors found.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
