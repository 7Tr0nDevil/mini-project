import React, { useEffect, useState } from "react";
import API from "../api";
import Sidebar from "./Sidebar";

export default function RecipientList() {
  const [recipients, setRecipients] = useState([]);
  const [filter, setFilter] = useState({ bloodType: "", organNeeded: "" });

  useEffect(() => {
    API.get("/api/recipients")
      .then((res) => setRecipients(res.data))
      .catch(() => alert("Error loading recipients"));
  }, []);

  const filteredRecipients = recipients.filter((r) =>
    (filter.bloodType === "" || r.bloodType === filter.bloodType) &&
    (filter.organNeeded === "" || r.organNeeded === filter.organNeeded)
  );

  // ✅ Function to get organ image path
  const getOrganImage = (organ) => {
    if (!organ) return null;
    const fileName = organ.toLowerCase().replace(/\s|\(|\)/g, "_") + ".png";
    return `/organs/${fileName}`;
  };

  return (
    <div style={{ display: "flex" }}>
      <Sidebar />
      <div className="container mt-4" style={{ marginLeft: "260px" }}>
        <h2 className="mb-4">Recipient List</h2>

        {/* Filter Controls */}
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
              onChange={(e) => setFilter({ ...filter, organNeeded: e.target.value })}
            >
              <option value="">All Organs Needed</option>
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

        {/* Table */}
        <div className="card shadow p-3">
          <table className="table table-bordered table-striped">
            <thead className="table-light">
              <tr>
                <th>Name</th>
                <th>Gender</th>
                <th>Age</th>
                <th>Phone</th>
                <th>Blood Type</th>
                <th>Organ Needed</th>
                
              </tr>
            </thead>
            <tbody>
              {filteredRecipients.map((r, i) => (
                <tr key={i}>
                  <td>{r.name}</td>
                  <td>{r.gender}</td>
                  <td>{r.age}</td>
                  <td>{r.phone_no}</td>
                  <td>{r.bloodType}</td>
                  <td>
                    
  <img
    src={`/organs/${r.organNeeded.toLowerCase().replace(/\s+/g, '-').replace(/[()]/g, '')}.png`}
    alt={r.organNeeded}
    style={{ width: '24px', height: '24px', marginRight: '8px' }}
  />
  {r.organNeeded}
</td>

                  
                </tr>
              ))}
              {filteredRecipients.length === 0 && (
                <tr>
                  <td colSpan="7" className="text-center text-muted">No recipients found.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
