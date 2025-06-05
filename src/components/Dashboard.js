import React, { useEffect, useState } from "react";
import API from "../api";
import Sidebar from "./Sidebar";

// ✅ Import chart components
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
  PieChart,
  Pie,
  Cell
} from "recharts";

export default function Dashboard() {
  const [donors, setDonors] = useState([]);
  const [recipients, setRecipients] = useState([]);

  useEffect(() => {
    const fetchData = async () => {
      const donorRes = await API.get("/api/donor");
      const recipientRes = await API.get("/api/recipients");
      setDonors(donorRes.data);
      setRecipients(recipientRes.data);
    };
    fetchData();
  }, []);

  // ✅ Donor by organ
  const donorOrganData = Object.entries(
    donors.reduce((acc, d) => {
      acc[d.organ] = (acc[d.organ] || 0) + 1;
      return acc;
    }, {})
  ).map(([organ, count]) => ({ organ, count }));

  // ✅ Donor by blood type
  const donorBloodData = Object.entries(
    donors.reduce((acc, d) => {
      acc[d.bloodType] = (acc[d.bloodType] || 0) + 1;
      return acc;
    }, {})
  ).map(([name, value]) => ({ name, value }));

  // ✅ Recipient by organ needed
  const recipientOrganData = Object.entries(
    recipients.reduce((acc, r) => {
      acc[r.organNeeded] = (acc[r.organNeeded] || 0) + 1;
      return acc;
    }, {})
  ).map(([organ, count]) => ({ organ, count }));

  // ✅ Recipient by blood type
  const recipientBloodData = Object.entries(
    recipients.reduce((acc, r) => {
      acc[r.bloodType] = (acc[r.bloodType] || 0) + 1;
      return acc;
    }, {})
  ).map(([name, value]) => ({ name, value }));

  const COLORS = [
    "#28a745", "#007bff", "#ffc107", "#dc3545",
    "#6610f2", "#17a2b8", "#6f42c1", "#20c997"
  ];

  return (
    <div style={{ display: "flex" }}>
      <Sidebar />
      <div className="container mt-5" style={{ marginLeft: "260px" }}>
        <h2 className="text-center mb-4">OrganHub Dashboard</h2>
        <div className="row text-center">
          <div className="col-md-6">
            <div className="card bg-success text-white p-4">
              <h4>Total Donors</h4>
              <h2>{donors.length}</h2>
            </div>
          </div>
          <div className="col-md-6 mt-md-0 mt-3">
            <div className="card bg-primary text-white p-4">
              <h4>Total Recipients</h4>
              <h2>{recipients.length}</h2>
            </div>
          </div>
        </div>

        {/* ✅ Donor Chart: Organ */}
        <div className="mt-5">
          <h4>Donor Distribution by Organ</h4>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={donorOrganData} margin={{ top: 20, right: 30, left: 20, bottom: 5 }}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="organ" />
              <YAxis allowDecimals={false} />
              <Tooltip />
              <Bar
                dataKey="count"
                fill="#28a745"
                barSize={50}
                radius={[10, 10, 0, 0]}
                label={{ position: 'top', fill: '#000', fontSize: 14 }}
              />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* ✅ Donor Chart: Blood Type */}
        <div className="mt-5">
          <h4>Donor Distribution by Blood Type</h4>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={donorBloodData}
                dataKey="value"
                nameKey="name"
                cx="50%"
                cy="50%"
                outerRadius={100}
                label
              >
                {donorBloodData.map((_, index) => (
                  <Cell key={index} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* ✅ Recipient Chart: Organ Needed */}
        <div className="mt-5">
          <h4>Recipient Distribution by Organ Needed</h4>
          <ResponsiveContainer width="100%" height={300}>
  <BarChart data={recipientOrganData} margin={{ top: 20, right: 30, left: 20, bottom: 5 }}>
    <CartesianGrid strokeDasharray="3 3" />
    <XAxis dataKey="organ" />
    <YAxis allowDecimals={false} />
    <Tooltip />
    <Bar
      dataKey="count"
      fill="#17a2b8"
      barSize={50}
      radius={[10, 10, 0, 0]}
      label={{ position: 'top', fill: '#000', fontSize: 14 }}
    />
  </BarChart>
</ResponsiveContainer>

        </div>

        {/* ✅ Recipient Chart: Blood Type */}
        <div className="mt-5">
          <h4>Recipient Distribution by Blood Type</h4>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={recipientBloodData}
                dataKey="value"
                nameKey="name"
                cx="50%"
                cy="50%"
                outerRadius={100}
                label
              >
                {recipientBloodData.map((_, index) => (
                  <Cell key={index} fill={COLORS[(index + 4) % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
