import React from 'react';
import Sidebar from './Sidebar';
import { Link } from 'react-router-dom';

export default function AdminDashboard() {
  return (
    <div style={{ display: "flex" }}>
      <Sidebar />
      <div className="container mt-5" style={{ marginLeft: "260px" }}>
        <h2 className="text-center mb-4">Admin Dashboard</h2>
        <p className="text-center">Welcome, Admin! Here you can manage the system, view donors and recipients, and perform updates.</p>

        <div className="row mt-4">
          <div className="col-md-4">
            <div className="card p-3 shadow-sm">
              <h5>View Donors</h5>
              <p>See the list of all registered donors.</p>
              <Link to="/donors" className="btn btn-primary w-100">Go to Donor List</Link>
            </div>
          </div>

          <div className="col-md-4 mt-3 mt-md-0">
            <div className="card p-3 shadow-sm">
              <h5>View Recipients</h5>
              <p>See the list of all registered recipients.</p>
              <Link to="/recipients" className="btn btn-primary w-100">Go to Recipient List</Link>
            </div>
          </div>

          <div className="col-md-4 mt-3 mt-md-0">
            <div className="card p-3 shadow-sm">
              <h5>System Updates</h5>
              <p>Access system controls, updates, or settings.</p>
              <button className="btn btn-warning w-100" disabled>
                Coming Soon
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
