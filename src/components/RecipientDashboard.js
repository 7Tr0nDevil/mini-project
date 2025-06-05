import React from 'react';
import Sidebar from './Sidebar';
import { Link } from 'react-router-dom';

export default function RecipientDashboard() {
  return (
    <div style={{ display: "flex" }}>
      <Sidebar />
      <div className="container mt-5" style={{ marginLeft: "260px" }}>
        <h2 className="text-center mb-4">Recipient Dashboard</h2>
        <p className="text-center">Welcome, Recipient! Here you can manage your needs, view matching donors, and track your application status.</p>

        <div className="row mt-4">
          <div className="col-md-4">
            <div className="card p-3 shadow-sm">
              <h5>Your Profile</h5>
              <p>View and update your recipient details and needs.</p>
              <Link to="/recipient/profile" className="btn btn-primary w-100">Go to Profile</Link>
            </div>
          </div>

          <div className="col-md-4 mt-3 mt-md-0">
            <div className="card p-3 shadow-sm">
              <h5>Matching Donors</h5>
              <p>See available donors matching your requirements.</p>
              <button className="btn btn-secondary w-100" disabled>
                Coming Soon
              </button>
            </div>
          </div>

          <div className="col-md-4 mt-3 mt-md-0">
            <div className="card p-3 shadow-sm">
              <h5>Application Status</h5>
              <p>Track the status of your recipient application.</p>
              <button className="btn btn-secondary w-100" disabled>
                Coming Soon
              </button>
            </div>
          </div>
        </div>

        <div className="row mt-4">
          <div className="col-md-4">
            <div className="card p-3 shadow-sm">
              <h5>My Certificate</h5>
              <p>View and download your recipient registration certificate.</p>
              <Link to="/recipient/certificate" className="btn btn-info w-100">View My Certificate</Link>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
