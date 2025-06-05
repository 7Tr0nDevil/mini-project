import React from 'react';
import Sidebar from './Sidebar';
import { Link } from 'react-router-dom';

export default function DonorDashboard() {
  return (
    <div style={{ display: "flex" }}>
      <Sidebar />
      <div className="container mt-5" style={{ marginLeft: "260px" }}>
        <h2 className="text-center mb-4">Donor Dashboard</h2>
        <p className="text-center">Welcome, Donor! Here you can manage your profile, view your certificate, and track organ requests.</p>

        <div className="row mt-4">
          <div className="col-md-4">
            <div className="card p-3 shadow-sm">
              <h5>Your Profile</h5>
              <p>View and update your donor profile details.</p>
              <Link to="/donor/profile" className="btn btn-primary w-100">Go to Profile</Link>
            </div>
          </div>

          <div className="col-md-4 mt-3 mt-md-0">
            <div className="card p-3 shadow-sm">
              <h5>Donation History</h5>
              <p>Review your past donations and status updates.</p>
              <button className="btn btn-secondary w-100" disabled>
                Coming Soon
              </button>
            </div>
          </div>

          <div className="col-md-4 mt-3 mt-md-0">
            <div className="card p-3 shadow-sm">
              <h5>Organ Requests</h5>
              <p>Track any organ requests linked to your profile.</p>
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
              <p>View and download your donor registration certificate.</p>
              <Link to="/donor/certificate" className="btn btn-info w-100">View My Certificate</Link>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

