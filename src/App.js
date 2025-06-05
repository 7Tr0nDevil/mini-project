import React from "react";
import { BrowserRouter as Router, Routes, Route, Link, Navigate } from "react-router-dom";
import WelcomePage from "./pages/WelcomePage";
import RoleSelector from "./pages/RoleSelector";
import DonorForm from "./components/DonorForm";
import RecipientForm from "./components/RecipientForm";
import Register from "./components/Register";
import DonorList from "./components/DonorList";
import RecipientList from "./components/RecipientList";
import Login from "./components/Login";
import AdminLogin from "./components/AdminLogin";
import AdminDashboard from "./components/AdminDashboard";
import DonorDashboard from "./components/DonorDashboard";
import RecipientDashboard from "./components/RecipientDashboard";
import DonorProfile from "./components/DonorProfile";
import RecipientProfile from "./components/RecipientProfile";
import PrivateRoute from "./components/PrivateRoute";
import { ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";

function App() {
  const userRole = localStorage.getItem("userRole");

  const handleLogout = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("userRole");
    window.location.href = "/login";
  };

  const location = window.location.pathname;
  const hideNavOn = ["/", "/login", "/admin-login", "/register", "/forgot-password", "/select-role"];

  return (
    <Router>
      {!hideNavOn.includes(location) && (
        <nav className="navbar navbar-expand navbar-dark bg-dark px-4">
          <Link className="navbar-brand" to="/">OrganHub</Link>
          <div className="d-flex">
            {userRole === "admin" && (
              <Link className="nav-link text-white" to="/admin-dashboard">Admin Dashboard</Link>
            )}
            {userRole && (
              <button className="btn btn-sm btn-danger ms-auto" onClick={handleLogout}>
                Logout
              </button>
            )}
          </div>
        </nav>
      )}

      <Routes>
        <Route path="/" element={<WelcomePage />} />
        <Route path="/login" element={<Login />} />
        <Route path="/admin-login" element={<AdminLogin />} />
        <Route path="/register" element={<Register />} />

        <Route path="/select-role" element={<RoleSelector />} />

        <Route path="/admin-dashboard" element={
          <PrivateRoute allowedRoles={["admin"]}>
            <AdminDashboard />
          </PrivateRoute>
        } />
        <Route path="/donors" element={
          <PrivateRoute allowedRoles={["admin"]}>
            <DonorList />
          </PrivateRoute>
        } />
        <Route path="/recipients" element={
          <PrivateRoute allowedRoles={["admin"]}>
            <RecipientList />
          </PrivateRoute>
        } />

        <Route path="/donor" element={
          <PrivateRoute allowedRoles={["donor"]}>
            <DonorForm />
          </PrivateRoute>
        } />
        <Route path="/donor-dashboard" element={
          <PrivateRoute allowedRoles={["donor"]}>
            <DonorDashboard />
          </PrivateRoute>
        } />
        <Route path="/donor/profile" element={
          <PrivateRoute allowedRoles={["donor"]}>
            <DonorProfile />
          </PrivateRoute>
        } />

        <Route path="/recipient" element={
          <PrivateRoute allowedRoles={["recipient"]}>
            <RecipientForm />
          </PrivateRoute>
        } />
        <Route path="/recipient-dashboard" element={
          <PrivateRoute allowedRoles={["recipient"]}>
            <RecipientDashboard />
          </PrivateRoute>
        } />
        <Route path="/recipient/profile" element={
          <PrivateRoute allowedRoles={["recipient"]}>
            <RecipientProfile />
          </PrivateRoute>
        } />

        <Route path="*" element={<Navigate to="/" />} />
      </Routes>

      <ToastContainer position="top-center" />
    </Router>
  );
}

export default App;
