import React from 'react';
import { Navigate } from 'react-router-dom';
import { jwtDecode } from 'jwt-decode';

const PrivateRoute = ({ children, allowedRoles }) => {
  const token = localStorage.getItem('token');
  if (!token) {
    console.warn("🔒 No token found, redirecting to login.");
    return <Navigate to="/login" replace />;
  }

  try {
    const decoded = jwtDecode(token);
    const userRole = decoded.role;

    if (allowedRoles.includes(userRole)) {
      return children;
    } else {
      console.warn(`🔒 Access denied for role: ${userRole}`);
      return <Navigate to="/login" replace />;
    }
  } catch (err) {
    console.error("❌ Token decode error:", err);
    return <Navigate to="/login" replace />;
  }
};

export default PrivateRoute;
