/**
 * Main Application Component
 * 
 * This is the root component of the React application.
 * It sets up routing, authentication context, and the overall app structure.
 * 
 * Learning Notes:
 * - React Router provides client-side routing for single-page applications
 * - Bootstrap provides responsive CSS framework for quick styling
 * - Context Providers wrap components to share state across the app
 * - Conditional rendering shows different content based on authentication state
 */

import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import Navbar from './components/Navbar';
import Home from './pages/Home';
import Login from './pages/Login';
import Register from './pages/Register';
import UserPosts from './pages/UserPosts';
import Profile from './pages/Profile';
import 'bootstrap/dist/css/bootstrap.min.css';
import './App.css';

/**
 * Protected Route Component
 * 
 * This component ensures that certain routes are only accessible
 * to authenticated users. If not authenticated, it redirects to login.
 */
interface ProtectedRouteProps {
  children: React.ReactNode;
}

const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ children }) => {
  const { isAuthenticated, isLoading } = useAuth();

  // Show loading spinner while checking authentication
  if (isLoading) {
    return (
      <div className="d-flex justify-content-center align-items-center" style={{ height: '100vh' }}>
        <div className="spinner-border text-primary" role="status">
          <span className="visually-hidden">Loading...</span>
        </div>
      </div>
    );
  }

  // Redirect to login if not authenticated
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
};

/**
 * Public Route Component
 * 
 * This component ensures that authentication routes (login, register)
 * are not accessible to already authenticated users.
 */
const PublicRoute: React.FC<ProtectedRouteProps> = ({ children }) => {
  const { isAuthenticated, isLoading } = useAuth();

  // Show loading spinner while checking authentication
  if (isLoading) {
    return (
      <div className="d-flex justify-content-center align-items-center" style={{ height: '100vh' }}>
        <div className="spinner-border text-primary" role="status">
          <span className="visually-hidden">Loading...</span>
        </div>
      </div>
    );
  }

  // Redirect to home if already authenticated
  if (isAuthenticated) {
    return <Navigate to="/" replace />;
  }

  return <>{children}</>;
};

/**
 * App Routes Component
 * 
 * Defines all the routes in the application.
 * Separated from App component for better organization.
 */
const AppRoutes: React.FC = () => {
  return (
    <div className="App">
      <Navbar />
      <div className="container mt-4">
        <Routes>
          {/* Protected Routes - Require Authentication */}
          <Route 
            path="/" 
            element={
              <ProtectedRoute>
                <Home />
              </ProtectedRoute>
            } 
          />
          <Route 
            path="/profile" 
            element={
              <ProtectedRoute>
                <Profile />
              </ProtectedRoute>
            } 
          />
          <Route 
            path="/users/:username" 
            element={
              <ProtectedRoute>
                <UserPosts />
              </ProtectedRoute>
            } 
          />

          {/* Public Routes - For Non-Authenticated Users */}
          <Route 
            path="/login" 
            element={
              <PublicRoute>
                <Login />
              </PublicRoute>
            } 
          />
          <Route 
            path="/register" 
            element={
              <PublicRoute>
                <Register />
              </PublicRoute>
            } 
          />

          {/* Catch-all route - redirect to home */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </div>
    </div>
  );
};

/**
 * Main App Component
 * 
 * This is the entry point of the application.
 * It wraps everything with necessary providers and router.
 */
const App: React.FC = () => {
  return (
    <Router>
      <AuthProvider>
        <AppRoutes />
      </AuthProvider>
    </Router>
  );
};

export default App;
