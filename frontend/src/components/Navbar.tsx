/**
 * Navigation Bar Component
 * 
 * This component provides the main navigation for the application.
 * It displays different options based on authentication status.
 * 
 * Learning Notes:
 * - Bootstrap Navbar provides responsive navigation
 * - Conditional rendering shows different content based on state
 * - React Router Link components enable client-side navigation
 * - Event handlers manage user interactions (logout, etc.)
 */

import React from 'react';
import { Navbar as BootstrapNavbar, Nav, Container, Button } from 'react-bootstrap';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

const Navbar: React.FC = () => {
  const { user, isAuthenticated, logout } = useAuth();
  const navigate = useNavigate();

  /**
   * Handle user logout
   * 
   * Logs out the user and redirects to login page
   */
  const handleLogout = (): void => {
    logout();
    navigate('/login');
  };

  return (
    <BootstrapNavbar bg="dark" variant="dark" expand="lg" sticky="top">
      <Container>
        {/* Brand/Logo */}
        <BootstrapNavbar.Brand as={Link} to="/">
          📝 My Blog
        </BootstrapNavbar.Brand>

        {/* Mobile menu toggle */}
        <BootstrapNavbar.Toggle aria-controls="basic-navbar-nav" />
        
        <BootstrapNavbar.Collapse id="basic-navbar-nav">
          <Nav className="me-auto">
            {/* Navigation items for authenticated users */}
            {isAuthenticated && (
              <>
                <Nav.Link as={Link} to="/">
                  Home
                </Nav.Link>
                <Nav.Link as={Link} to="/profile">
                  Profile
                </Nav.Link>
              </>
            )}
          </Nav>

          {/* Right side navigation */}
          <Nav className="ms-auto">
            {isAuthenticated ? (
              /* Authenticated user options */
              <>
                <BootstrapNavbar.Text className="me-3">
                  Welcome, <strong>{user?.username}</strong>!
                </BootstrapNavbar.Text>
                <Button variant="outline-light" onClick={handleLogout}>
                  Logout
                </Button>
              </>
            ) : (
              /* Non-authenticated user options */
              <>
                <Nav.Link as={Link} to="/login">
                  Login
                </Nav.Link>
                <Nav.Link as={Link} to="/register">
                  Register
                </Nav.Link>
              </>
            )}
          </Nav>
        </BootstrapNavbar.Collapse>
      </Container>
    </BootstrapNavbar>
  );
};

export default Navbar;