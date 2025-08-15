/**
 * Login Page Component
 * 
 * This component provides the user authentication interface.
 * It handles form validation, API calls, and error display.
 * 
 * Learning Notes:
 * - Controlled components in React manage form state through React state
 * - Form validation provides immediate feedback to users
 * - Try-catch blocks handle API errors gracefully
 * - Bootstrap forms provide consistent styling and layout
 */

import React, { useState } from 'react';
import { Form, Button, Card, Alert, Row, Col } from 'react-bootstrap';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

const Login: React.FC = () => {
  // Form state management
  const [formData, setFormData] = useState({
    email: '',
    password: '',
  });
  
  // UI state management
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  // Hooks
  const { login } = useAuth();
  const navigate = useNavigate();

  /**
   * Handle form input changes
   * 
   * This function updates the form state when user types in input fields.
   * It uses the name attribute of the input to determine which field to update.
   */
  const handleChange = (e: React.ChangeEvent<HTMLInputElement>): void => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
    
    // Clear error when user starts typing
    if (error) {
      setError(null);
    }
  };

  /**
   * Validate form data
   * 
   * Performs client-side validation before submitting to the API.
   * Returns an error message if validation fails, null if valid.
   */
  const validateForm = (): string | null => {
    if (!formData.email.trim()) {
      return 'Email is required';
    }
    
    if (!formData.password) {
      return 'Password is required';
    }
    
    // Basic email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(formData.email)) {
      return 'Please enter a valid email address';
    }
    
    return null;
  };

  /**
   * Handle form submission
   * 
   * This function processes the login form when submitted.
   * It validates data, calls the API, and handles success/error states.
   */
  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>): Promise<void> => {
    e.preventDefault();
    
    // Validate form
    const validationError = validateForm();
    if (validationError) {
      setError(validationError);
      return;
    }
    
    setIsLoading(true);
    setError(null);
    
    try {
      // Attempt login
      await login(formData.email, formData.password);
      
      // Success - redirect to home page
      navigate('/');
    } catch (err: any) {
      // Handle error response
      const errorMessage = err.response?.data?.message || 'Login failed. Please try again.';
      setError(errorMessage);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Row className="justify-content-center">
      <Col md={6} lg={4}>
        <Card>
          <Card.Body>
            <Card.Title className="text-center mb-4">
              <h3>Sign In</h3>
            </Card.Title>
            
            {/* Error Alert */}
            {error && (
              <Alert variant="danger" dismissible onClose={() => setError(null)}>
                {error}
              </Alert>
            )}
            
            {/* Login Form */}
            <Form onSubmit={handleSubmit}>
              {/* Email Field */}
              <Form.Group className="mb-3">
                <Form.Label>Email Address</Form.Label>
                <Form.Control
                  type="email"
                  name="email"
                  value={formData.email}
                  onChange={handleChange}
                  placeholder="Enter your email"
                  disabled={isLoading}
                  required
                />
              </Form.Group>
              
              {/* Password Field */}
              <Form.Group className="mb-3">
                <Form.Label>Password</Form.Label>
                <Form.Control
                  type="password"
                  name="password"
                  value={formData.password}
                  onChange={handleChange}
                  placeholder="Enter your password"
                  disabled={isLoading}
                  required
                />
              </Form.Group>
              
              {/* Submit Button */}
              <div className="d-grid">
                <Button 
                  variant="primary" 
                  type="submit" 
                  disabled={isLoading}
                  size="lg"
                >
                  {isLoading ? (
                    <>
                      <span className="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>
                      Signing In...
                    </>
                  ) : (
                    'Sign In'
                  )}
                </Button>
              </div>
            </Form>
            
            {/* Register Link */}
            <div className="text-center mt-3">
              <p className="mb-0">
                Don't have an account?{' '}
                <Link to="/register" className="text-decoration-none">
                  Sign up here
                </Link>
              </p>
            </div>
          </Card.Body>
        </Card>
      </Col>
    </Row>
  );
};

export default Login;