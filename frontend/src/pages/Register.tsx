/**
 * Register Page Component
 * 
 * This component provides the user registration interface.
 * It includes comprehensive form validation and user feedback.
 * 
 * Learning Notes:
 * - Client-side validation improves user experience by providing immediate feedback
 * - Password confirmation prevents user typos during registration
 * - Consistent error handling provides clear feedback to users
 * - Form state management keeps the UI in sync with user input
 */

import React, { useState } from 'react';
import { Form, Button, Card, Alert, Row, Col } from 'react-bootstrap';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

const Register: React.FC = () => {
  // Form state management
  const [formData, setFormData] = useState({
    email: '',
    username: '',
    password: '',
    password2: '',
  });
  
  // UI state management
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  // Hooks
  const { register } = useAuth();
  const navigate = useNavigate();

  /**
   * Handle form input changes
   * 
   * Updates form state and clears errors when user starts typing.
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
   * Comprehensive form validation
   * 
   * Validates all form fields and returns appropriate error messages.
   * This helps users understand what needs to be corrected.
   */
  const validateForm = (): string | null => {
    // Required field validation
    if (!formData.email.trim()) {
      return 'Email is required';
    }
    
    if (!formData.username.trim()) {
      return 'Username is required';
    }
    
    if (!formData.password) {
      return 'Password is required';
    }
    
    if (!formData.password2) {
      return 'Please confirm your password';
    }
    
    // Email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(formData.email)) {
      return 'Please enter a valid email address';
    }
    
    // Username length validation
    if (formData.username.length < 2) {
      return 'Username must be at least 2 characters long';
    }
    
    // Username format validation (alphanumeric and underscore only)
    const usernameRegex = /^[a-zA-Z0-9_]+$/;
    if (!usernameRegex.test(formData.username)) {
      return 'Username can only contain letters, numbers, and underscores';
    }
    
    // Password length validation
    if (formData.password.length < 6) {
      return 'Password must be at least 6 characters long';
    }
    
    // Password confirmation validation
    if (formData.password !== formData.password2) {
      return 'Passwords do not match';
    }
    
    return null;
  };

  /**
   * Handle form submission
   * 
   * Processes registration with validation and error handling.
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
      // Attempt registration
      await register(
        formData.email,
        formData.username,
        formData.password,
        formData.password2
      );
      
      // Success - redirect to home page
      navigate('/');
    } catch (err: any) {
      // Handle error response
      const errorMessage = err.response?.data?.message || 'Registration failed. Please try again.';
      setError(errorMessage);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Row className="justify-content-center">
      <Col md={6} lg={5}>
        <Card>
          <Card.Body>
            <Card.Title className="text-center mb-4">
              <h3>Create Account</h3>
            </Card.Title>
            
            {/* Error Alert */}
            {error && (
              <Alert variant="danger" dismissible onClose={() => setError(null)}>
                {error}
              </Alert>
            )}
            
            {/* Registration Form */}
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
                <Form.Text className="text-muted">
                  We'll never share your email with anyone else.
                </Form.Text>
              </Form.Group>
              
              {/* Username Field */}
              <Form.Group className="mb-3">
                <Form.Label>Username</Form.Label>
                <Form.Control
                  type="text"
                  name="username"
                  value={formData.username}
                  onChange={handleChange}
                  placeholder="Choose a username"
                  disabled={isLoading}
                  required
                />
                <Form.Text className="text-muted">
                  Use letters, numbers, and underscores only. Minimum 2 characters.
                </Form.Text>
              </Form.Group>
              
              {/* Password Field */}
              <Form.Group className="mb-3">
                <Form.Label>Password</Form.Label>
                <Form.Control
                  type="password"
                  name="password"
                  value={formData.password}
                  onChange={handleChange}
                  placeholder="Create a password"
                  disabled={isLoading}
                  required
                />
                <Form.Text className="text-muted">
                  Minimum 6 characters.
                </Form.Text>
              </Form.Group>
              
              {/* Confirm Password Field */}
              <Form.Group className="mb-3">
                <Form.Label>Confirm Password</Form.Label>
                <Form.Control
                  type="password"
                  name="password2"
                  value={formData.password2}
                  onChange={handleChange}
                  placeholder="Confirm your password"
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
                      Creating Account...
                    </>
                  ) : (
                    'Create Account'
                  )}
                </Button>
              </div>
            </Form>
            
            {/* Login Link */}
            <div className="text-center mt-3">
              <p className="mb-0">
                Already have an account?{' '}
                <Link to="/login" className="text-decoration-none">
                  Sign in here
                </Link>
              </p>
            </div>
          </Card.Body>
        </Card>
      </Col>
    </Row>
  );
};

export default Register;