/**
 * Profile Page Component
 * 
 * This component displays the current user's profile information
 * and provides a summary of their activity on the blog.
 * 
 * Learning Notes:
 * - User profile data is fetched from the API and displayed
 * - Loading states provide feedback during data fetching
 * - Error handling ensures graceful failure recovery
 * - Bootstrap cards organize information visually
 */

import React, { useState, useEffect } from 'react';
import { Row, Col, Card, Alert, Badge } from 'react-bootstrap';
import { useAuth } from '../contexts/AuthContext';
import { apiService, User } from '../services/api';

const Profile: React.FC = () => {
  // State management
  const [userProfile, setUserProfile] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Auth context (unused but kept for potential future use)
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { user } = useAuth();

  /**
   * Format date for display
   * 
   * Converts ISO date string to a user-friendly format.
   */
  const formatDate = (dateString: string): string => {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    });
  };

  /**
   * Fetch user profile data
   * 
   * Loads detailed profile information from the API.
   */
  const fetchUserProfile = async (): Promise<void> => {
    try {
      setIsLoading(true);
      setError(null);
      
      const response = await apiService.getUserProfile();
      setUserProfile(response.user);
    } catch (err: any) {
      const errorMessage = err.response?.data?.message || 'Failed to load profile';
      setError(errorMessage);
    } finally {
      setIsLoading(false);
    }
  };

  // Load profile data on component mount
  useEffect(() => {
    fetchUserProfile();
  }, []);

  // Loading state
  if (isLoading) {
    return (
      <Row className="justify-content-center">
        <Col md={8}>
          <div className="text-center">
            <div className="spinner-border text-primary" role="status">
              <span className="visually-hidden">Loading profile...</span>
            </div>
            <p className="mt-2">Loading your profile...</p>
          </div>
        </Col>
      </Row>
    );
  }

  // Error state
  if (error) {
    return (
      <Row className="justify-content-center">
        <Col md={8}>
          <Alert variant="danger">
            <Alert.Heading>Error Loading Profile</Alert.Heading>
            <p>{error}</p>
          </Alert>
        </Col>
      </Row>
    );
  }

  return (
    <Row className="justify-content-center">
      <Col md={8}>
        {/* Page Header */}
        <div className="mb-4">
          <h1>My Profile</h1>
          <p className="text-muted">View your account information and activity summary</p>
        </div>

        {/* Profile Information Card */}
        <Card className="mb-4">
          <Card.Header>
            <Card.Title className="mb-0">Account Information</Card.Title>
          </Card.Header>
          <Card.Body>
            <Row>
              <Col md={6}>
                <div className="mb-3">
                  <label className="form-label fw-bold">Username</label>
                  <p className="mb-0">{userProfile?.username}</p>
                </div>
                
                <div className="mb-3">
                  <label className="form-label fw-bold">Email</label>
                  <p className="mb-0">{userProfile?.email}</p>
                </div>
                
                <div className="mb-3">
                  <label className="form-label fw-bold">Member Since</label>
                  <p className="mb-0">
                    {userProfile?.date_created && formatDate(userProfile.date_created)}
                  </p>
                </div>
              </Col>
              
              <Col md={6}>
                <div className="text-center">
                  {/* Profile Avatar Placeholder */}
                  <div 
                    className="bg-primary text-white rounded-circle d-flex align-items-center justify-content-center mx-auto mb-3"
                    style={{ width: '80px', height: '80px', fontSize: '2rem' }}
                  >
                    {userProfile?.username?.charAt(0).toUpperCase()}
                  </div>
                  <h5>{userProfile?.username}</h5>
                  <Badge bg="primary">Active Member</Badge>
                </div>
              </Col>
            </Row>
          </Card.Body>
        </Card>

        {/* Activity Summary Card */}
        <Card>
          <Card.Header>
            <Card.Title className="mb-0">Activity Summary</Card.Title>
          </Card.Header>
          <Card.Body>
            <Row className="text-center">
              <Col md={4}>
                <div className="p-3">
                  <div className="display-6 text-primary fw-bold">
                    {userProfile?.posts_count || 0}
                  </div>
                  <div className="text-muted">Posts Created</div>
                </div>
              </Col>
              
              <Col md={4}>
                <div className="p-3">
                  <div className="display-6 text-success fw-bold">
                    {userProfile?.comments_count || 0}
                  </div>
                  <div className="text-muted">Comments Made</div>
                </div>
              </Col>
              
              <Col md={4}>
                <div className="p-3">
                  <div className="display-6 text-danger fw-bold">
                    {userProfile?.likes_count || 0}
                  </div>
                  <div className="text-muted">Likes Given</div>
                </div>
              </Col>
            </Row>
            
            {/* Activity Level Badge */}
            <div className="text-center mt-3 pt-3 border-top">
              {(() => {
                const totalActivity = (userProfile?.posts_count || 0) + 
                                    (userProfile?.comments_count || 0) + 
                                    (userProfile?.likes_count || 0);
                
                if (totalActivity >= 50) {
                  return <Badge bg="warning" className="px-3 py-2">🏆 Super Active</Badge>;
                } else if (totalActivity >= 20) {
                  return <Badge bg="success" className="px-3 py-2">⭐ Active</Badge>;
                } else if (totalActivity >= 5) {
                  return <Badge bg="primary" className="px-3 py-2">👍 Getting Started</Badge>;
                } else {
                  return <Badge bg="secondary" className="px-3 py-2">🌱 New Member</Badge>;
                }
              })()}
            </div>
          </Card.Body>
        </Card>
      </Col>
    </Row>
  );
};

export default Profile;