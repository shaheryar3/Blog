/**
 * User Posts Page Component
 * 
 * This component displays all posts from a specific user.
 * It includes user information and paginated post listing.
 * 
 * Learning Notes:
 * - URL parameters are accessed using React Router hooks
 * - Component state manages both user data and posts data
 * - Error handling provides feedback for invalid users
 * - Reusable components (PostCard, Pagination) reduce code duplication
 */

import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { Row, Col, Card, Alert, Badge } from 'react-bootstrap';
import { useAuth } from '../contexts/AuthContext';
import { apiService, Post } from '../services/api';
import PostCard from '../components/PostCard';
import Pagination from '../components/Pagination';

// URL parameters interface (removed as using inline type now)

const UserPosts: React.FC = () => {
  // URL parameters
  const { username } = useParams<{ username: string }>();
  
  // State management
  const [posts, setPosts] = useState<Post[]>([]);
  const [userInfo, setUserInfo] = useState<{ id: number; username: string } | null>(null);
  const [pagination, setPagination] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Auth context
  const { user: currentUser } = useAuth();

  /**
   * Fetch user posts from the API
   * 
   * Loads posts for the specified user with pagination.
   */
  const fetchUserPosts = async (page: number = 1): Promise<void> => {
    if (!username) return;
    
    try {
      setIsLoading(true);
      setError(null);
      
      const response = await apiService.getUserPosts(username, page, 10);
      setPosts(response.posts);
      setUserInfo(response.user);
      setPagination(response.pagination);
    } catch (err: any) {
      const errorMessage = err.response?.data?.message || 'Failed to load user posts';
      setError(errorMessage);
    } finally {
      setIsLoading(false);
    }
  };

  /**
   * Handle post deletion
   * 
   * Removes the deleted post from the local state.
   */
  const handlePostDeleted = (postId: number): void => {
    setPosts(prevPosts => prevPosts.filter(post => post.id !== postId));
  };

  /**
   * Handle post like/unlike
   * 
   * Updates the post's like status and count in local state.
   */
  const handlePostLiked = (postId: number, liked: boolean, likesCount: number): void => {
    setPosts(prevPosts => 
      prevPosts.map(post => 
        post.id === postId 
          ? { ...post, user_liked: liked, likes_count: likesCount }
          : post
      )
    );
  };

  /**
   * Handle page change
   * 
   * Fetches posts for the new page.
   */
  const handlePageChange = (page: number): void => {
    fetchUserPosts(page);
  };

  // Load user posts on component mount and when username changes
  useEffect(() => {
    if (username) {
      fetchUserPosts(1);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [username]);

  // Loading state
  if (isLoading) {
    return (
      <Row>
        <Col className="text-center">
          <div className="spinner-border text-primary" role="status">
            <span className="visually-hidden">Loading posts...</span>
          </div>
          <p className="mt-2">Loading {username}'s posts...</p>
        </Col>
      </Row>
    );
  }

  // Error state
  if (error) {
    return (
      <Row>
        <Col>
          <Alert variant="danger">
            <Alert.Heading>Error Loading Posts</Alert.Heading>
            <p>{error}</p>
          </Alert>
        </Col>
      </Row>
    );
  }

  // Check if this is the current user's profile
  const isOwnProfile = currentUser?.username === username;

  return (
    <div>
      {/* User Header */}
      <Row className="mb-4">
        <Col>
          <Card>
            <Card.Body>
              <Row className="align-items-center">
                <Col>
                  <div className="d-flex align-items-center">
                    {/* User Avatar */}
                    <div 
                      className="bg-primary text-white rounded-circle d-flex align-items-center justify-content-center me-3"
                      style={{ width: '60px', height: '60px', fontSize: '1.5rem' }}
                    >
                      {userInfo?.username?.charAt(0).toUpperCase()}
                    </div>
                    
                    <div>
                      <h2 className="mb-1">
                        {userInfo?.username}
                        {isOwnProfile && (
                          <Badge bg="primary" className="ms-2">You</Badge>
                        )}
                      </h2>
                      <p className="text-muted mb-0">
                        {posts.length === 0 && 'No posts yet'}
                        {posts.length === 1 && '1 post'}
                        {posts.length > 1 && `${pagination?.total || posts.length} posts`}
                      </p>
                    </div>
                  </div>
                </Col>
              </Row>
            </Card.Body>
          </Card>
        </Col>
      </Row>

      {/* Posts Section */}
      {posts.length > 0 ? (
        <>
          {/* Posts List */}
          <Row>
            <Col>
              {posts.map(post => (
                <PostCard
                  key={post.id}
                  post={post}
                  onPostDeleted={handlePostDeleted}
                  onPostLiked={handlePostLiked}
                  className="mb-3"
                />
              ))}
            </Col>
          </Row>

          {/* Pagination */}
          {pagination && pagination.pages > 1 && (
            <Row className="mt-4">
              <Col>
                <Pagination
                  currentPage={pagination.page}
                  totalPages={pagination.pages}
                  onPageChange={handlePageChange}
                />
              </Col>
            </Row>
          )}
        </>
      ) : (
        /* Empty State */
        <Row>
          <Col>
            <Card className="text-center">
              <Card.Body>
                <div className="py-5">
                  <h4 className="text-muted mb-3">No Posts Yet</h4>
                  <p className="text-muted">
                    {isOwnProfile 
                      ? "You haven't created any posts yet. Share your first thought!"
                      : `${userInfo?.username} hasn't shared any posts yet.`
                    }
                  </p>
                  {isOwnProfile && (
                    <div className="mt-3">
                      <a href="/" className="btn btn-primary">
                        Create Your First Post
                      </a>
                    </div>
                  )}
                </div>
              </Card.Body>
            </Card>
          </Col>
        </Row>
      )}
    </div>
  );
};

export default UserPosts;