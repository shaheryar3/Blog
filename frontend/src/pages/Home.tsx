/**
 * Home Page Component
 * 
 * This is the main page of the blog application where users can:
 * - View all posts from all users
 * - Create new posts
 * - Like and comment on posts
 * - View posts with pagination
 * 
 * Learning Notes:
 * - useEffect with dependency arrays controls when effects run
 * - State management with useState keeps UI in sync with data
 * - Conditional rendering shows different content based on state
 * - Component composition breaks complex UI into manageable pieces
 */

import React, { useState, useEffect } from 'react';
import { Row, Col, Card, Button, Alert } from 'react-bootstrap';
import { useAuth } from '../contexts/AuthContext';
import { apiService, Post, PostsResponse } from '../services/api';
import PostCard from '../components/PostCard';
import CreatePostForm from '../components/CreatePostForm';
import Pagination from '../components/Pagination';

const Home: React.FC = () => {
  // State management
  const [posts, setPosts] = useState<Post[]>([]);
  const [pagination, setPagination] = useState<PostsResponse['pagination'] | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [currentPage, setCurrentPage] = useState(1);
  const [showCreateForm, setShowCreateForm] = useState(false);

  // Auth context
  const { user } = useAuth();

  /**
   * Fetch posts from the API
   * 
   * This function loads posts for the current page and updates state.
   * It's called on component mount and when the page changes.
   */
  const fetchPosts = async (page: number = 1): Promise<void> => {
    try {
      setIsLoading(true);
      setError(null);
      
      const response = await apiService.getPosts(page, 10);
      setPosts(response.posts);
      setPagination(response.pagination);
      setCurrentPage(page);
    } catch (err: any) {
      const errorMessage = err.response?.data?.message || 'Failed to load posts';
      setError(errorMessage);
    } finally {
      setIsLoading(false);
    }
  };

  /**
   * Handle successful post creation
   * 
   * When a new post is created, we add it to the beginning of the posts array
   * and close the creation form.
   */
  const handlePostCreated = (newPost: Post): void => {
    setPosts(prevPosts => [newPost, ...prevPosts]);
    setShowCreateForm(false);
    
    // If we were on a page other than 1, go back to page 1 to see the new post
    if (currentPage !== 1) {
      setCurrentPage(1);
      fetchPosts(1);
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
    fetchPosts(page);
  };

  // Load initial posts on component mount
  useEffect(() => {
    fetchPosts(1);
  }, []);

  return (
    <div>
      {/* Page Header */}
      <Row className="mb-4">
        <Col>
          <div className="d-flex justify-content-between align-items-center">
            <h1>Welcome to the Blog, {user?.username}!</h1>
            <Button 
              variant="primary" 
              onClick={() => setShowCreateForm(!showCreateForm)}
            >
              {showCreateForm ? 'Cancel' : 'Create Post'}
            </Button>
          </div>
        </Col>
      </Row>

      {/* Create Post Form */}
      {showCreateForm && (
        <Row className="mb-4">
          <Col>
            <CreatePostForm 
              onPostCreated={handlePostCreated}
              onCancel={() => setShowCreateForm(false)}
            />
          </Col>
        </Row>
      )}

      {/* Error Alert */}
      {error && (
        <Row className="mb-4">
          <Col>
            <Alert variant="danger" dismissible onClose={() => setError(null)}>
              {error}
            </Alert>
          </Col>
        </Row>
      )}

      {/* Loading State */}
      {isLoading ? (
        <Row>
          <Col className="text-center">
            <div className="spinner-border text-primary" role="status">
              <span className="visually-hidden">Loading posts...</span>
            </div>
            <p className="mt-2">Loading posts...</p>
          </Col>
        </Row>
      ) : (
        <>
          {/* Posts List */}
          {posts.length > 0 ? (
            <>
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
                    <Card.Title>No Posts Yet</Card.Title>
                    <Card.Text>
                      Be the first to share something! Click the "Create Post" button to get started.
                    </Card.Text>
                    <Button 
                      variant="primary" 
                      onClick={() => setShowCreateForm(true)}
                    >
                      Create Your First Post
                    </Button>
                  </Card.Body>
                </Card>
              </Col>
            </Row>
          )}
        </>
      )}
    </div>
  );
};

export default Home;