/**
 * Post Card Component
 * 
 * This component displays individual blog posts with interactive features:
 * - Like/unlike functionality
 * - Comments display and creation
 * - Post deletion (for post owners)
 * - User navigation
 * 
 * Learning Notes:
 * - Component props define the interface between parent and child components
 * - Event handlers manage user interactions and communicate with parent components
 * - Conditional rendering shows different UI based on user permissions
 * - Bootstrap components provide consistent styling and responsive design
 */

import React, { useState } from 'react';
import { Card, Button, Row, Col, Collapse, Form, Alert, Dropdown } from 'react-bootstrap';
import { Link } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { apiService, Post, Comment } from '../services/api';

// Component props interface
interface PostCardProps {
  post: Post;
  onPostDeleted: (postId: number) => void;
  onPostLiked: (postId: number, liked: boolean, likesCount: number) => void;
  className?: string;
}

const PostCard: React.FC<PostCardProps> = ({ 
  post, 
  onPostDeleted, 
  onPostLiked, 
  className = '' 
}) => {
  // State management
  const [showComments, setShowComments] = useState(false);
  const [comments, setComments] = useState<Comment[]>([]);
  const [commentsLoaded, setCommentsLoaded] = useState(false);
  const [newComment, setNewComment] = useState('');
  const [isSubmittingComment, setIsSubmittingComment] = useState(false);
  const [isLiking, setIsLiking] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Auth context
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
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  /**
   * Toggle like on post
   * 
   * Handles the like/unlike functionality with optimistic updates.
   */
  const handleLike = async (): Promise<void> => {
    if (isLiking) return;
    
    setIsLiking(true);
    setError(null);
    
    try {
      const response = await apiService.toggleLike(post.id);
      onPostLiked(post.id, response.liked, response.likes_count);
    } catch (err: any) {
      const errorMessage = err.response?.data?.message || 'Failed to update like';
      setError(errorMessage);
    } finally {
      setIsLiking(false);
    }
  };

  /**
   * Delete post
   * 
   * Handles post deletion with confirmation.
   */
  const handleDelete = async (): Promise<void> => {
    if (isDeleting) return;
    
    // Confirm deletion
    if (!window.confirm('Are you sure you want to delete this post?')) {
      return;
    }
    
    setIsDeleting(true);
    setError(null);
    
    try {
      await apiService.deletePost(post.id);
      onPostDeleted(post.id);
    } catch (err: any) {
      const errorMessage = err.response?.data?.message || 'Failed to delete post';
      setError(errorMessage);
    } finally {
      setIsDeleting(false);
    }
  };

  /**
   * Load comments for the post
   * 
   * Fetches comments when the comments section is expanded.
   */
  const loadComments = async (): Promise<void> => {
    if (commentsLoaded) return;
    
    try {
      const response = await apiService.getComments(post.id);
      setComments(response.comments);
      setCommentsLoaded(true);
    } catch (err: any) {
      const errorMessage = err.response?.data?.message || 'Failed to load comments';
      setError(errorMessage);
    }
  };

  /**
   * Toggle comments visibility
   * 
   * Shows/hides comments and loads them if necessary.
   */
  const toggleComments = (): void => {
    const newShowComments = !showComments;
    setShowComments(newShowComments);
    
    if (newShowComments && !commentsLoaded) {
      loadComments();
    }
  };

  /**
   * Submit new comment
   * 
   * Handles comment creation and updates local state.
   */
  const handleCommentSubmit = async (e: React.FormEvent): Promise<void> => {
    e.preventDefault();
    
    if (!newComment.trim() || isSubmittingComment) return;
    
    setIsSubmittingComment(true);
    setError(null);
    
    try {
      const response = await apiService.createComment(post.id, newComment.trim());
      setComments(prev => [...prev, response.comment]);
      setNewComment('');
    } catch (err: any) {
      const errorMessage = err.response?.data?.message || 'Failed to create comment';
      setError(errorMessage);
    } finally {
      setIsSubmittingComment(false);
    }
  };

  /**
   * Delete comment
   * 
   * Handles comment deletion with confirmation.
   */
  const handleCommentDelete = async (commentId: number): Promise<void> => {
    if (!window.confirm('Are you sure you want to delete this comment?')) {
      return;
    }
    
    try {
      await apiService.deleteComment(commentId);
      setComments(prev => prev.filter(comment => comment.id !== commentId));
    } catch (err: any) {
      const errorMessage = err.response?.data?.message || 'Failed to delete comment';
      setError(errorMessage);
    }
  };

  return (
    <Card className={className}>
      <Card.Header>
        <Row className="align-items-center">
          <Col>
            <Link 
              to={`/users/${post.author.username}`} 
              className="text-decoration-none fw-bold"
            >
              {post.author.username}
            </Link>
            <small className="text-muted ms-2">
              {formatDate(post.date_created)}
            </small>
          </Col>
          <Col xs="auto">
            {/* Post actions dropdown (only for post owner) */}
            {user?.id === post.author.id && (
              <Dropdown>
                <Dropdown.Toggle variant="link" size="sm" className="text-muted">
                  ⋮
                </Dropdown.Toggle>
                <Dropdown.Menu>
                  <Dropdown.Item 
                    onClick={handleDelete}
                    disabled={isDeleting}
                    className="text-danger"
                  >
                    {isDeleting ? 'Deleting...' : 'Delete Post'}
                  </Dropdown.Item>
                </Dropdown.Menu>
              </Dropdown>
            )}
          </Col>
        </Row>
      </Card.Header>

      <Card.Body>
        {/* Error Alert */}
        {error && (
          <Alert variant="danger" dismissible onClose={() => setError(null)} className="mb-3">
            {error}
          </Alert>
        )}

        {/* Post Content */}
        <Card.Text style={{ whiteSpace: 'pre-wrap' }}>
          {post.text}
        </Card.Text>

        {/* Post Actions */}
        <Row className="align-items-center">
          <Col>
            {/* Like Button */}
            <Button
              variant={post.user_liked ? "danger" : "outline-danger"}
              size="sm"
              onClick={handleLike}
              disabled={isLiking}
              className="me-2"
            >
              {isLiking ? (
                <span className="spinner-border spinner-border-sm me-1" />
              ) : (
                post.user_liked ? '❤️' : '🤍'
              )}
              {post.likes_count}
            </Button>

            {/* Comments Button */}
            <Button
              variant="outline-primary"
              size="sm"
              onClick={toggleComments}
            >
              💬 {post.comments_count} Comments
            </Button>
          </Col>
        </Row>

        {/* Comments Section */}
        <Collapse in={showComments}>
          <div className="mt-3">
            {/* Comments List */}
            {comments.length > 0 && (
              <div className="mb-3">
                {comments.map(comment => (
                  <div key={comment.id} className="border-start ps-3 py-2 mb-2">
                    <div className="d-flex justify-content-between align-items-start">
                      <div className="flex-grow-1">
                        <Link 
                          to={`/users/${comment.author.username}`}
                          className="text-decoration-none fw-bold"
                        >
                          {comment.author.username}
                        </Link>
                        <small className="text-muted ms-2">
                          {formatDate(comment.date_created)}
                        </small>
                        <p className="mb-0 mt-1" style={{ whiteSpace: 'pre-wrap' }}>
                          {comment.text}
                        </p>
                      </div>
                      {comment.can_delete && (
                        <Button
                          variant="link"
                          size="sm"
                          className="text-danger p-0 ms-2"
                          onClick={() => handleCommentDelete(comment.id)}
                        >
                          ✕
                        </Button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Add Comment Form */}
            <Form onSubmit={handleCommentSubmit}>
              <Row>
                <Col>
                  <Form.Control
                    type="text"
                    placeholder="Add a comment..."
                    value={newComment}
                    onChange={(e) => setNewComment(e.target.value)}
                    disabled={isSubmittingComment}
                  />
                </Col>
                <Col xs="auto">
                  <Button 
                    type="submit" 
                    variant="primary" 
                    size="sm"
                    disabled={!newComment.trim() || isSubmittingComment}
                  >
                    {isSubmittingComment ? (
                      <span className="spinner-border spinner-border-sm" />
                    ) : (
                      'Post'
                    )}
                  </Button>
                </Col>
              </Row>
            </Form>
          </div>
        </Collapse>
      </Card.Body>
    </Card>
  );
};

export default PostCard;