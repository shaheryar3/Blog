/**
 * Create Post Form Component
 * 
 * This component provides a form for creating new blog posts.
 * It includes validation, character counting, and real-time feedback.
 * 
 * Learning Notes:
 * - Controlled components keep form state in React state
 * - Character counting helps users stay within limits
 * - Form validation provides immediate user feedback
 * - Component callbacks communicate with parent components
 */

import React, { useState } from 'react';
import { Card, Form, Button, Alert, Row, Col } from 'react-bootstrap';
import { apiService, Post } from '../services/api';

// Component props interface
interface CreatePostFormProps {
  onPostCreated: (post: Post) => void;
  onCancel: () => void;
}

const CreatePostForm: React.FC<CreatePostFormProps> = ({ onPostCreated, onCancel }) => {
  // State management
  const [postText, setPostText] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Configuration
  const MAX_CHARACTERS = 2000;
  const MIN_CHARACTERS = 1;

  /**
   * Get character count styling based on remaining characters
   * 
   * Provides visual feedback as users approach the character limit.
   */
  const getCharacterCountColor = (): string => {
    const remaining = MAX_CHARACTERS - postText.length;
    if (remaining < 50) return 'text-danger';
    if (remaining < 100) return 'text-warning';
    return 'text-muted';
  };

  /**
   * Validate post content
   * 
   * Checks if the post content meets requirements.
   */
  const validatePost = (): string | null => {
    if (postText.trim().length < MIN_CHARACTERS) {
      return 'Post cannot be empty';
    }
    
    if (postText.length > MAX_CHARACTERS) {
      return `Post cannot exceed ${MAX_CHARACTERS} characters`;
    }
    
    return null;
  };

  /**
   * Handle form submission
   * 
   * Validates input, creates the post, and handles success/error states.
   */
  const handleSubmit = async (e: React.FormEvent): Promise<void> => {
    e.preventDefault();
    
    // Validate input
    const validationError = validatePost();
    if (validationError) {
      setError(validationError);
      return;
    }
    
    setIsSubmitting(true);
    setError(null);
    
    try {
      // Create the post
      const response = await apiService.createPost(postText.trim());
      
      // Notify parent component of successful creation
      onPostCreated(response.post);
      
      // Reset form
      setPostText('');
    } catch (err: any) {
      // Handle error
      const errorMessage = err.response?.data?.message || 'Failed to create post';
      setError(errorMessage);
    } finally {
      setIsSubmitting(false);
    }
  };

  /**
   * Handle text area change
   * 
   * Updates state and clears errors when user types.
   */
  const handleTextChange = (e: React.ChangeEvent<HTMLTextAreaElement>): void => {
    const value = e.target.value;
    
    // Prevent exceeding max characters
    if (value.length <= MAX_CHARACTERS) {
      setPostText(value);
      
      // Clear error when user starts typing
      if (error) {
        setError(null);
      }
    }
  };

  /**
   * Handle cancel action
   * 
   * Clears form and notifies parent component.
   */
  const handleCancel = (): void => {
    setPostText('');
    setError(null);
    onCancel();
  };

  return (
    <Card>
      <Card.Header>
        <Card.Title className="mb-0">Create New Post</Card.Title>
      </Card.Header>
      
      <Card.Body>
        {/* Error Alert */}
        {error && (
          <Alert variant="danger" dismissible onClose={() => setError(null)}>
            {error}
          </Alert>
        )}
        
        <Form onSubmit={handleSubmit}>
          {/* Post Content Text Area */}
          <Form.Group className="mb-3">
            <Form.Label>What's on your mind?</Form.Label>
            <Form.Control
              as="textarea"
              rows={4}
              value={postText}
              onChange={handleTextChange}
              placeholder="Share your thoughts, experiences, or anything interesting..."
              disabled={isSubmitting}
              className="resize-none"
            />
            
            {/* Character Count */}
            <Form.Text className={getCharacterCountColor()}>
              {postText.length} / {MAX_CHARACTERS} characters
              {postText.length > MAX_CHARACTERS - 100 && (
                <span className="ms-2">
                  ({MAX_CHARACTERS - postText.length} remaining)
                </span>
              )}
            </Form.Text>
          </Form.Group>
          
          {/* Action Buttons */}
          <Row>
            <Col>
              <div className="d-flex gap-2">
                <Button
                  type="submit"
                  variant="primary"
                  disabled={isSubmitting || !postText.trim()}
                >
                  {isSubmitting ? (
                    <>
                      <span className="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>
                      Publishing...
                    </>
                  ) : (
                    'Publish Post'
                  )}
                </Button>
                
                <Button
                  type="button"
                  variant="secondary"
                  onClick={handleCancel}
                  disabled={isSubmitting}
                >
                  Cancel
                </Button>
              </div>
            </Col>
          </Row>
        </Form>
        
        {/* Helpful Tips */}
        <div className="mt-3">
          <small className="text-muted">
            <strong>Tips:</strong>
            <ul className="mb-0 mt-1">
              <li>Share interesting thoughts, experiences, or discoveries</li>
              <li>Use line breaks to organize longer posts</li>
              <li>Be respectful and constructive in your posts</li>
            </ul>
          </small>
        </div>
      </Card.Body>
    </Card>
  );
};

export default CreatePostForm;