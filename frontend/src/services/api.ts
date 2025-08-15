/**
 * API Service for Blog Application
 * 
 * This module handles all HTTP requests to the Flask backend API.
 * It manages authentication tokens and provides methods for all blog operations.
 * 
 * Learning Notes:
 * - Axios is a popular HTTP client library for JavaScript
 * - Interceptors allow automatic handling of common concerns (auth headers, error handling)
 * - TypeScript interfaces define the shape of data objects for type safety
 * - Local storage is used to persist authentication tokens
 */

import axios from 'axios';

// Base URL for the Flask API
const API_BASE_URL = 'http://localhost:5000/api';

// Create axios instance with base configuration
const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// TypeScript interfaces for type safety
export interface User {
  id: number;
  username: string;
  email: string;
  date_created?: string;
  posts_count?: number;
  comments_count?: number;
  likes_count?: number;
}

export interface Post {
  id: number;
  text: string;
  date_created: string;
  author: {
    id: number;
    username: string;
  };
  likes_count: number;
  comments_count: number;
  user_liked: boolean;
}

export interface Comment {
  id: number;
  text: string;
  date_created: string;
  author: {
    id: number;
    username: string;
  };
  can_delete: boolean;
}

export interface AuthResponse {
  message: string;
  token: string;
  user: User;
}

export interface PostsResponse {
  posts: Post[];
  pagination: {
    page: number;
    pages: number;
    per_page: number;
    total: number;
    has_next: boolean;
    has_prev: boolean;
  };
}

export interface CommentsResponse {
  comments: Comment[];
}

// Token management
export const TokenManager = {
  /**
   * Get authentication token from localStorage
   */
  getToken: (): string | null => {
    return localStorage.getItem('authToken');
  },

  /**
   * Save authentication token to localStorage
   */
  setToken: (token: string): void => {
    localStorage.setItem('authToken', token);
  },

  /**
   * Remove authentication token from localStorage
   */
  removeToken: (): void => {
    localStorage.removeItem('authToken');
  },

  /**
   * Check if user is authenticated
   */
  isAuthenticated: (): boolean => {
    return !!TokenManager.getToken();
  }
};

// Request interceptor to add authentication token
api.interceptors.request.use(
  (config) => {
    const token = TokenManager.getToken();
    if (token && config.headers) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor to handle authentication errors
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Token expired or invalid, remove it
      TokenManager.removeToken();
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// API Service Class
class ApiService {
  /**
   * Authentication Methods
   */
  
  /**
   * Register a new user
   */
  async register(userData: {
    email: string;
    username: string;
    password: string;
    password2: string;
  }): Promise<AuthResponse> {
    const response = await api.post('/auth/register', userData);
    const data = response.data as AuthResponse;
    
    // Save token automatically after successful registration
    if (data.token) {
      TokenManager.setToken(data.token);
    }
    
    return data;
  }

  /**
   * Login user
   */
  async login(credentials: {
    email: string;
    password: string;
  }): Promise<AuthResponse> {
    const response = await api.post('/auth/login', credentials);
    const data = response.data as AuthResponse;
    
    // Save token automatically after successful login
    if (data.token) {
      TokenManager.setToken(data.token);
    }
    
    return data;
  }

  /**
   * Logout user (client-side only)
   */
  logout(): void {
    TokenManager.removeToken();
  }

  /**
   * Post Methods
   */
  
  /**
   * Get all posts with pagination
   */
  async getPosts(page: number = 1, perPage: number = 10): Promise<PostsResponse> {
    const response = await api.get('/posts', {
      params: { page, per_page: perPage }
    });
    return response.data as PostsResponse;
  }

  /**
   * Create a new post
   */
  async createPost(text: string): Promise<{ message: string; post: Post }> {
    const response = await api.post('/posts', { text });
    return response.data as { message: string; post: Post };
  }

  /**
   * Delete a post
   */
  async deletePost(postId: number): Promise<{ message: string }> {
    const response = await api.delete(`/posts/${postId}`);
    return response.data as { message: string };
  }

  /**
   * Get posts by a specific user
   */
  async getUserPosts(username: string, page: number = 1, perPage: number = 10): Promise<{
    user: { id: number; username: string };
    posts: Post[];
    pagination: PostsResponse['pagination'];
  }> {
    const response = await api.get(`/users/${username}/posts`, {
      params: { page, per_page: perPage }
    });
    return response.data as {
      user: { id: number; username: string };
      posts: Post[];
      pagination: PostsResponse['pagination'];
    };
  }

  /**
   * Comment Methods
   */
  
  /**
   * Get comments for a post
   */
  async getComments(postId: number): Promise<CommentsResponse> {
    const response = await api.get(`/posts/${postId}/comments`);
    return response.data as CommentsResponse;
  }

  /**
   * Create a comment on a post
   */
  async createComment(postId: number, text: string): Promise<{ message: string; comment: Comment }> {
    const response = await api.post(`/posts/${postId}/comments`, { text });
    return response.data as { message: string; comment: Comment };
  }

  /**
   * Delete a comment
   */
  async deleteComment(commentId: number): Promise<{ message: string }> {
    const response = await api.delete(`/comments/${commentId}`);
    return response.data as { message: string };
  }

  /**
   * Like Methods
   */
  
  /**
   * Toggle like on a post
   */
  async toggleLike(postId: number): Promise<{
    message: string;
    liked: boolean;
    likes_count: number;
  }> {
    const response = await api.post(`/posts/${postId}/like`);
    return response.data as {
      message: string;
      liked: boolean;
      likes_count: number;
    };
  }

  /**
   * User Methods
   */
  
  /**
   * Get current user profile
   */
  async getUserProfile(): Promise<{ user: User }> {
    const response = await api.get('/user/profile');
    return response.data as { user: User };
  }
}

// Export singleton instance
export const apiService = new ApiService();
export default apiService;