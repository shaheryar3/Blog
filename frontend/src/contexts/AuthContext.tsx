/**
 * Authentication Context
 * 
 * This React Context provides authentication state management across the entire application.
 * It handles user login, logout, and authentication state persistence.
 * 
 * Learning Notes:
 * - React Context allows data to be shared across components without prop drilling
 * - useContext hook provides an easy way to consume context values
 * - Custom hooks encapsulate complex logic and make it reusable
 * - useEffect with empty dependency array runs once on component mount
 */

import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { User, TokenManager, apiService } from '../services/api';

// Define the shape of our authentication context
interface AuthContextType {
  user: User | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, username: string, password: string, password2: string) => Promise<void>;
  logout: () => void;
  updateUser: (user: User) => void;
}

// Create the context with default values
const AuthContext = createContext<AuthContextType | undefined>(undefined);

// Props for the AuthProvider component
interface AuthProviderProps {
  children: ReactNode;
}

/**
 * AuthProvider Component
 * 
 * This component wraps the entire application and provides authentication state.
 * It automatically checks for existing authentication tokens on app startup.
 */
export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  // State management
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  /**
   * Initialize authentication state on app startup
   * 
   * This effect runs once when the component mounts and checks
   * if there's a valid authentication token in localStorage.
   */
  useEffect(() => {
    const initializeAuth = async () => {
      try {
        // Check if we have a token
        if (TokenManager.isAuthenticated()) {
          // Try to fetch user profile to validate token
          const response = await apiService.getUserProfile();
          setUser(response.user);
          setIsAuthenticated(true);
        }
      } catch (error) {
        // Token is invalid, clear it
        console.error('Token validation failed:', error);
        TokenManager.removeToken();
        setUser(null);
        setIsAuthenticated(false);
      } finally {
        setIsLoading(false);
      }
    };

    initializeAuth();
  }, []);

  /**
   * Login function
   * 
   * Authenticates user with email and password, then sets user state.
   */
  const login = async (email: string, password: string): Promise<void> => {
    try {
      const response = await apiService.login({ email, password });
      setUser(response.user);
      setIsAuthenticated(true);
    } catch (error) {
      // Re-throw error to be handled by the component
      throw error;
    }
  };

  /**
   * Register function
   * 
   * Creates a new user account and automatically logs them in.
   */
  const register = async (
    email: string, 
    username: string, 
    password: string, 
    password2: string
  ): Promise<void> => {
    try {
      const response = await apiService.register({ email, username, password, password2 });
      setUser(response.user);
      setIsAuthenticated(true);
    } catch (error) {
      // Re-throw error to be handled by the component
      throw error;
    }
  };

  /**
   * Logout function
   * 
   * Clears user state and removes authentication token.
   */
  const logout = (): void => {
    apiService.logout();
    setUser(null);
    setIsAuthenticated(false);
  };

  /**
   * Update user function
   * 
   * Allows updating user information (e.g., after profile changes).
   */
  const updateUser = (updatedUser: User): void => {
    setUser(updatedUser);
  };

  // Context value object
  const value: AuthContextType = {
    user,
    isLoading,
    isAuthenticated,
    login,
    register,
    logout,
    updateUser,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

/**
 * Custom hook to use authentication context
 * 
 * This hook provides a convenient way to access authentication state
 * and functions from any component in the application.
 * 
 * Usage:
 * const { user, login, logout, isAuthenticated } = useAuth();
 */
export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  
  return context;
};

export default AuthContext;