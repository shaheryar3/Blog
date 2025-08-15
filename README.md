# 📝 Blog Application - Flask + React

This is a full-stack blog application built with **Flask (Python)** as the backend API and **React (TypeScript)** as the frontend. The application demonstrates modern web development practices with RESTful API design, JWT authentication, and responsive UI components.

## 🚀 Features

### Backend (Flask REST API)
- **JWT Authentication**: Secure token-based authentication system
- **User Management**: Registration, login, and profile management
- **Post Operations**: Create, read, delete blog posts with pagination
- **Comment System**: Add and delete comments on posts
- **Like System**: Like/unlike posts with real-time updates
- **CORS Support**: Configured for frontend-backend communication
- **SQLite Database**: Simple, file-based database for easy setup

### Frontend (React + TypeScript)
- **Modern React**: Functional components with hooks and TypeScript
- **Responsive Design**: Bootstrap-based UI components
- **Authentication Context**: Global state management for user authentication
- **Protected Routes**: Route guards for authenticated-only pages
- **Real-time Updates**: Optimistic UI updates for better user experience
- **Form Validation**: Client-side validation with error handling
- **Pagination**: Efficient data loading with paginated results

## 📁 Project Structure

```
Blog/
├── app.py                          # Flask application entry point
├── requirements.txt                # Python dependencies
├── website/                        # Flask backend package
│   ├── __init__.py                # Flask app factory and configuration
│   ├── models.py                  # Database models (User, Post, Comment, Like)
│   ├── auth.py                    # Traditional web authentication routes
│   ├── views.py                   # Traditional web view routes
│   └── api.py                     # REST API endpoints for React frontend
├── frontend/                       # React frontend application
│   ├── package.json               # Node.js dependencies
│   ├── src/
│   │   ├── App.tsx                # Main React component with routing
│   │   ├── contexts/              # React Context providers
│   │   │   └── AuthContext.tsx    # Authentication state management
│   │   ├── services/              # API service layer
│   │   │   └── api.ts             # Axios-based API client
│   │   ├── components/            # Reusable React components
│   │   │   ├── Navbar.tsx         # Navigation bar
│   │   │   ├── PostCard.tsx       # Individual post display
│   │   │   ├── CreatePostForm.tsx # Post creation form
│   │   │   └── Pagination.tsx     # Pagination controls
│   │   └── pages/                 # Page-level components
│   │       ├── Login.tsx          # User login page
│   │       ├── Register.tsx       # User registration page
│   │       ├── Home.tsx           # Main blog feed
│   │       ├── Profile.tsx        # User profile page
│   │       └── UserPosts.tsx      # Individual user's posts
│   └── public/                    # Static assets
└── README.md                      # This file
```

## 🛠️ Technologies Used

### Backend Technologies
- **Flask 3.0.2**: Lightweight Python web framework
- **Flask-SQLAlchemy**: ORM for database operations
- **Flask-Login**: Session management for traditional web interface
- **Flask-CORS**: Cross-Origin Resource Sharing for API access
- **PyJWT**: JSON Web Token implementation for API authentication
- **SQLite**: Lightweight, file-based database
- **Werkzeug**: Password hashing and security utilities

### Frontend Technologies
- **React 18**: Modern JavaScript library for building user interfaces
- **TypeScript**: Static type checking for better code quality
- **React Router**: Client-side routing for single-page application
- **Axios**: HTTP client for API requests
- **Bootstrap 5**: CSS framework for responsive design
- **React Bootstrap**: Bootstrap components for React

## 📚 Learning Notes

This project is designed to be educational and includes extensive comments explaining key concepts:

### REST API Design
- **HTTP Methods**: Proper use of GET, POST, DELETE for different operations
- **Status Codes**: Meaningful HTTP status codes (200, 201, 400, 401, 404, 500)
- **JSON Communication**: Structured data exchange between frontend and backend
- **Error Handling**: Comprehensive error responses with helpful messages

### Authentication & Security
- **JWT Tokens**: Stateless authentication suitable for APIs
- **Token Interceptors**: Automatic token attachment and refresh handling
- **Route Protection**: Server-side and client-side route guards
- **Password Hashing**: Secure password storage using Werkzeug

### React Patterns
- **Context API**: Global state management without prop drilling
- **Custom Hooks**: Reusable logic encapsulation
- **Component Composition**: Breaking down complex UI into manageable pieces
- **TypeScript Integration**: Type safety for better development experience

### Database Design
- **Relational Models**: Foreign key relationships between users, posts, comments, and likes
- **Cascade Deletes**: Automatic cleanup of related records
- **Pagination**: Efficient data loading for large datasets

## 🚀 Getting Started

### Prerequisites
- **Python 3.8+**: For running the Flask backend
- **Node.js 16+**: For running the React frontend
- **npm or yarn**: For managing frontend dependencies

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd Blog
   ```

2. **Set up the Flask backend**
   ```bash
   # Install Python dependencies
   pip install -r requirements.txt
   
   # Start the Flask development server
   python app.py
   ```
   The backend will run on `http://localhost:5000`

3. **Set up the React frontend**
   ```bash
   # Navigate to frontend directory
   cd frontend
   
   # Install Node.js dependencies
   npm install
   
   # Start the React development server
   npm start
   ```
   The frontend will run on `http://localhost:3000`

### First Time Setup

1. **Create your first user**: Navigate to `http://localhost:3000/register`
2. **Register a new account**: Fill out the registration form
3. **Start blogging**: You'll be automatically logged in and redirected to the home page

## 🔧 API Endpoints

### Authentication
- `POST /api/auth/register` - Create a new user account
- `POST /api/auth/login` - Authenticate user and get JWT token

### Posts
- `GET /api/posts` - Get all posts (paginated)
- `POST /api/posts` - Create a new post
- `DELETE /api/posts/{id}` - Delete a post (author only)
- `GET /api/users/{username}/posts` - Get posts by specific user

### Comments
- `GET /api/posts/{id}/comments` - Get comments for a post
- `POST /api/posts/{id}/comments` - Add comment to a post
- `DELETE /api/comments/{id}` - Delete a comment

### Likes
- `POST /api/posts/{id}/like` - Toggle like on a post

### User
- `GET /api/user/profile` - Get current user profile

## 🎨 UI Components

### Pages
- **Login Page**: Email and password authentication
- **Register Page**: New user registration with validation
- **Home Page**: Main blog feed with all posts
- **Profile Page**: User account information and statistics
- **User Posts Page**: Individual user's post history

### Components
- **Navbar**: Responsive navigation with authentication state
- **PostCard**: Individual post display with like/comment functionality
- **CreatePostForm**: Rich post creation interface with character counting
- **Pagination**: Smart pagination with ellipsis for large page counts

## 🔐 Authentication Flow

1. **Registration/Login**: User provides credentials to React frontend
2. **API Call**: Frontend sends credentials to Flask API
3. **JWT Generation**: Flask creates and returns JWT token
4. **Token Storage**: React stores token in localStorage
5. **Authenticated Requests**: Token automatically attached to API requests
6. **Token Validation**: Flask validates token on protected endpoints

## 🚧 Development Workflow

### Adding New Features

1. **Backend (Flask)**:
   - Add new models to `models.py`
   - Create API endpoints in `api.py`
   - Test with curl or Postman

2. **Frontend (React)**:
   - Add API methods to `services/api.ts`
   - Create/update components
   - Add routing if needed

### Testing
- **Backend**: Test API endpoints with curl commands
- **Frontend**: Use React DevTools and browser inspection
- **Integration**: Test full user workflows in the browser

## 📝 Code Comments & Learning

The codebase includes extensive comments explaining:
- **Architecture decisions** and why certain patterns were chosen
- **Technical concepts** like JWT authentication, React Context, etc.
- **Best practices** for security, performance, and maintainability
- **Common patterns** used in modern web development

## 🤝 Contributing

This project is designed for learning purposes. Feel free to:
- Add new features (user profiles, image uploads, etc.)
- Improve the UI/UX design
- Add unit tests
- Implement additional security measures
- Optimize performance

## 📄 License

This project is created for educational purposes. Feel free to use it as a learning resource or starting point for your own blog application.

## 🆘 Troubleshooting

### Common Issues

1. **CORS Errors**: Make sure Flask-CORS is properly configured
2. **Token Issues**: Check browser localStorage for valid JWT tokens
3. **Database Issues**: Delete the SQLite database file to reset
4. **Port Conflicts**: Make sure ports 3000 and 5000 are available

### Getting Help

The code includes extensive comments and documentation. If you're stuck:
1. Check the browser console for error messages
2. Review the Flask server logs
3. Examine the network tab in browser DevTools
4. Read through the commented code sections

---

**Happy Coding! 🎉**

This project demonstrates the power of combining Flask's simplicity with React's modern frontend capabilities. It's a great starting point for understanding full-stack web development with API-driven architecture.
