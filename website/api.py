"""
REST API Blueprint for Blog Application

This module provides RESTful API endpoints for the blog application.
It handles JSON requests and responses for frontend-backend communication.

Key Features:
- JWT-based authentication
- CRUD operations for posts
- Comment and like functionality
- User management
- Comprehensive error handling

Learning Notes:
- REST APIs use HTTP methods (GET, POST, PUT, DELETE) semantically
- JSON is the standard data format for REST APIs
- Status codes convey the result of operations (200, 201, 400, 401, 404, 500)
- Authentication is handled via tokens rather than sessions
"""

from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required, current_user, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash
from .models import User, Post, Comment, Like, db
from datetime import datetime
import jwt
from functools import wraps

# Create API blueprint - this groups related API routes together
api = Blueprint('api', __name__)

def token_required(f):
    """
    Decorator for protecting API endpoints with JWT tokens
    
    This decorator:
    1. Extracts the JWT token from the request header
    2. Verifies the token's validity
    3. Loads the user associated with the token
    4. Passes the user to the protected function
    
    Learning Note: Decorators are a powerful Python feature that allow
    you to modify the behavior of functions without changing their code.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        
        try:
            # Remove 'Bearer ' prefix if present
            if token.startswith('Bearer '):
                token = token[7:]
            
            # Decode the JWT token
            data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user_id = data['user_id']
            user = User.query.get(current_user_id)
            
            if not user:
                return jsonify({'message': 'Invalid token'}), 401
                
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
        
        return f(user, *args, **kwargs)
    
    return decorated_function

# =============================================
# AUTHENTICATION ENDPOINTS
# =============================================

@api.route('/auth/register', methods=['POST'])
def register():
    """
    Register a new user
    
    Expected JSON payload:
    {
        "email": "user@example.com",
        "username": "username",
        "password": "password",
        "password2": "password"
    }
    
    Returns:
    - 201: User created successfully with JWT token
    - 400: Validation errors
    """
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['email', 'username', 'password', 'password2']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'message': f'{field} is required'}), 400
        
        email = data['email']
        username = data['username']
        password1 = data['password']
        password2 = data['password2']
        
        # Validation checks
        if User.query.filter_by(email=email).first():
            return jsonify({'message': 'Email is already in use'}), 400
        
        if User.query.filter_by(username=username).first():
            return jsonify({'message': 'Username is already in use'}), 400
        
        if password1 != password2:
            return jsonify({'message': 'Passwords do not match'}), 400
        
        if len(username) < 2:
            return jsonify({'message': 'Username is too short'}), 400
        
        if len(password1) < 6:
            return jsonify({'message': 'Password is too short'}), 400
        
        if len(email) < 4:
            return jsonify({'message': 'Email is invalid'}), 400
        
        # Create new user
        hashed_password = generate_password_hash(password1)
        new_user = User(email=email, username=username, password=hashed_password)
        
        db.session.add(new_user)
        db.session.commit()
        
        # Generate JWT token
        token = jwt.encode({
            'user_id': new_user.id,
            'exp': datetime.utcnow().timestamp() + 86400  # 24 hours
        }, current_app.config['SECRET_KEY'], algorithm='HS256')
        
        return jsonify({
            'message': 'User created successfully',
            'token': token,
            'user': {
                'id': new_user.id,
                'username': new_user.username,
                'email': new_user.email
            }
        }), 201
        
    except Exception as e:
        return jsonify({'message': 'Server error', 'error': str(e)}), 500

@api.route('/auth/login', methods=['POST'])
def login():
    """
    Authenticate user and return JWT token
    
    Expected JSON payload:
    {
        "email": "user@example.com",
        "password": "password"
    }
    
    Returns:
    - 200: Login successful with JWT token
    - 401: Invalid credentials
    - 400: Missing required fields
    """
    try:
        data = request.get_json()
        
        if not data.get('email') or not data.get('password'):
            return jsonify({'message': 'Email and password are required'}), 400
        
        email = data['email']
        password = data['password']
        
        # Find user by email
        user = User.query.filter_by(email=email).first()
        
        if not user or not check_password_hash(user.password, password):
            return jsonify({'message': 'Invalid email or password'}), 401
        
        # Generate JWT token
        token = jwt.encode({
            'user_id': user.id,
            'exp': datetime.utcnow().timestamp() + 86400  # 24 hours
        }, current_app.config['SECRET_KEY'], algorithm='HS256')
        
        return jsonify({
            'message': 'Login successful',
            'token': token,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email
            }
        }), 200
        
    except Exception as e:
        return jsonify({'message': 'Server error', 'error': str(e)}), 500

# =============================================
# POST ENDPOINTS
# =============================================

@api.route('/posts', methods=['GET'])
@token_required
def get_posts(current_user):
    """
    Get all posts with pagination
    
    Query Parameters:
    - page: Page number (default: 1)
    - per_page: Posts per page (default: 10, max: 100)
    
    Returns:
    - 200: List of posts with pagination info
    """
    try:
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 10, type=int), 100)
        
        # Get paginated posts, ordered by creation date (newest first)
        posts_pagination = Post.query.order_by(Post.date_created.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        posts_data = []
        for post in posts_pagination.items:
            # Check if current user liked this post
            user_liked = Like.query.filter_by(
                author=current_user.id, 
                post_id=post.id
            ).first() is not None
            
            posts_data.append({
                'id': post.id,
                'text': post.text,
                'date_created': post.date_created.isoformat(),
                'author': {
                    'id': post.user.id,
                    'username': post.user.username
                },
                'likes_count': len(post.likes),
                'comments_count': len(post.comments),
                'user_liked': user_liked
            })
        
        return jsonify({
            'posts': posts_data,
            'pagination': {
                'page': posts_pagination.page,
                'pages': posts_pagination.pages,
                'per_page': posts_pagination.per_page,
                'total': posts_pagination.total,
                'has_next': posts_pagination.has_next,
                'has_prev': posts_pagination.has_prev
            }
        }), 200
        
    except Exception as e:
        return jsonify({'message': 'Server error', 'error': str(e)}), 500

@api.route('/posts', methods=['POST'])
@token_required
def create_post(current_user):
    """
    Create a new post
    
    Expected JSON payload:
    {
        "text": "Post content"
    }
    
    Returns:
    - 201: Post created successfully
    - 400: Invalid input
    """
    try:
        data = request.get_json()
        
        if not data.get('text'):
            return jsonify({'message': 'Post text is required'}), 400
        
        text = data['text'].strip()
        if not text:
            return jsonify({'message': 'Post cannot be empty'}), 400
        
        # Create new post
        new_post = Post(text=text, author=current_user.id)
        db.session.add(new_post)
        db.session.commit()
        
        return jsonify({
            'message': 'Post created successfully',
            'post': {
                'id': new_post.id,
                'text': new_post.text,
                'date_created': new_post.date_created.isoformat(),
                'author': {
                    'id': current_user.id,
                    'username': current_user.username
                },
                'likes_count': 0,
                'comments_count': 0,
                'user_liked': False
            }
        }), 201
        
    except Exception as e:
        return jsonify({'message': 'Server error', 'error': str(e)}), 500

@api.route('/posts/<int:post_id>', methods=['DELETE'])
@token_required
def delete_post(current_user, post_id):
    """
    Delete a post (only by the author)
    
    Returns:
    - 200: Post deleted successfully
    - 403: Unauthorized (not the author)
    - 404: Post not found
    """
    try:
        post = Post.query.get(post_id)
        
        if not post:
            return jsonify({'message': 'Post not found'}), 404
        
        if post.author != current_user.id:
            return jsonify({'message': 'Unauthorized to delete this post'}), 403
        
        # Delete the post (comments and likes will be deleted due to CASCADE)
        db.session.delete(post)
        db.session.commit()
        
        return jsonify({'message': 'Post deleted successfully'}), 200
        
    except Exception as e:
        return jsonify({'message': 'Server error', 'error': str(e)}), 500

# =============================================
# COMMENT ENDPOINTS
# =============================================

@api.route('/posts/<int:post_id>/comments', methods=['GET'])
@token_required
def get_comments(current_user, post_id):
    """
    Get comments for a specific post
    
    Returns:
    - 200: List of comments
    - 404: Post not found
    """
    try:
        post = Post.query.get(post_id)
        
        if not post:
            return jsonify({'message': 'Post not found'}), 404
        
        comments_data = []
        for comment in post.comments:
            comments_data.append({
                'id': comment.id,
                'text': comment.text,
                'date_created': comment.date_created.isoformat(),
                'author': {
                    'id': comment.user.id,
                    'username': comment.user.username
                },
                'can_delete': comment.author == current_user.id or post.author == current_user.id
            })
        
        return jsonify({'comments': comments_data}), 200
        
    except Exception as e:
        return jsonify({'message': 'Server error', 'error': str(e)}), 500

@api.route('/posts/<int:post_id>/comments', methods=['POST'])
@token_required
def create_comment(current_user, post_id):
    """
    Create a comment on a post
    
    Expected JSON payload:
    {
        "text": "Comment text"
    }
    
    Returns:
    - 201: Comment created successfully
    - 400: Invalid input
    - 404: Post not found
    """
    try:
        data = request.get_json()
        
        if not data.get('text'):
            return jsonify({'message': 'Comment text is required'}), 400
        
        text = data['text'].strip()
        if not text:
            return jsonify({'message': 'Comment cannot be empty'}), 400
        
        post = Post.query.get(post_id)
        if not post:
            return jsonify({'message': 'Post not found'}), 404
        
        # Create new comment
        new_comment = Comment(text=text, author=current_user.id, post_id=post_id)
        db.session.add(new_comment)
        db.session.commit()
        
        return jsonify({
            'message': 'Comment created successfully',
            'comment': {
                'id': new_comment.id,
                'text': new_comment.text,
                'date_created': new_comment.date_created.isoformat(),
                'author': {
                    'id': current_user.id,
                    'username': current_user.username
                },
                'can_delete': True
            }
        }), 201
        
    except Exception as e:
        return jsonify({'message': 'Server error', 'error': str(e)}), 500

@api.route('/comments/<int:comment_id>', methods=['DELETE'])
@token_required
def delete_comment(current_user, comment_id):
    """
    Delete a comment (by comment author or post author)
    
    Returns:
    - 200: Comment deleted successfully
    - 403: Unauthorized
    - 404: Comment not found
    """
    try:
        comment = Comment.query.get(comment_id)
        
        if not comment:
            return jsonify({'message': 'Comment not found'}), 404
        
        # Check if user can delete (comment author or post author)
        post = Post.query.get(comment.post_id)
        if comment.author != current_user.id and post.author != current_user.id:
            return jsonify({'message': 'Unauthorized to delete this comment'}), 403
        
        db.session.delete(comment)
        db.session.commit()
        
        return jsonify({'message': 'Comment deleted successfully'}), 200
        
    except Exception as e:
        return jsonify({'message': 'Server error', 'error': str(e)}), 500

# =============================================
# LIKE ENDPOINTS
# =============================================

@api.route('/posts/<int:post_id>/like', methods=['POST'])
@token_required
def toggle_like(current_user, post_id):
    """
    Toggle like on a post
    
    Returns:
    - 200: Like toggled successfully
    - 404: Post not found
    """
    try:
        post = Post.query.get(post_id)
        
        if not post:
            return jsonify({'message': 'Post not found'}), 404
        
        # Check if user already liked this post
        existing_like = Like.query.filter_by(
            author=current_user.id, 
            post_id=post_id
        ).first()
        
        if existing_like:
            # Unlike the post
            db.session.delete(existing_like)
            db.session.commit()
            liked = False
        else:
            # Like the post
            new_like = Like(author=current_user.id, post_id=post_id)
            db.session.add(new_like)
            db.session.commit()
            liked = True
        
        # Get updated like count
        likes_count = Like.query.filter_by(post_id=post_id).count()
        
        return jsonify({
            'message': 'Like toggled successfully',
            'liked': liked,
            'likes_count': likes_count
        }), 200
        
    except Exception as e:
        return jsonify({'message': 'Server error', 'error': str(e)}), 500

# =============================================
# USER ENDPOINTS
# =============================================

@api.route('/user/profile', methods=['GET'])
@token_required
def get_user_profile(current_user):
    """
    Get current user's profile
    
    Returns:
    - 200: User profile data
    """
    try:
        return jsonify({
            'user': {
                'id': current_user.id,
                'username': current_user.username,
                'email': current_user.email,
                'date_created': current_user.date_created.isoformat(),
                'posts_count': len(current_user.posts),
                'comments_count': len(current_user.comments),
                'likes_count': len(current_user.likes)
            }
        }), 200
        
    except Exception as e:
        return jsonify({'message': 'Server error', 'error': str(e)}), 500

@api.route('/users/<username>/posts', methods=['GET'])
@token_required
def get_user_posts(current_user, username):
    """
    Get posts by a specific user
    
    Returns:
    - 200: List of user's posts
    - 404: User not found
    """
    try:
        user = User.query.filter_by(username=username).first()
        
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 10, type=int), 100)
        
        posts_pagination = Post.query.filter_by(author=user.id).order_by(
            Post.date_created.desc()
        ).paginate(page=page, per_page=per_page, error_out=False)
        
        posts_data = []
        for post in posts_pagination.items:
            user_liked = Like.query.filter_by(
                author=current_user.id, 
                post_id=post.id
            ).first() is not None
            
            posts_data.append({
                'id': post.id,
                'text': post.text,
                'date_created': post.date_created.isoformat(),
                'author': {
                    'id': user.id,
                    'username': user.username
                },
                'likes_count': len(post.likes),
                'comments_count': len(post.comments),
                'user_liked': user_liked
            })
        
        return jsonify({
            'user': {
                'id': user.id,
                'username': user.username
            },
            'posts': posts_data,
            'pagination': {
                'page': posts_pagination.page,
                'pages': posts_pagination.pages,
                'per_page': posts_pagination.per_page,
                'total': posts_pagination.total,
                'has_next': posts_pagination.has_next,
                'has_prev': posts_pagination.has_prev
            }
        }), 200
        
    except Exception as e:
        return jsonify({'message': 'Server error', 'error': str(e)}), 500