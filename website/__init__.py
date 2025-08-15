"""
Flask Application Factory

This module creates and configures the Flask application with all necessary extensions.

Key Components:
- SQLAlchemy: ORM for database operations
- Flask-Login: Session management for traditional web interface
- Flask-CORS: Cross-Origin Resource Sharing for React frontend
- JWT: Token-based authentication for API endpoints

Learning Notes:
- Application Factory pattern allows creating multiple app instances for testing
- Blueprints organize routes into logical groups
- CORS is essential for frontend-backend communication in web applications
"""

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from os import path
from flask_login import LoginManager

# Initialize extensions
db = SQLAlchemy()
DB_NAME = "database.db"

def create_app():
    """
    Create and configure Flask application instance
    
    This function:
    1. Creates Flask app with configuration
    2. Initializes database and extensions
    3. Registers blueprints for different route groups
    4. Sets up authentication
    5. Enables CORS for frontend communication
    """
    app = Flask(__name__)

    # Configuration
    app.config["SECRET_KEY"] = "MY_KEY"  # In production, use environment variable
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Reduce overhead
    
    # Initialize extensions
    db.init_app(app)
    
    # Enable CORS for React frontend
    # This allows the React app to make requests to the Flask API
    CORS(app, resources={
        r"/api/*": {
            "origins": ["http://localhost:3000", "http://127.0.0.1:3000"],
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"]
        }
    })

    # Import and register blueprints
    from .views import views          # Traditional web interface routes
    from .auth import auth            # Traditional authentication routes  
    from .api import api              # REST API routes for React frontend

    # Register blueprints with URL prefixes
    app.register_blueprint(views, url_prefix="/")
    app.register_blueprint(auth, url_prefix="/auth")
    app.register_blueprint(api, url_prefix="/api")  # All API routes start with /api
    
    # Import models to ensure they're registered with SQLAlchemy
    from .models import User, Post, Comment, Like

    # Create database if it doesn't exist
    create_database(app)

    # Set up Flask-Login for traditional web interface
    login_manager = LoginManager()
    login_manager.login_view = "auth.signin"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(id):
        """Load user for Flask-Login sessions"""
        return User.query.get(int(id))

    return app


def create_database(app):
    """
    Create database tables if they don't exist
    
    Learning Note: Using app context ensures database operations
    happen within the proper Flask application context
    """
    with app.app_context():
        if not path.exists('website/'+ DB_NAME):
            db.create_all()
            print('Database created!')
        else:
            print("Database exists")

