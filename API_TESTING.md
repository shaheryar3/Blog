# API Testing Guide

This document provides examples of how to test the REST API endpoints using curl commands.

## Authentication Endpoints

### Register a New User
```bash
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "username": "testuser",
    "password": "password123",
    "password2": "password123"
  }'
```

Expected Response:
```json
{
  "message": "User created successfully",
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "user": {
    "id": 1,
    "username": "testuser",
    "email": "user@example.com"
  }
}
```

### Login User
```bash
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123"
  }'
```

## Post Endpoints

### Get All Posts
```bash
curl -X GET http://localhost:5000/api/posts \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### Create a Post
```bash
curl -X POST http://localhost:5000/api/posts \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "text": "This is my first blog post!"
  }'
```

### Delete a Post
```bash
curl -X DELETE http://localhost:5000/api/posts/1 \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## Comment Endpoints

### Get Comments for a Post
```bash
curl -X GET http://localhost:5000/api/posts/1/comments \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### Create a Comment
```bash
curl -X POST http://localhost:5000/api/posts/1/comments \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{
    "text": "Great post!"
  }'
```

## Like Endpoints

### Toggle Like on a Post
```bash
curl -X POST http://localhost:5000/api/posts/1/like \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## User Endpoints

### Get User Profile
```bash
curl -X GET http://localhost:5000/api/user/profile \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### Get Posts by User
```bash
curl -X GET http://localhost:5000/api/users/testuser/posts \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## Error Responses

### 401 Unauthorized
```json
{
  "message": "Token is missing"
}
```

### 400 Bad Request
```json
{
  "message": "Email is required"
}
```

### 404 Not Found
```json
{
  "message": "Post not found"
}
```

## Tips for Testing

1. **Save the JWT Token**: After login/register, save the token for subsequent requests
2. **Use Environment Variables**: Store tokens in environment variables for security
3. **Check Response Status**: Always check HTTP status codes for success/failure
4. **Test Error Cases**: Try invalid data to test error handling
5. **Use Postman**: Consider using Postman for a GUI-based testing experience