#!/bin/bash

# Blog Application Setup Script
# This script helps you set up and run both the Flask backend and React frontend

echo "🚀 Blog Application Setup & Start Script"
echo "========================================"

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check prerequisites
echo "📋 Checking prerequisites..."

if ! command_exists python; then
    echo "❌ Python is not installed. Please install Python 3.8+ first."
    exit 1
fi

if ! command_exists node; then
    echo "❌ Node.js is not installed. Please install Node.js 16+ first."
    exit 1
fi

if ! command_exists npm; then
    echo "❌ npm is not installed. Please install npm first."
    exit 1
fi

echo "✅ All prerequisites are installed!"

# Install Python dependencies
echo ""
echo "📦 Installing Python dependencies..."
pip install -r requirements.txt

if [ $? -ne 0 ]; then
    echo "❌ Failed to install Python dependencies"
    exit 1
fi

echo "✅ Python dependencies installed!"

# Install Node.js dependencies
echo ""
echo "📦 Installing Node.js dependencies..."
cd frontend
npm install

if [ $? -ne 0 ]; then
    echo "❌ Failed to install Node.js dependencies"
    exit 1
fi

echo "✅ Node.js dependencies installed!"
cd ..

# Create a function to start servers
start_servers() {
    echo ""
    echo "🚀 Starting servers..."
    echo ""
    
    # Start Flask backend in background
    echo "Starting Flask backend on http://localhost:5000..."
    python app.py &
    FLASK_PID=$!
    
    # Wait a moment for Flask to start
    sleep 3
    
    # Start React frontend
    echo "Starting React frontend on http://localhost:3000..."
    cd frontend
    npm start &
    REACT_PID=$!
    cd ..
    
    echo ""
    echo "🎉 Both servers are starting!"
    echo "📱 Frontend: http://localhost:3000"
    echo "🔧 Backend:  http://localhost:5000"
    echo ""
    echo "💡 To stop the servers, press Ctrl+C"
    echo ""
    
    # Function to cleanup on exit
    cleanup() {
        echo ""
        echo "🛑 Stopping servers..."
        kill $FLASK_PID 2>/dev/null
        kill $REACT_PID 2>/dev/null
        echo "✅ Servers stopped!"
        exit 0
    }
    
    # Set trap to cleanup on script exit
    trap cleanup INT
    
    # Wait for both processes
    wait
}

# Check if user wants to start servers
echo ""
read -p "🚀 Do you want to start both servers now? (y/n): " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    start_servers
else
    echo ""
    echo "📚 Setup complete! To start the servers manually:"
    echo "   1. Start Flask backend: python app.py"
    echo "   2. Start React frontend: cd frontend && npm start"
    echo ""
    echo "🌐 Then visit http://localhost:3000 to use the application"
fi