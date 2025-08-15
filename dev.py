"""
Development Server Management Script

This script helps start both Flask and React development servers concurrently.
It's useful for full-stack development where you need both servers running.

Usage: python dev.py
"""

import subprocess
import sys
import os
import signal
import time
from threading import Thread

def start_flask():
    """Start the Flask development server"""
    print("🔧 Starting Flask backend on http://localhost:5000...")
    try:
        subprocess.run([sys.executable, "app.py"], cwd=os.getcwd())
    except KeyboardInterrupt:
        pass

def start_react():
    """Start the React development server"""
    print("📱 Starting React frontend on http://localhost:3000...")
    try:
        subprocess.run(["npm", "start"], cwd="frontend")
    except KeyboardInterrupt:
        pass

def main():
    """Main function to start both servers"""
    print("🚀 Blog Application Development Server")
    print("=====================================")
    print("Starting both Flask backend and React frontend...")
    print("Press Ctrl+C to stop both servers")
    print()
    
    # Start Flask in a separate thread
    flask_thread = Thread(target=start_flask)
    flask_thread.daemon = True
    flask_thread.start()
    
    # Give Flask a moment to start
    time.sleep(2)
    
    # Start React in main thread (this will block)
    try:
        start_react()
    except KeyboardInterrupt:
        print("\n🛑 Stopping servers...")
        sys.exit(0)

if __name__ == "__main__":
    main()