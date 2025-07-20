#!/bin/bash

# Cloud Risk Prioritization Engine - Startup Script
# This script sets up the environment and starts the application

set -e  # Exit on any error

echo "🚀 Starting Cloud Risk Prioritization Engine..."

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed."
    exit 1
fi

# Check if we're in the correct directory
if [ ! -f "app.py" ]; then
    echo "❌ Please run this script from the project root directory"
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "📦 Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "📋 Installing dependencies..."
pip install -q --upgrade pip
pip install -q -r requirements.txt

# Set default environment variables if not already set
export FLASK_ENV="${FLASK_ENV:-development}"
export FLASK_DEBUG="${FLASK_DEBUG:-True}"
export DATABASE_URL="${DATABASE_URL:-sqlite:///cloud_risk_prioritization.db}"

echo "🗄️  Database URL: $DATABASE_URL"

# Initialize database and load data
echo "🏗️  Initializing database..."
python -c "
from src.database import init_db
try:
    init_db()
    print('✅ Database initialized successfully')
except Exception as e:
    print(f'❌ Database initialization failed: {e}')
    exit(1)
"

# Load mock data
echo "📊 Loading mock data..."
python -c "
from src.data_loader import DataLoader
from src.risk_engine import RiskPrioritizationService
from flask import Flask
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///cloud_risk_prioritization.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

from src.database import db
db.init_app(app)

with app.app_context():
    try:
        loader = DataLoader()
        results = loader.load_all_data()
        print(f'✅ Loaded {results[\"vulnerabilities\"]} vulnerabilities and {results[\"assets\"]} assets')
        
        # Calculate risk scores
        service = RiskPrioritizationService()
        risk_results = service.calculate_all_risk_scores()
        print(f'✅ Calculated {risk_results[\"successful_calculations\"]} risk scores')
        
    except Exception as e:
        print(f'❌ Data loading failed: {e}')
        exit(1)
"

# Start the application
echo ""
echo "🎯 Starting the application..."
echo "📍 Access the dashboard at: http://localhost:5000"
echo "📊 API endpoints available at: http://localhost:5000/api/"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

# Run the Flask application
python app.py