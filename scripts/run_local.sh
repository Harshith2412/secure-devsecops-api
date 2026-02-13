#!/bin/bash

# Secure DevSecOps API - Local Development Script

set -e

echo "🚀 Starting Secure DevSecOps API Platform..."

# Check if .env exists
if [ ! -f .env ]; then
    echo "📝 Creating .env from .env.example..."
    cp .env.example .env
    echo "⚠️  Please update .env with your actual values!"
fi

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker and try again."
    exit 1
fi

# Build and start containers
echo "🐳 Building Docker containers..."
docker-compose build

echo "🐳 Starting services..."
docker-compose up -d

# Wait for database to be ready
echo "⏳ Waiting for database to be ready..."
sleep 10

# Check if services are running
if docker-compose ps | grep -q "Up"; then
    echo "✅ Services are running!"
    echo ""
    echo "📍 API is available at: http://localhost:8000"
    echo "📍 API Documentation: http://localhost:8000/docs"
    echo "📍 Health Check: http://localhost:8000/health"
    echo ""
    echo "To view logs: docker-compose logs -f"
    echo "To stop: docker-compose down"
else
    echo "❌ Failed to start services. Check logs with: docker-compose logs"
    exit 1
fi