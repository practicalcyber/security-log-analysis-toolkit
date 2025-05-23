#!/bin/bash

# Security Log Analysis Toolkit - Startup Script
# This script helps you quickly set up and run the security toolkit

set -e

echo "🛡️  Security Log Analysis Toolkit Setup"
echo "========================================"

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    echo "   Visit: https://docs.docker.com/get-docker/"
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    echo "   Visit: https://docs.docker.com/compose/install/"
    exit 1
fi

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p logs frontend docs tests

# Copy frontend files if they don't exist
if [ ! -f "frontend/index.html" ]; then
    echo "📄 Setting up frontend files..."
    mkdir -p frontend
    # The index.html content would be copied here in a real setup
fi

# Setup environment file
if [ ! -f ".env" ]; then
    echo "⚙️  Setting up environment configuration..."
    cp .env.example .env
    echo "✅ Created .env file. Please edit it with your API keys if needed."
else
    echo "✅ Environment file already exists."
fi

# Create sample log files
echo "📝 Creating sample log files..."
cat > logs/sample-windows.log << EOF
2024-01-15 08:15:30 Event ID: 4624 An account was successfully logged on Account Name: john.doe Source Network Address: 192.168.1.45 Logon Type: 2
2024-01-15 08:16:42 Event ID: 4625 An account failed to log on Account Name: admin Source Network Address: 203.0.113.1 Logon Type: 3
2024-01-15 08:16:45 Event ID: 4625 An account failed to log on Account Name: administrator Source Network Address: 203.0.113.1 Logon Type: 3
2024-01-15 23:45:15 Event ID: 4624 An account was successfully logged on Account Name: admin Source Network Address: 198.51.100.25 Logon Type: 10
EOF

cat > logs/sample-linux.log << EOF
Jan 15 08:15:30 webserver sshd[12345]: Accepted password for john from 192.168.1.45 port 22 ssh2
Jan 15 08:16:42 webserver sshd[12346]: Failed password for admin from 203.0.113.1 port 22 ssh2
Jan 15 08:16:45 webserver sshd[12347]: Failed password for administrator from 203.0.113.1 port 22 ssh2
Jan 15 23:45:15 webserver sshd[12352]: Accepted password for admin from 198.51.100.25 port 22 ssh2
EOF

# Build and start services
echo "🐳 Building and starting Docker containers..."
echo "   This may take a few minutes on first run..."

# Pull base images first
docker-compose pull

# Build and start services
docker-compose up -d --build

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 10

# Health check
echo "🔍 Checking service health..."
for i in {1..30}; do
    if curl -s http://localhost:8000/ > /dev/null; then
        echo "✅ API service is running!"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "❌ API service failed to start. Check logs with: docker-compose logs api"
        exit 1
    fi
    sleep 2
done

# Check database
echo "🗄️  Checking database connection..."
if docker-compose exec -T db pg_isready -U secuser > /dev/null; then
    echo "✅ Database is ready!"
else
    echo "❌ Database is not ready. Check logs with: docker-compose logs db"
fi

# Show status
echo ""
echo "🎉 Security Log Analysis Toolkit is ready!"
echo ""
echo "📊 Access points:"
echo "   Frontend:    http://localhost"
echo "   API Docs:    http://localhost:8000/docs"
echo "   Database:    localhost:5432 (secuser/secpass123)"
echo ""
echo "🔧 Useful commands:"
echo "   View logs:     docker-compose logs -f"
echo "   Stop services: docker-compose down"
echo "   Restart:       docker-compose restart"
echo "   Clean up:      docker-compose down -v"
echo ""
echo "📁 Sample log files created in ./logs/ directory"
echo "   Upload these files through the web interface to test the system"
echo ""
echo "⚠️  Default auth token for demo: 'demo-token-123'"
echo "   Change this in production!"
echo ""

# Show service status
echo "📋 Service Status:"
docker-compose ps

# Open browser if available
if command -v open &> /dev/null; then
    echo "🌐 Opening browser..."
    open http://localhost
elif command -v xdg-open &> /dev/null; then
    echo "🌐 Opening browser..."
    xdg-open http://localhost
else
    echo "🌐 Please open http://localhost in your browser"
fi

echo ""
echo "✨ Setup complete! Happy analyzing! 🛡️"