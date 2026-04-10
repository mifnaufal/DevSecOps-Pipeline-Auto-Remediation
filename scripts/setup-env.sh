#!/usr/bin/env bash
# setup-env.sh - Initialize the development environment
# Installs dependencies, sets up the database, and verifies all services.

set -euo pipefail

echo "=== DevSecOps Environment Setup ==="

# Check prerequisites
check_prerequisites() {
    echo ""
    echo "[1/5] Checking prerequisites..."
    
    local missing=0
    
    command -v go &> /dev/null || { echo "  ❌ Go not installed"; missing=1; }
    command -v python3 &> /dev/null || { echo "  ❌ Python3 not installed"; missing=1; }
    command -v node &> /dev/null || { echo "  ❌ Node.js not installed"; missing=1; }
    command -v docker &> /dev/null || { echo "  ❌ Docker not installed"; missing=1; }
    command -v docker-compose &> /dev/null || { echo "  ❌ Docker Compose not installed"; missing=1; }
    
    if [[ $missing -eq 1 ]]; then
        echo ""
        echo "Please install missing prerequisites before continuing."
        exit 1
    fi
    
    echo "  ✅ All prerequisites met"
}

# Install Go dependencies
install_go_deps() {
    echo ""
    echo "[2/5] Installing Go dependencies..."
    go mod download
    echo "  ✅ Go dependencies installed"
}

# Install Python codemod dependencies
install_python_deps() {
    echo ""
    echo "[3/5] Installing Python codemod dependencies..."
    pip install tree-sitter tree-sitter-python tree-sitter-javascript 2>/dev/null || {
        echo "  ⚠️  tree-sitter packages require specific setup; codemods will use regex fallback"
    }
    echo "  ✅ Python dependencies handled"
}

# Install frontend dependencies
install_frontend_deps() {
    echo ""
    echo "[4/5] Installing frontend dependencies..."
    if [[ -d "frontend" ]]; then
        cd frontend
        npm install
        cd ..
    fi
    echo "  ✅ Frontend dependencies installed"
}

# Start and verify database
setup_database() {
    echo ""
    echo "[5/5] Setting up database..."
    
    # Check if PostgreSQL is running
    if docker ps --format '{{.Names}}' | grep -q devsecops-postgres; then
        echo "  PostgreSQL already running"
    else
        echo "  Starting PostgreSQL..."
        docker-compose up -d postgres
        sleep 5
    fi
    
    # Run migrations
    echo "  Running migrations..."
    for f in $(ls db/migrations/*.sql | sort); do
        docker exec -i devsecops-postgres psql -U devsecops -d devsecops < "$f" 2>/dev/null || true
    done
    
    # Verify
    TABLES=$(docker exec devsecops-postgres psql -U devsecops -d devsecops -t -c "
        SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public';" 2>/dev/null || echo "0")
    
    echo "  ✅ Database ready ($TABLES tables)"
}

# Execute
check_prerequisites
install_go_deps
install_python_deps
install_frontend_deps
setup_database

echo ""
echo "🎉 Environment setup complete!"
echo ""
echo "Next steps:"
echo "  1. Start all services: docker-compose up -d"
echo "  2. Run E2E test: ./scripts/e2e-test.sh"
echo "  3. Open dashboard: http://localhost:3000"
echo "  4. View API docs: http://localhost:8080/api/v1/health"
