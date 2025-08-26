# AuthGuard - Composable Authentication Service
# A lightweight, high-performance authentication service for nginx auth_request

.PHONY: help build run test clean docker dev-up dev-down lint format deps dev check

# Default target
help: ## Show this help message
	@echo "AuthGuard - Composable Authentication Service"
	@echo ""
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

# Build commands
build: ## Build the authguard binary
	@echo "Building AuthGuard..."
	@go build -o authguard ./cmd/authguard

# Run commands
run: ## Run AuthGuard locally (requires .env)
	@echo "Starting AuthGuard..."
	@echo "Make sure to source .env first: source .env"
	@go run ./cmd/authguard

run-env: ## Source .env and run AuthGuard
	@echo "Starting AuthGuard with environment..."
	@bash -c "source .env && go run ./cmd/authguard"

# Test commands
test: ## Run all tests
	@echo "Running tests..."
	@go test -v ./...

test-coverage: ## Run tests with coverage report
	@echo "Running tests with coverage..."
	@go test -v -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Code quality
lint: ## Run linter (golangci-lint)
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not found. Install with: make install-tools"; \
	fi

format: ## Format code
	@echo "Formatting code..."
	@gofmt -s -w .
	@if command -v goimports >/dev/null 2>&1; then \
		goimports -w .; \
	fi

check: deps lint test ## Run all checks (deps, lint, test)

# Dependencies
deps: ## Download and tidy dependencies
	@echo "Downloading dependencies..."
	@go mod download
	@go mod tidy

# Development environment with nginx
dev-up: ## Start development environment (nginx + authguard + redis)
	@echo "🚀 Starting AuthGuard development environment..."
	@docker-compose -f dev/docker-compose.yml up -d
	@echo ""
	@echo "✅ Development environment started!"
	@echo ""
	@echo "📋 Services Available:"
	@echo "  🌐 nginx (proxy):     http://localhost"
	@echo "  🛡️  AuthGuard:         http://localhost:8080"  
	@echo "  🔧 Backend (mock):    http://localhost:3000"
	@echo "  🗄️  Redis:             localhost:6379"
	@echo ""
	@echo "🧪 Testing Commands:"
	@echo ""
	@echo "📊 Health Check:"
	@echo "  curl http://localhost:8080/health"
	@echo ""
	@echo "🔐 Authentication Tests:"
	@echo "  # IP Whitelist (should work from localhost)"
	@echo "  curl -v http://localhost/auth/ip-only"
	@echo ""
	@echo "  # Firebase + IP (requires valid Firebase token)"
	@echo "  curl -v http://localhost/auth/firebase-ip \\"
	@echo "    -H 'Authorization: Bearer YOUR_FIREBASE_TOKEN'"
	@echo ""
	@echo "  # Firebase only (requires valid Firebase token)"
	@echo "  curl -v http://localhost/auth/firebase \\"
	@echo "    -H 'Authorization: Bearer YOUR_FIREBASE_TOKEN'"
	@echo ""
	@echo "🔒 Protected Routes (through nginx auth_request):"
	@echo "  # IP whitelist protected"
	@echo "  curl -v http://localhost/protected/internal"
	@echo ""
	@echo "  # Firebase protected"
	@echo "  curl -v http://localhost/protected/api \\"
	@echo "    -H 'Authorization: Bearer YOUR_FIREBASE_TOKEN'"
	@echo ""
	@echo "  # Admin (Firebase + IP required)"
	@echo "  curl -v http://localhost/protected/admin \\"
	@echo "    -H 'Authorization: Bearer YOUR_FIREBASE_TOKEN'"
	@echo ""
	@echo "📈 Monitoring:"
	@echo "  # Prometheus metrics"
	@echo "  curl http://localhost:8080/metrics"
	@echo ""
	@echo "  # Redis cache inspection"
	@echo "  docker exec -it authguard-redis redis-cli"
	@echo "  > keys firebase:*"
	@echo "  > keys ip_whitelist:*"
	@echo ""
	@echo "🔍 Logs:"
	@echo "  # AuthGuard logs"
	@echo "  docker logs -f authguard-app"
	@echo ""
	@echo "  # nginx logs"
	@echo "  docker logs -f authguard-nginx"
	@echo ""
	@echo "💡 Tips:"
	@echo "  - Configure Firebase token in dev/.env"
	@echo "  - Check nginx.conf for auth endpoint mappings"
	@echo "  - Use 'make dev-down' to stop all services"

dev-down: ## Stop development environment
	@echo "Stopping development environment..."
	@docker-compose -f dev/docker-compose.yml down

dev-logs: ## View development environment logs
	@docker-compose -f dev/docker-compose.yml logs -f

dev-clean: ## Clean development environment
	@echo "Cleaning development environment..."
	@docker-compose -f dev/docker-compose.yml down --rmi all --volumes --remove-orphans

# Docker commands
docker: ## Build Docker image
	@echo "Building Docker image..."
	@docker build -t authguard:latest .

# Development mode
dev: ## Run in development mode with hot reload (requires air)
	@echo "Starting development server with hot reload..."
	@if command -v air >/dev/null 2>&1; then \
		air; \
	else \
		echo "Air not found. Install with: make install-tools"; \
		echo "Falling back to regular run..."; \
		$(MAKE) run-env; \
	fi

# Testing endpoints
test-health: ## Test health endpoint
	@echo "Testing health endpoint..."
	@curl -s http://localhost:8080/health | jq . 2>/dev/null || curl -s http://localhost:8080/health

test-nginx-health: ## Test health endpoint through nginx
	@echo "Testing health endpoint through nginx..."
	@curl -s http://localhost/health | jq . 2>/dev/null || curl -s http://localhost/health

test-firebase: ## Test Firebase authentication (TOKEN=your_token)
	@echo "Testing Firebase authentication..."
	@if [ -z "$(TOKEN)" ]; then \
		echo "Usage: make test-firebase TOKEN=your_firebase_token"; \
		exit 1; \
	fi
	@curl -X POST http://localhost:8080/validate \
		-H "Authorization: Bearer $(TOKEN)" \
		-H "X-Auth-Providers: firebase" \
		-v

test-nginx-firebase: ## Test Firebase through nginx (TOKEN=your_token)
	@echo "Testing Firebase authentication through nginx..."
	@if [ -z "$(TOKEN)" ]; then \
		echo "Usage: make test-nginx-firebase TOKEN=your_firebase_token"; \
		exit 1; \
	fi
	@curl -X GET http://localhost/protected \
		-H "Authorization: Bearer $(TOKEN)" \
		-v

test-ip: ## Test IP whitelist authentication
	@echo "Testing IP whitelist authentication..."
	@curl -X POST http://localhost:8080/validate \
		-H "X-Auth-Providers: ip_whitelist" \
		-v

test-nginx-admin: ## Test admin endpoint (multi-provider through nginx, TOKEN=your_token)
	@echo "Testing admin endpoint (Firebase + IP whitelist through nginx)..."
	@if [ -z "$(TOKEN)" ]; then \
		echo "Usage: make test-nginx-admin TOKEN=your_firebase_token"; \
		exit 1; \
	fi
	@curl -X GET http://localhost/admin \
		-H "Authorization: Bearer $(TOKEN)" \
		-v

# Environment setup
setup-env: ## Create .env file from template
	@if [ ! -f .env ]; then \
		echo "Creating .env file..."; \
		cp dev/.env.example .env; \
		echo ".env file created. Please edit it with your Firebase credentials."; \
	else \
		echo ".env file already exists"; \
	fi

# Install development tools
install-tools: ## Install development tools
	@echo "Installing development tools..."
	@go install github.com/cosmtrek/air@latest
	@go install golang.org/x/tools/cmd/goimports@latest
	@if ! command -v golangci-lint >/dev/null 2>&1; then \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $$(go env GOPATH)/bin; \
	fi

# Clean up
clean: ## Clean build artifacts
	@echo "Cleaning build artifacts..."
	@rm -f authguard
	@rm -f coverage.out coverage.html
	@go clean -cache

clean-all: clean dev-clean ## Clean everything (build artifacts, Docker, etc.)

# Quick start for development
quick-start: setup-env deps install-tools ## Quick setup for development
	@echo ""
	@echo "🚀 AuthGuard Quick Start Complete!"
	@echo ""
	@echo "Next steps:"
	@echo "  1. Edit .env file with your Firebase credentials"
	@echo "  2. Start development environment: make dev-up"
	@echo "  3. Test health: make test-nginx-health"
	@echo "  4. Test IP whitelist: make test-ip"
	@echo "  5. Test with Firebase: make test-nginx-firebase TOKEN=your_token"
	@echo ""
	@echo "Development URLs:"
	@echo "  - nginx (with auth): http://localhost"
	@echo "  - AuthGuard direct: http://localhost:8080"
	@echo "  - Health check: http://localhost/health"
	@echo "  - Metrics: http://localhost:9090/metrics"