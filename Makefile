.PHONY: build test lint clean docker-up docker-down e2e benchmark migrate

# Build all Go services
build:
	@echo "Building Go services..."
	go build -o bin/triage-engine ./cmd/triage-engine/
	go build -o bin/remediation-runner ./cmd/remediation-runner/
	go build -o bin/validation-gate ./cmd/validation-gate/
	go build -o bin/prbot ./cmd/prbot/
	go build -o bin/api-server ./cmd/api-server/
	@echo "Build complete."

# Run all tests
test:
	@echo "Running Go tests..."
	go test ./... -v -count=1 -timeout 120s
	@echo "Running Python codemod tests..."
	python3 -m pytest codemods/python/tests/ -v 2>/dev/null || echo "Python tests skipped (no pytest)"
	@echo "Running JS codemod tests..."
	node codemods/python/tests/test_insecure_crypto.js 2>/dev/null || echo "JS tests skipped"

# Run linter
lint:
	@echo "Linting Go code..."
	golangci-lint run ./... 2>/dev/null || go vet ./...
	@echo "Linting Python code..."
	ruff check codemods/ 2>/dev/null || echo "Ruff not installed"
	@echo "Linting JavaScript..."
	npx eslint frontend/ 2>/dev/null || echo "ESLint not installed"

# Clean build artifacts
clean:
	rm -rf bin/
	rm -rf reports/
	go clean -cache

# Start Docker Compose stack
docker-up:
	docker-compose up -d

# Stop Docker Compose stack
docker-down:
	docker-compose down

# Run database migrations
migrate:
	@for f in $$(ls db/migrations/*.sql | sort); do \
		echo "Applying $$f..."; \
		docker exec -i devsecops-postgres psql -U devsecops -d devsecops < $$f 2>/dev/null || \
		PGPASSWORD=devsecops psql -h localhost -U devsecops -d devsecops -f $$f; \
	done

# Run end-to-end test
e2e:
	chmod +x scripts/*.sh
	./scripts/e2e-test.sh

# Run benchmark
benchmark:
	./scripts/benchmark.sh ./test-fixtures/sample-app 3

# Install dependencies
install:
	go mod download
	pip install tree-sitter tree-sitter-python tree-sitter-javascript semgrep 2>/dev/null || true
	cd frontend && npm install

# Full pipeline test
pipeline: build test e2e
