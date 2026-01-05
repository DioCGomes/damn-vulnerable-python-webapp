.PHONY: help install venv run dev clean reset db shell freeze

# Default Python interpreter
PYTHON := python3
VENV := venv
BIN := $(VENV)/bin

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[0;33m
BLUE := \033[0;34m
NC := \033[0m # No Color

help: ## Show this help message
	@echo ""
	@echo "$(RED)╔═══════════════════════════════════════════════════════════════╗$(NC)"
	@echo "$(RED)║$(NC)         $(YELLOW)DVPWA - Damn Vulnerable Python Web App$(NC)            $(RED)║$(NC)"
	@echo "$(RED)╚═══════════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@echo "$(GREEN)Available commands:$(NC)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(BLUE)%-15s$(NC) %s\n", $$1, $$2}'
	@echo ""

venv: ## Create virtual environment
	@echo "$(GREEN)Creating virtual environment...$(NC)"
	$(PYTHON) -m venv $(VENV)
	@echo "$(GREEN)Virtual environment created!$(NC)"
	@echo "$(YELLOW)Activate with: source $(VENV)/bin/activate$(NC)"

install: venv ## Create venv and install dependencies
	@echo "$(GREEN)Installing dependencies...$(NC)"
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -r requirements.txt
	@echo "$(GREEN)Dependencies installed!$(NC)"

run: ## Run the application (creates venv if needed)
	@if [ ! -d "$(VENV)" ]; then \
		echo "$(YELLOW)Virtual environment not found. Creating...$(NC)"; \
		$(MAKE) install; \
	fi
	@echo ""
	@echo "$(RED)⚠️  WARNING: This is an intentionally vulnerable application!$(NC)"
	@echo "$(RED)⚠️  DO NOT expose to the internet or use in production!$(NC)"
	@echo ""
	@echo "$(GREEN)Starting DVPWA on http://localhost:5000$(NC)"
	@echo ""
	$(BIN)/python app.py

dev: ## Run in development mode with auto-reload
	@if [ ! -d "$(VENV)" ]; then \
		$(MAKE) install; \
	fi
	FLASK_ENV=development FLASK_DEBUG=1 $(BIN)/flask --app app run --reload --host 0.0.0.0 --port 5000

db: ## Initialize/reset the database
	@echo "$(GREEN)Initializing database...$(NC)"
	@if [ ! -d "$(VENV)" ]; then \
		$(MAKE) install; \
	fi
	$(BIN)/python -c "from app import init_db, app; app.app_context().push(); init_db(); print('Database initialized!')"

reset: ## Reset database and uploads
	@echo "$(YELLOW)Resetting application state...$(NC)"
	rm -f vulnerable.db
	rm -rf uploads/*
	@if [ ! -d "$(VENV)" ]; then \
		$(MAKE) install; \
	fi
	$(BIN)/python -c "from app import init_db, app; app.app_context().push(); init_db(); print('Database reset!')"
	@mkdir -p uploads
	@echo "This is a sample file in the uploads directory." > uploads/readme.txt
	@echo "Try to read files outside this directory using path traversal!" >> uploads/readme.txt
	@echo "$(GREEN)Application reset complete!$(NC)"

clean: ## Remove virtual environment and generated files
	@echo "$(YELLOW)Cleaning up...$(NC)"
	rm -rf $(VENV)
	rm -rf __pycache__
	rm -rf .pytest_cache
	rm -f vulnerable.db
	rm -rf uploads
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	@echo "$(GREEN)Cleanup complete!$(NC)"

shell: ## Open Python shell with app context
	@if [ ! -d "$(VENV)" ]; then \
		$(MAKE) install; \
	fi
	$(BIN)/python -c "from app import *; import code; code.interact(local=locals())"

freeze: ## Update requirements.txt with current packages
	$(BIN)/pip freeze > requirements.txt
	@echo "$(GREEN)requirements.txt updated!$(NC)"

test-sqli: ## Test SQL injection vulnerability
	@echo "$(YELLOW)Testing SQL Injection on /login...$(NC)"
	@curl -s -X POST http://localhost:5000/login \
		-d "username=admin' OR '1'='1' --&password=anything" \
		-c /tmp/dvpwa_cookies.txt \
		-L | grep -q "Welcome back" && \
		echo "$(RED)✓ SQL Injection successful!$(NC)" || \
		echo "$(GREEN)✗ SQL Injection failed (app may not be running)$(NC)"

test-xss: ## Test XSS vulnerability
	@echo "$(YELLOW)Testing Reflected XSS on /search...$(NC)"
	@curl -s "http://localhost:5000/search?q=<script>alert(1)</script>" | \
		grep -q "<script>alert(1)</script>" && \
		echo "$(RED)✓ XSS payload reflected!$(NC)" || \
		echo "$(GREEN)✗ XSS test failed (app may not be running)$(NC)"

test-lfi: ## Test Local File Inclusion vulnerability
	@echo "$(YELLOW)Testing Path Traversal on /file...$(NC)"
	@curl -s -b /tmp/dvpwa_cookies.txt "http://localhost:5000/file?name=../app.py" | \
		grep -q "Flask" && \
		echo "$(RED)✓ Path Traversal successful!$(NC)" || \
		echo "$(GREEN)✗ LFI test failed (login first or app not running)$(NC)"

test-api: ## Test sensitive data exposure
	@echo "$(YELLOW)Testing /api/user endpoint...$(NC)"
	@curl -s http://localhost:5000/api/user | \
		grep -q "password" && \
		echo "$(RED)✓ Sensitive data exposed!$(NC)" || \
		echo "$(GREEN)✗ API test failed (app may not be running)$(NC)"

test: test-sqli test-xss test-api ## Run all vulnerability tests
	@echo ""
	@echo "$(YELLOW)Note: Some tests require logging in first.$(NC)"
	@echo "$(YELLOW)Run 'make run' in another terminal before testing.$(NC)"

