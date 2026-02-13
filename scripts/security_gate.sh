#!/bin/bash

# Security Gate Script - DevSecOps Pipeline
# Runs all security checks and fails if any critical issues are found

set -e

echo "🔒 Running Security Gate Checks..."
echo "=================================="

FAILED=0

# Function to run a check and track failures
run_check() {
    local name=$1
    local command=$2
    
    echo ""
    echo "▶️  Running: $name"
    if eval "$command"; then
        echo "✅ $name passed"
    else
        echo "❌ $name failed"
        FAILED=1
    fi
}

# 1.