#!/bin/sh

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Function to print step headers
print_step() {
    echo ""
    echo "${BLUE}${BOLD}═══════════════════════════════════════════════════════════════${NC}"
    echo "${BLUE}${BOLD}  $1${NC}"
    echo "${BLUE}${BOLD}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# Function to print success message
print_success() {
    echo "${GREEN}${BOLD}✓ $1${NC}"
}

# Function to print error message and exit
print_error() {
    echo "${RED}${BOLD}✗ $1${NC}"
    exit 1
}

# Function to run command with error handling
run_command() {
    local cmd="$1"
    local description="$2"

    echo "${YELLOW}→ Running: ${cmd}${NC}"

    if $cmd; then
        print_success "$description completed successfully"
    else
        print_error "$description failed"
    fi
}

echo "${BOLD}${BLUE}"
echo "██████╗ ██╗   ██╗██████╗ ██╗     ██╗███████╗██╗  ██╗"
echo "██╔══██╗██║   ██║██╔══██╗██║     ██║██╔════╝██║  ██║"
echo "██████╔╝██║   ██║██████╔╝██║     ██║███████╗███████║"
echo "██╔═══╝ ██║   ██║██╔══██╗██║     ██║╚════██║██╔══██║"
echo "██║     ╚██████╔╝██████╔╝███████╗██║███████║██║  ██║"
echo "╚═╝      ╚═════╝ ╚═════╝ ╚══════╝╚═╝╚══════╝╚═╝  ╚═╝"
echo "${NC}"
echo "${BOLD}Starting Package Publishing Process...${NC}"

print_step "1/10 Cleaning Previous Build"
run_command "pdm run clean" "Clean"

print_step "2/10 Installing Dependencies"
run_command "pdm run install" "Dependencies installation"

print_step "3/10 Installing Development Dependencies"
run_command "pdm run install-dev" "Development dependencies installation"

print_step "4/10 Check Outdated Dependencies"
run_command "pdm outdated" "Outdated dependencies"

print_step "5/10 Update Dependencies"
run_command "pdm update" "dependencies update"

print_step "6/10 Type Checking"
run_command "pdm run typecheck" "Type checking"

print_step "7/10 Running Tests"
run_command "pdm run test-quick" "Tests"

print_step "8/10 Bumping Version"
run_command "pdm run bump-version" "Version bump"

print_step "9/10 Building Package"
run_command "pdm build" "Package build"

print_step "10/10 Publishing Package"
run_command "pdm publish" "Package publishing"

echo ""
echo "${GREEN}${BOLD}🎉 PUBLISHING COMPLETED SUCCESSFULLY! 🎉${NC}"
echo "${GREEN}${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo "${GREEN}Your XP package has been successfully published!${NC}"
echo ""
