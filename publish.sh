#!/bin/sh

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Parse command line arguments
QUALITY_ONLY=false
BUMP_TYPE="patch"
CI_MODE=false
for arg in "$@"; do
    case $arg in
        --quality)
            QUALITY_ONLY=true
            shift
            ;;
        --ci)
            CI_MODE=true
            shift
            ;;
        --major)
            BUMP_TYPE="major"
            shift
            ;;
        --minor)
            BUMP_TYPE="minor"
            shift
            ;;
        --patch)
            BUMP_TYPE="patch"
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--quality] [--ci] [--major|--minor|--patch] [--help]"
            echo ""
            echo "Options:"
            echo "  --quality       Run only quality checks without publishing"
            echo "  --ci            Use CI-compatible test suite (excludes reverseproxy tests)"
            echo "  --major         Bump major version (x.0.0)"
            echo "  --minor         Bump minor version (0.x.0)"
            echo "  --patch         Bump patch version (0.0.x) [default]"
            echo "  --help          Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown argument: $arg"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Set total steps based on mode
if [ "$QUALITY_ONLY" = true ]; then
    STEPS=17
else
    STEPS=26
fi
STEP=0

# Function to print step headers
print_step() {
    STEP=$((STEP + 1))
    echo ""
    echo "${BLUE}${BOLD}═══════════════════════════════════════════════════════════════${NC}"
    echo "${BLUE}${BOLD}  $STEP/$STEPS $1${NC}"
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

    if eval "$cmd"; then
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
if [ "$QUALITY_ONLY" = true ]; then
    echo "${BOLD}Starting check_msdefender Package Quality Checks...${NC}"
else
    echo "${BOLD}Starting check_msdefender Package Publishing Process...${NC}"
fi

# Sync with the remote BEFORE doing any work so the release commit/tag at the
# end fast-forwards cleanly — avoids a `git push` rejection (remote moved)
# after the build+publish have already shipped to PyPI. Publish-only: quality
# checks never touch git state. Runs from a clean tree (rebase aborts on
# uncommitted changes — commit your work before publishing).
if [ "$QUALITY_ONLY" = false ]; then
    print_step "Syncing with Remote (git pull --rebase)"
    run_command "git pull --rebase" "Git pull --rebase"
fi

print_step "Cleaning Previous Build (pdm run clean)"
run_command "pdm run clean" "Clean"

print_step "Installing Dependencies (pdm install)"
run_command "pdm run install" "Dependencies installation"

print_step "Installing Development Dependencies (pdm install-dev)"
run_command "pdm run install-dev" "Development dependencies installation"

print_step "Checking for Outdated Dependencies (pdm outdated)"
run_command "pdm outdated" "Outdated Dependencies"

print_step "Updating Dependencies (pdm update)"
run_command "pdm update" "Dependencies update"

print_step "Converting to Absolute Imports (absolufy-imports)"
run_command "pdm run absolufy" "Import conversion"

print_step "Sorting Imports (ruff isort)"
run_command "pdm run isort" "Import sorting"

print_step "Code Formatting (ruff format)"
run_command "pdm run format" "Code formatting"

print_step "Docstring Formatting (docformatter)"
run_command "pdm run docformatter" "Docstring formatting"

print_step "Type Checking (pyright)"
run_command "pdm run typecheck" "Type checking"

print_step "Docstring Lint (flake8)"
run_command "pdm run flake8" "Docstring lint"

print_step "Docstring Coverage (interrogate)"
run_command "pdm run interrogate" "Docstring coverage"

print_step "Code Quality Check (refurb)"
run_command "pdm run refurb" "Code quality check"

print_step "Linting (ruff)"
run_command "pdm run lint" "Linting"

print_step "Dead Code Check (vulture)"
run_command "pdm run vulture" "Dead code check"

print_step "Running Tests (pytest)"
if [ "$CI_MODE" = true ]; then
    run_command "pdm run test-ci" "Tests (CI)"
else
    run_command "pdm run test" "Tests"
fi

# Blocking quality-metrics gate: absolute ceilings/floors + best-ever ratchet
# vs doc/quality-history.csv. Runs after the tests so the coverage-based rules
# read fresh data (.coverage / coverage.xml).
print_step "Quality Metrics Gate (ratchet)"
run_command "pdm run metrics-gate" "Quality metrics gate"

# Exit here if --quality flag is set
if [ "$QUALITY_ONLY" = true ]; then
    echo ""
    echo "${GREEN}${BOLD}🎉 QUALITY CHECKS COMPLETED SUCCESSFULLY! 🎉${NC}"
    echo "${GREEN}${BOLD}═══════════════════════════════════════════════════════════════${NC}"
    echo "${GREEN}All quality checks have passed. Your code is ready for publishing!${NC}"
    echo ""
    exit 0
fi

print_step "Running Integration Tests"
run_command "pdm run check_msdefender_integration -q" "Integration tests"

# Push the current (committed) code to trigger the SonarCloud analysis, then
# wait for its quality gate before releasing. Gated on SONAR_TOKEN being
# present (env or .env) so a publish made before SonarCloud is wired up skips
# cleanly instead of hard-failing. 900s: GitHub CI takes ~4-5 min to produce
# the analysis of the pushed commit; a short timeout would lose the race.
print_step "Sonarcloud Quality Gate"
HAS_SONAR_TOKEN=false
if [ -n "${SONAR_TOKEN:-}" ]; then
    HAS_SONAR_TOKEN=true
elif [ -f .env ] && grep -q '^SONAR_TOKEN=' .env 2>/dev/null; then
    HAS_SONAR_TOKEN=true
fi
if [ "$HAS_SONAR_TOKEN" = true ]; then
    run_command "git push" "Pushing commits for analysis"
    if python scripts/sonar_gate.py --timeout 900 --interval 20; then
        print_success "Sonarcloud quality gate passed"
    else
        print_error "Sonarcloud quality gate FAILED — aborting publish"
    fi
else
    echo "${YELLOW}WARN: SONAR_TOKEN absent — skipping SonarCloud gate.${NC}"
    echo "${YELLOW}      Create the project on sonarcloud.io (key lduchosal_check_msdefender),${NC}"
    echo "${YELLOW}      add the SONAR_TOKEN secret + the SonarCloud CI job, then set${NC}"
    echo "${YELLOW}      SONAR_TOKEN locally to enable this gate.${NC}"
fi

print_step "Bumping Version (pdm bump ${BUMP_TYPE})"
run_command "pdm bump ${BUMP_TYPE}" "Version bump"

# Extract version after bump
VERSION=$(python -c "import check_msdefender; print(check_msdefender.__version__)")
echo "${BLUE}New version: ${VERSION}${NC}"

print_step "Building Package (pdm)"
run_command "pdm build" "Package build"

print_step "Publishing Package (pdm publish)"
run_command "pdm publish" "Package publishing"

print_step "Adding All Files to Git"
run_command "git add ." "Adding all files to git"

print_step "Committing, Tagging and Pushing"
COMMIT_MSG="chore: release version ${VERSION}"
run_command "git commit -m \"${COMMIT_MSG}\"" "Git commit"
run_command "git tag check-msdefender-${VERSION}" "Creating git tag"
run_command "git push" "Pushing commits"
run_command "git push --tags" "Pushing tags"

print_step "Cleaning Previous Build (pdm run clean)"
run_command "pdm run clean" "Clean"

echo ""
echo "${GREEN}${BOLD}🎉 PUBLISHING COMPLETED SUCCESSFULLY! 🎉${NC}"
echo "${GREEN}${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo "${GREEN}Your check_msdefender package has been successfully published and tagged!${NC}"
echo ""
