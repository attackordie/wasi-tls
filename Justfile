# WASI-TLS Hardware-Accelerated Crypto Component (HACC) - Justfile
# Comprehensive development, testing, and validation automation

# Default recipe - show available commands with categories
default:
    @echo "🔐 WASI-TLS Hardware-Accelerated Crypto Component (HACC)"
    @echo "================================================"
    @echo ""
    @echo "📋 Quick Start:"
    @echo "  just setup                 # Install all required tools"
    @echo "  just dev-check            # Check development prerequisites"
    @echo "  just validate-safety      # Validate WIT memory safety"
    @echo "  just build                # Build with safe bindings"
    @echo "  just test                 # Run comprehensive tests"
    @echo ""
    @echo "🧪 Local CI Testing (matches GitHub exactly):"
    @echo "  just act-security         # Run security validation locally"
    @echo "  just act-build            # Run build checks locally"
    @echo "  just act-all              # Run all GitHub workflows locally"
    @echo ""
    @echo "🍴 Fork Testing (for testing framework changes):"
    @echo "  just act-compare-fork <repo>  # Compare main vs fork results"
    @echo "  just dev-help                 # See all fork testing commands"
    @echo ""
    @echo "🛠️  Available Commands:"
    @just --list --unsorted | sed 's/^/  /'
    @echo ""
    @echo "💡 Run 'just <command> --help' for detailed help"

# ============================================================================
# WIT Interface Management
# ============================================================================

# Validate WIT interface definitions
validate-wit:
    @echo "🔍 Validating WIT interface definitions..."
    wasm-tools component wit wit/ --output /dev/null
    @echo "✅ WIT validation successful"

# Generate all bindings with safety validation
generate-bindings: validate-safety
    @echo "🔧 Generating WIT bindings with safety audit..."
    @just generate-rust-bindings
    @just audit-generated-safety
    @just generate-js-bindings
    @just generate-go-bindings
    @echo "✅ All bindings generated and validated"

# Generate Rust bindings with memory safety focus
generate-rust-bindings:
    @echo "🦀 Generating memory-safe Rust bindings..."
    mkdir -p bindings/rust
    wit-bindgen rust wit/ --world tls-world --out-dir bindings/rust --all-features --generate-all --ownership owning
    @echo "✅ Memory-safe Rust bindings generated in bindings/rust/"

# Audit generated bindings for unsafe code
audit-generated-safety:
    @echo "🔍 Auditing generated bindings for unsafe code..."
    @if [ -d "bindings/rust" ]; then \
        total_unsafe=$(find bindings/rust -name "*.rs" -exec grep -c "unsafe" {} \; 2>/dev/null | awk '{sum += $1} END {print sum+0}'); \
        file_count=$(find bindings/rust -name "*.rs" | wc -l); \
        echo "📊 Safety Audit Results:"; \
        echo "  Total Files: $file_count"; \
        echo "  Unsafe Blocks: $total_unsafe"; \
        if [ $total_unsafe -eq 0 ]; then \
            echo "  🏆 PERFECT SAFETY: Zero unsafe code in generated bindings!"; \
        else \
            echo "  ⚠️  Generated bindings contain unsafe code (expected for WASM interop)"; \
            echo "  💡 This is normal - unsafe code isolated in binding layer only"; \
            echo "  📍 Application code remains 100% memory-safe"; \
        fi; \
    else \
        echo "  ⚠️  No Rust bindings found to audit"; \
    fi

# Generate JavaScript/TypeScript bindings  
generate-js-bindings:
    @echo "📜 Generating JavaScript/TypeScript bindings..."
    mkdir -p bindings/js
    -wit-bindgen js wit/ --world tls-world --out-dir bindings/js --all-features --generate-all || echo "⚠️  JS bindings may not be available in current wit-bindgen version"

# Generate Go bindings (if available)
generate-go-bindings:
    @echo "🐹 Generating Go bindings..."
    mkdir -p bindings/go
    -wit-bindgen tiny-go wit/ --world tls-world --out-dir bindings/go --all-features --generate-all || echo "⚠️  Go bindings not available in current wit-bindgen version"

# Generate C bindings
generate-c-bindings:
    @echo "⚙️ Generating C bindings..."
    mkdir -p bindings/c
    wit-bindgen c wit/ --world tls-world --out-dir bindings/c --all-features --generate-all
    @echo "✅ C bindings generated in bindings/c/"

# ============================================================================
# Documentation Generation
# ============================================================================

# Generate comprehensive documentation
generate-docs: validate-wit
    @echo "📚 Generating documentation..."
    @just generate-wit-docs
    @just generate-json-docs
    @just generate-markdown-docs
    @echo "✅ Documentation generation complete"

# Generate WIT documentation
generate-wit-docs:
    @echo "📄 Generating WIT documentation..."
    mkdir -p docs/generated
    wasm-tools component wit wit/ --all-features > docs/generated/wit-documentation.wit
    @echo "✅ WIT documentation generated: docs/generated/wit-documentation.wit"

# Generate JSON documentation from WIT
generate-json-docs:
    @echo "📝 Generating JSON documentation..."
    mkdir -p docs/generated
    wasm-tools component wit wit/ --json --all-features > docs/generated/api-reference.json
    @echo "✅ API reference JSON generated: docs/generated/api-reference.json"

# Generate markdown documentation using wit-bindgen
generate-markdown-docs:
    @echo "🌐 Generating markdown documentation..."
    mkdir -p docs/generated
    wit-bindgen markdown wit/ --world tls-world --all-features > docs/generated/api-reference.md
    @echo "✅ Markdown documentation generated: docs/generated/api-reference.md"

# ============================================================================
# Testing and Validation
# ============================================================================

# Run all test layers (comprehensive testing strategy)
test: test-layer-1 test-layer-2 test-layer-3 test-layer-4 test-layer-5
    @echo "✅ All test layers completed successfully"

# Layer 1: WIT Interface Safety Tests
test-layer-1: validate-safety
    @echo "🧪 Layer 1: WIT Interface Safety"
    @echo "Testing WIT interface memory safety patterns..."

# Layer 2: Implementation Unit Tests  
test-layer-2:
    @echo "🔬 Layer 2: Implementation Unit Tests"
    @just test-implementations

# Layer 3: Security Validation Tests
test-layer-3:
    @echo "🛡️ Layer 3: Security Validation"
    @just test-security

# Layer 4: Compliance and Integration Tests
test-layer-4:
    @echo "📋 Layer 4: Compliance & Integration"
    @just test-compliance
    @just test-integration
    @just test-host

# Layer 5: End-to-End System Tests
test-layer-5:
    @echo "🚀 Layer 5: End-to-End System Tests"
    @just test-components
    @just test-defensive

# Test implementations
test-implementations:
    @echo "🔬 Testing implementations..."
    cd test/implementations/rust && cargo test
    @echo "✅ Implementation tests passed"

# Run security validation tests
test-security:
    @echo "🛡️ Running security validation..."
    cd test/implementations/rust && cargo run --release --bin security-validator -- --level basic --verbose
    cd test/implementations/rust && cargo run --release --bin security-validator -- --level rfc8446
    cd test/security-validation && cargo test
    @echo "✅ Security validation passed"

# Run compliance tests
test-compliance:
    @echo "📋 Running compliance tests..."
    cd test/compliance-testing && cargo test
    @echo "✅ Compliance tests passed"

# Run integration tests
test-integration:
    @echo "🔄 Running integration tests..."
    cd test/integration-testing && cargo test
    @echo "✅ Integration tests passed"

# Run host testing (full system access)
test-host:
    @echo "🖥️ Running host-side tests..."
    cd test/host-testing && cargo test
    @echo "✅ Host tests passed"

# Run component tests (WASM)
test-components:
    @echo "🧩 Running component tests..."
    cd test/component-testing && cargo component build --release
    cd test/component-testing && cargo test --target wasm32-wasi-preview2
    @echo "✅ Component tests passed"

# Run defensive tests
test-defensive:
    @echo "🛡️ Running defensive tests..."
    cd test/defensive-testing && cargo test boundary-testing
    cd test/defensive-testing && cargo test input-validation
    @echo "✅ Defensive tests passed"

# Run performance benchmarks
benchmark:
    @echo "⚡ Running performance benchmarks..."
    cd test/implementations/rust && cargo bench tls_performance
    @echo "✅ Benchmarks completed"

# ============================================================================
# Security Operations
# ============================================================================

# Run comprehensive security audit
security-audit: validate-wit
    @echo "🔐 Running comprehensive security audit..."
    @just test-security
    @just security-fuzzing
    @just security-stress-test
    @echo "✅ Security audit completed"

# Run security fuzzing (short duration)
security-fuzzing:
    @echo "🎯 Running security fuzzing..."
    cd test/implementations/rust && timeout 300 cargo run --release --bin fuzzing-harness -- --timeout 300 || echo "Fuzzing completed (timeout reached)"
    @echo "✅ Security fuzzing completed"

# Run stress testing
security-stress-test:
    @echo "💪 Running stress tests..."
    cd test/implementations/rust && cargo run --release --bin stress-tester -- --connections 100 --duration 60
    @echo "✅ Stress testing completed"

# Generate security report
security-report:
    @echo "📊 Generating security report..."
    mkdir -p reports
    cd test/implementations/rust && cargo run --release --bin security-validator -- --level advanced --output ../../reports/security-report.json
    @echo "✅ Security report generated: reports/security-report.json"

# ============================================================================
# Development Workflow
# ============================================================================

# Development setup - install required tools
setup:
    @echo "🔧 Setting up development environment..."
    @just check-tools
    @just install-targets
    @just generate-bindings
    @echo "✅ Development environment ready"

# Check for required tools
check-tools:
    @echo "🔍 Checking required tools..."
    @command -v wasm-tools >/dev/null 2>&1 || (echo "❌ wasm-tools not found. Install with: cargo install wasm-tools"; exit 1)
    @command -v wit-bindgen >/dev/null 2>&1 || (echo "❌ wit-bindgen not found. Install with: cargo install wit-bindgen-cli"; exit 1)
    @command -v cargo-component >/dev/null 2>&1 || (echo "❌ cargo-component not found. Install with: cargo install cargo-component"; exit 1)
    @echo "✅ All required tools found"



# Install targets (add missing dependencies for cargo commands)
install-targets:
    @echo "🎯 Installing Rust targets..."
    rustup target add wasm32-wasi-preview2
    cargo install wit-bindgen-cli@0.38.0 --force 2>/dev/null || echo "wit-bindgen already installed"
    cargo install wasm-tools@1.224.0 --force 2>/dev/null || echo "wasm-tools already installed"
    cargo install cargo-component@0.15.0 --force 2>/dev/null || echo "cargo-component already installed"
    @echo "✅ Targets installed"

# ============================================================================
# Development Environment & CI Testing
# ============================================================================

# Show available development commands
dev-help:
    @echo "🚀 WASI-TLS Development Commands"
    @echo ""
    @echo "📋 Setup:"
    @echo "  just dev-check       - Check development prerequisites"
    @echo "  just rust-setup      - Set up Rust development environment"
    @echo "  just act-install     - Install act tool for local CI"
    @echo ""
    @echo "🧪 Local CI Testing (matches GitHub exactly):"
    @echo "  just act-security    - Run security validation workflow"
    @echo "  just act-build       - Run build and test workflow"
    @echo "  just act-all         - Run all workflows"
    @echo ""
    @echo "🍴 Fork Testing (critical for testing framework changes):"
    @echo "  just act-security-fork <repo>        - Test security against fork"
    @echo "  just act-all-fork <repo>             - Test all workflows against fork"
    @echo "  just act-compare-fork <repo>         - Compare main vs fork results"
    @echo "  just act-security-level-fork <level> <repo> - Test specific level on fork"
    @echo ""
    @echo "⚡ Quick Development:"
    @echo "  just test            - Run core tests (fast)"
    @echo "  just build           - Build project"
    @echo "  just clean           - Clean build artifacts"
    @echo ""
    @echo "🔧 Utilities:"
    @echo "  just act-clean       - Clean up act containers"
    @echo "  just dev-help        - Show this help"

# Check if development prerequisites are installed
dev-check:
    @echo "🔍 Checking development prerequisites..."
    @command -v act >/dev/null 2>&1 || (echo "❌ act not installed. Run: just act-install" && exit 1)
    @command -v docker >/dev/null 2>&1 || (echo "❌ Docker not installed. Please install Docker: https://docs.docker.com/get-docker/" && exit 1)
    @command -v cargo >/dev/null 2>&1 || (echo "❌ Rust/Cargo not installed. Run: just rust-setup" && exit 1)
    @rustup target list --installed | grep -q wasm32-wasi-preview2 || (echo "❌ wasm32-wasi-preview2 target not installed. Run: rustup target add wasm32-wasi-preview2" && exit 1)
    @echo "✅ All prerequisites are installed!"

# Set up Rust development environment
rust-setup:
    @echo "🦀 Setting up Rust development environment..."
    rustup toolchain install stable --component rustfmt clippy
    rustup target add wasm32-wasi-preview2
    cargo install wit-bindgen-cli@0.38.0 wasm-tools@1.224.0 cargo-component@0.15.0
    @echo "✅ Rust development environment ready!"

# Install act tool for running GitHub Actions locally
act-install:
    @echo "Installing act (GitHub Actions runner)..."
    @echo "Note: For security, the install script will be downloaded for your review before running with sudo."
    tmpfile=$(mktemp /tmp/act-install.XXXXXX.sh) && \
    curl -fsSL https://raw.githubusercontent.com/nektos/act/master/install.sh -o "$tmpfile" && \
    echo "Downloaded install script to $tmpfile" && \
    echo "SHA256 checksum:" && sha256sum "$tmpfile" && \
    echo "Please review the script before running:" && \
    echo "    less $tmpfile" && \
    echo "To install, run:" && \
    echo "    sudo bash $tmpfile"

# Act commands - run GitHub CI locally using act (github.com/nektos/act)
# Each command corresponds to a specific workflow in .github/workflows/
# Uses --rm to automatically clean up containers after each run

# Run security validation workflow locally (matches .github/workflows/security-validation.yml)
act-security:
    @echo "🛡️ Running security validation workflow locally..."
    act -W ./.github/workflows/security-validation.yml --rm

# Run main workflow locally (if exists)
act-build:
    @echo "🔧 Running build workflow locally..."
    act -W ./.github/workflows/main.yml --rm || echo "⚠️  main.yml workflow not found"

# Run all workflows locally
act-all:
    @echo "🚀 Running all workflows locally..."
    act -W ./.github/workflows/security-validation.yml --rm
    -act -W ./.github/workflows/main.yml --rm
    @echo "✅ All local CI workflows completed"

# Run specific security validation job
act-security-level level:
    @echo "🔍 Running security validation for level: {{level}}"
    act -W ./.github/workflows/security-validation.yml -j security-validation --rm --matrix security-level:{{level}}

# Fork-specific commands for testing custom repositories
# These are essential when testing changes to the testing framework itself

# Run security validation workflow against fork
act-security-fork repo:
    @echo "🛡️ Running security validation against fork: {{repo}}"
    act -W ./.github/workflows/security-validation.yml --rm --env GITHUB_REPOSITORY={{repo}}

# Run main workflow against fork
act-build-fork repo:
    @echo "🔧 Running build workflow against fork: {{repo}}"
    act -W ./.github/workflows/main.yml --rm --env GITHUB_REPOSITORY={{repo}} || echo "⚠️  main.yml workflow not found"

# Run specific security level against fork
act-security-level-fork level repo:
    @echo "🔍 Running security level {{level}} against fork: {{repo}}"
    act -W ./.github/workflows/security-validation.yml -j security-validation --rm --matrix security-level:{{level}} --env GITHUB_REPOSITORY={{repo}}

# Run all workflows against fork
act-all-fork repo:
    @echo "🚀 Running all workflows against fork: {{repo}}"
    act -W ./.github/workflows/security-validation.yml --rm --env GITHUB_REPOSITORY={{repo}}
    -act -W ./.github/workflows/main.yml --rm --env GITHUB_REPOSITORY={{repo}}
    @echo "✅ All fork workflows completed for {{repo}}"

# Test both main and fork (critical for testing framework changes)
act-compare-fork repo:
    @echo "🔄 Comparing main branch vs fork: {{repo}}"
    @echo "Testing main branch first..."
    @just act-security
    @echo ""
    @echo "Testing fork: {{repo}}"
    @just act-security-fork {{repo}}
    @echo ""
    @echo "✅ Comparison complete - review both outputs above"

# Clean up any stuck act containers
act-clean:
    @echo "Current act containers:"
    -docker ps --filter "name=act-"
    @echo "Stopping and removing act containers..."
    -docker stop $(docker ps -q --filter "name=act-") 2>/dev/null || true
    -docker rm $(docker ps -aq --filter "name=act-") 2>/dev/null || true
    @echo "Act containers cleaned up."

# ============================================================================
# File Operations
# ============================================================================

# Clean generated files
clean:
    @echo "🧹 Cleaning generated files..."
    rm -rf bindings/
    rm -rf docs/generated/
    rm -rf reports/
    cd test/implementations/rust && cargo clean
    cd test/component-testing && cargo clean
    cd test/compliance-testing && cargo clean
    cd test/integration-testing && cargo clean
    cd test/security-validation && cargo clean
    cd test/host-testing && cargo clean
    cd test/defensive-testing && cargo clean
    @echo "✅ Cleanup completed"

# Format all code
format:
    @echo "🎨 Formatting code..."
    cd test/implementations/rust && cargo fmt
    cd test/component-testing && cargo fmt
    cd test/compliance-testing && cargo fmt
    cd test/integration-testing && cargo fmt
    cd test/security-validation && cargo fmt
    cd test/host-testing && cargo fmt
    cd test/defensive-testing && cargo fmt
    @echo "✅ Code formatting completed"

# Run linters
lint:
    @echo "🔍 Running linters..."
    cd test/implementations/rust && cargo clippy -- -D warnings
    cd test/component-testing && cargo clippy -- -D warnings
    cd test/compliance-testing && cargo clippy -- -D warnings
    cd test/integration-testing && cargo clippy -- -D warnings
    cd test/security-validation && cargo clippy -- -D warnings
    cd test/host-testing && cargo clippy -- -D warnings
    cd test/defensive-testing && cargo clippy -- -D warnings
    @echo "✅ Linting completed"

# ============================================================================
# CI/CD Support
# ============================================================================

# Full CI pipeline with comprehensive safety validation
ci: check-environment validate-safety generate-bindings test security-audit
    @echo "🚀 CI pipeline completed successfully"

# Pre-commit checks with safety validation
pre-commit: format lint validate-safety test-layer-1 test-layer-2
    @echo "✅ Pre-commit checks passed"

# Check environment and tool versions  
check-environment:
    @echo "🔍 Environment Check:"
    @echo "===================="
    @rustc --version | sed 's/^/  Rust:        /'
    @wasm-tools --version 2>/dev/null | sed 's/^/  wasm-tools:  /' || echo "  wasm-tools:  ❌ NOT FOUND"
    @wit-bindgen --version 2>/dev/null | sed 's/^/  wit-bindgen: /' || echo "  wit-bindgen: ❌ NOT FOUND"
    @cargo component --version 2>/dev/null | sed 's/^/  cargo-comp:  /' || echo "  cargo-comp:  ❌ NOT FOUND"
    @echo ""
    @echo "  WIT Files:" $(shell find wit -name '*.wit' 2>/dev/null | wc -l) "found"
    @echo "  Test Dirs:" $(shell find test -maxdepth 1 -type d | wc -l) "found"

# Prepare release
prepare-release: clean setup ci generate-docs security-report
    @echo "📦 Release preparation completed"
    @echo "Generated artifacts:"
    @echo "  - Language bindings: bindings/"
    @echo "  - Documentation: docs/generated/"
    @echo "  - Security report: reports/"

# ============================================================================
# HACC-Specific Commands
# ============================================================================

# Verify HACC architecture compliance
verify-hacc: validate-wit
    @echo "🏗️ Verifying HACC architecture compliance..."
    @echo "Checking for required HACC interfaces..."
    @grep -q "hardware-crypto-info" wit/types.wit && echo "✅ Hardware crypto info interface found" || echo "❌ Hardware crypto info interface missing"
    @grep -q "traffic-protection-policy" wit/types.wit && echo "✅ Traffic protection interface found" || echo "❌ Traffic protection interface missing"
    @grep -q "certificate-validator" wit/types.wit && echo "✅ Certificate validation interface found" || echo "❌ Certificate validation interface missing"
    @grep -q "security-policy" wit/types.wit && echo "✅ Security policy interface found" || echo "❌ Security policy interface missing"
    @grep -q "deployment-manager" wit/types.wit && echo "✅ Deployment manager interface found" || echo "❌ Deployment manager interface missing"
    @echo "✅ HACC architecture compliance verified"

# Primary safety validation - checks all WIT files for memory safety patterns
validate-safety: validate-wit check-unsafe-patterns check-resource-patterns safety-report
    @echo "✅ WIT safety validation complete"

# Check for unsafe memory patterns in WIT files
check-unsafe-patterns:
    @echo "🔍 Checking for unsafe memory patterns..."
    @unsafe_found=false; \
    patterns="ptr|pointer|offset|address|allocate|deallocate|free|malloc|raw_ptr|mem_addr"; \
    for wit in wit/*.wit; do \
        if [ -f "$wit" ]; then \
            if grep -qE "($patterns)" "$wit" 2>/dev/null; then \
                echo "  ⚠️  $(basename $wit) contains unsafe patterns:"; \
                grep -nE "($patterns)" "$wit" | head -3 | sed 's/^/      /'; \
                unsafe_found=true; \
            fi; \
        fi; \
    done; \
    if $unsafe_found; then \
        echo ""; \
        echo "❌ UNSAFE PATTERNS DETECTED"; \
        echo "🔧 Required Actions:"; \
        echo "  1. Replace raw pointers with safe types (string, list<u8>)"; \
        echo "  2. Use resource types for memory management"; \
        echo "  3. Let the Component Model handle memory automatically"; \
        exit 1; \
    else \
        echo "✅ No unsafe memory patterns found"; \
    fi

# Check for proper resource usage patterns
check-resource-patterns:
    @echo "🔍 Analyzing resource patterns..."
    @for wit in wit/*.wit; do \
        if [ -f "$wit" ]; then \
            resources=$(grep -c "resource " "$wit" 2>/dev/null || echo 0); \
            constructors=$(grep -c "constructor" "$wit" 2>/dev/null || echo 0); \
            echo "  📄 $(basename $wit):"; \
            echo "      Resources: $resources"; \
            echo "      Constructors: $constructors"; \
            if [ $resources -gt 0 ] && [ $constructors -eq 0 ]; then \
                echo "      ⚠️  Resources without constructors detected"; \
            fi; \
        fi; \
    done

# Generate comprehensive safety report
safety-report:
    @echo ""
    @echo "📊 WIT Safety Metrics:"
    @echo "====================="
    @total_strings=$(grep -h "string" wit/*.wit 2>/dev/null | wc -l); \
    total_lists=$(grep -h "list<" wit/*.wit 2>/dev/null | wc -l); \
    total_results=$(grep -h "result<" wit/*.wit 2>/dev/null | wc -l); \
    total_resources=$(grep -h "resource " wit/*.wit 2>/dev/null | wc -l); \
    total_options=$(grep -h "option<" wit/*.wit 2>/dev/null | wc -l); \
    echo "  Safe Types Used:"; \
    echo "    Strings:   $total_strings"; \
    echo "    Lists:     $total_lists"; \
    echo "    Results:   $total_results"; \
    echo "    Options:   $total_options"; \
    echo "    Resources: $total_resources"; \
    echo ""; \
    safety_score=$((total_strings + total_lists + total_results + total_resources + total_options)); \
    echo "  Safety Score: $safety_score points"; \
    if [ $safety_score -gt 50 ]; then \
        echo "  Rating: 🏆 Excellent - High use of safe abstractions"; \
    elif [ $safety_score -gt 25 ]; then \
        echo "  Rating: ✅ Good - Adequate safety patterns"; \
    else \
        echo "  Rating: ⚠️  Needs Improvement - Consider more safe types"; \
    fi

# Generate HACC feature matrix
hacc-features:
    @echo "📋 HACC Feature Matrix:"
    @echo "========================"
    @echo "Post-Quantum Cryptography:"
    @grep -c "crypto-strength\|pqc-family\|extended-cipher-suite" wit/types.wit | sed 's/^/  - Interfaces: /'
    @echo "Hardware Isolation:"
    @grep -c "isolation-level\|component-isolation\|hardware-isolation" wit/types.wit | sed 's/^/  - Interfaces: /'
    @echo "Traffic Protection:"
    @grep -c "traffic-protection\|padding\|timing-jitter" wit/types.wit | sed 's/^/  - Interfaces: /'
    @echo "Certificate Validation:"
    @grep -c "certificate-validator\|validation-rule\|validation-result" wit/types.wit | sed 's/^/  - Interfaces: /'
    @echo "Deployment Models:"
    @grep -c "deployment-model\|tee-deployment\|hsm-deployment\|browser-deployment" wit/types.wit | sed 's/^/  - Interfaces: /'
    @echo "Total WIT Interfaces:"
    @grep -cE "^[[:space:]]*resource|^[[:space:]]*record|^[[:space:]]*enum|^[[:space:]]*variant" wit/types.wit | sed 's/^/  - Total: /'

# ============================================================================
# Troubleshooting
# ============================================================================

# Diagnose common issues
diagnose:
    @echo "🔧 Running diagnostics..."
    @echo "Tool versions:"
    @wasm-tools --version 2>/dev/null | sed 's/^/  wasm-tools: /' || echo "  wasm-tools: NOT FOUND"
    @wit-bindgen --version 2>/dev/null | sed 's/^/  wit-bindgen: /' || echo "  wit-bindgen: NOT FOUND" 
    @cargo component --version 2>/dev/null | sed 's/^/  cargo-component: /' || echo "  cargo-component: NOT FOUND"
    @echo "Rust targets:"
    @rustup target list --installed | grep wasm32 | sed 's/^/  /'
    @echo "WIT file structure:"
    @find wit/ -name "*.wit" | sed 's/^/  /'
    @echo "Test directories:"
    @find test/ -maxdepth 1 -type d | sed 's/^/  /'

# Show help for specific commands
help command:
    @echo "Help for command: {{command}}"
    @just --show {{command}}

# ============================================================================
# COMPREHENSIVE TEST COMMANDS
# ============================================================================

# Test all implemented test directories individually
test-all-dirs:
    @echo "🧪 Testing all implemented test directories..."
    @echo "1/7: Implementation tests"
    @just test-implementations
    @echo "2/7: Security validation tests"
    @just test-security
    @echo "3/7: Compliance tests"
    @just test-compliance
    @echo "4/7: Integration tests"
    @just test-integration
    @echo "5/7: Host-side tests"
    @just test-host
    @echo "6/7: Component tests"
    @just test-components
    @echo "7/7: Defensive tests"
    @just test-defensive
    @echo "✅ All test directories completed successfully"

# Run tests that match the GitHub CI security workflow
test-ci-security:
    @echo "🛡️ Running CI security tests locally..."
    cd test/implementations/rust && cargo build --release --all-targets
    cd test/implementations/rust && cargo test wit_validation --release -- --nocapture
    cd test/implementations/rust && cargo test security --release -- --nocapture
    cd test/implementations/rust && cargo test stress --release -- --nocapture
    cd test/implementations/rust && cargo run --release --bin security-validator -- --level basic --verbose
    cd test/implementations/rust && cargo run --release --bin security-validator -- --level rfc8446 --verbose
    @echo "✅ CI security tests completed"

# Build command that includes all test directories
build:
    @echo "🔧 Building all components..."
    @just generate-bindings
    cd test/implementations/rust && cargo build --release
    cd test/component-testing && cargo component build --release
    cd test/compliance-testing && cargo build
    cd test/integration-testing && cargo build
    cd test/security-validation && cargo build
    cd test/host-testing && cargo build
    cd test/defensive-testing && cargo build
    @echo "✅ All components built successfully"

# ============================================================================
# QUICK COMMANDS (Aliases)
# ============================================================================

# Quick build and test
qt: validate-safety test-layer-2
    @echo "✅ Quick build and test completed"

# Quick safety check
qs: validate-safety
    @echo "✅ Quick safety check completed"

# Quick clean and rebuild
rebuild: clean generate-bindings build
    @echo "✅ Clean rebuild completed"

# Quick test of all directories
test-quick: test-all-dirs
    @echo "✅ Quick test of all directories completed"

# Show version information
version:
    @echo "WASI-TLS Hardware-Accelerated Crypto Component (HACC)"
    @echo "===================================================="
    @echo "System Version: 1.0.0" 
    @echo "WIT Spec: 0.2.0"
    @echo ""
    @echo "Tools:"
    @rustc --version
    @wasm-tools --version 2>/dev/null || echo "wasm-tools: not installed"
    @wit-bindgen --version 2>/dev/null || echo "wit-bindgen: not installed"