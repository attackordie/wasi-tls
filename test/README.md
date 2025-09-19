# WASI-TLS Testing Framework

## 🛡️ Security-First Testing Architecture

This document outlines the comprehensive testing strategy for the WASI-TLS proposal, with a focus on **responsible security testing** that validates security requirements while avoiding the creation of tools that could be misused against other projects.

### Core Principles

1. **WIT-Driven Testing**: All tests originate from and validate against `wit/types.wit`
2. **Security-First Design**: Validate TLS 1.3 security constraints through interface design
3. **Defensive Testing**: Focus on validation that security requirements are met
4. **Responsible Research**: Separate public defensive testing from private vulnerability research

## 📁 Testing Directory Structure

```
test/
├── README.md                    # This file
├── host-testing/               # 🔓 PUBLIC: Host-side testing (full system access)
│   ├── src/
│   │   ├── integration/        # End-to-end network testing
│   │   ├── compliance/         # RFC 8446 compliance with real TLS stacks
│   │   └── security/          # Host-side security validation
│   ├── Cargo.toml             # Full dependencies (tokio, rustls, etc.)
│   └── benches/               # Performance benchmarking
├── component-testing/          # 🔓 PUBLIC: WASM component testing (no system calls)
│   ├── src/
│   │   ├── wit-validation/     # Pure WIT interface logic validation
│   │   ├── unit-tests/        # Component behavior testing
│   │   └── input-validation/  # Safe input boundary testing
│   ├── Cargo.toml             # WASM-compatible dependencies only
│   └── wasm-tests/            # WASM-specific test targets
├── fixtures/                   # 🔓 PUBLIC: Test certificates (marked TEST-ONLY)
│   ├── public/                # Safe test data (both host and component)
│   └── README.md              # Security guidelines for test data
└── private/                    # 🔒 PRIVATE: Vulnerability research (gitignored)
    ├── README.md              # Security research guidelines
    ├── fuzzing/               # Advanced fuzzing tools (host-side only)
    ├── exploit-tools/         # Vulnerability research utilities
    └── attack-payloads/       # Malicious test inputs
```

### 🖥️ Host-Side Testing (`/test/host-testing/`)

**Environment**: Development machines, CI/CD servers, full system access

**Capabilities**:
- ✅ System calls (network, filesystem, threads)
- ✅ Async runtimes (tokio, async-std)
- ✅ Real TLS implementations (rustls, openssl)
- ✅ Performance benchmarking and profiling
- ✅ Integration with external services

**Dependencies**: tokio, rustls, wasmtime, criterion, tempfile

### 🔒 Component Testing (`/test/component-testing/`)

**Environment**: WASM isolates (V8, wasmtime, browser)

**Capabilities**:
- ❌ No system calls
- ❌ No async runtimes  
- ❌ No filesystem access
- ❌ No network access
- ✅ Pure computational logic
- ✅ WASI-provided interfaces only

**Dependencies**: wit-bindgen, wasi, pure Rust crates (no_std compatible)

**🚨 IMPORTANT**: The `/test/private/` directory is gitignored and should NEVER be committed to public repositories. It contains vulnerability research tools that could be misused.

## 🔓 Public Security Validation

### 1. WIT Interface Security Validation

**Location**: `test/security-validation/src/wit_validation.rs`

**Purpose**: Validates that the WIT interface design prevents common TLS vulnerabilities through interface constraints.

**Key Validations**:
- **TLS 1.3 Only Constraint**: Ensures interface only supports TLS 1.3 (0x0304)
- **No 0-RTT Support**: Validates 0-RTT is prohibited (prevents replay attacks)
- **No Session Resumption**: Ensures session resumption is not supported (maintains forward secrecy)
- **Mandatory Certificate Validation**: Verifies hostname verification and certificate validation are required
- **Comprehensive Error Handling**: Validates all security-relevant error conditions are covered

```rust
// Example: Real WIT interface security validation
#[test]
fn test_tls13_only_constraint() {
    let wit_content = read_wit_types_file()?;
    assert!(wit_content.contains("0x0304"));      // TLS 1.3
    assert!(!wit_content.contains("0x0303"));     // No TLS 1.2
}
```

### 2. TLS 1.3 RFC 8446 Compliance Testing

**Location**: `test/security-validation/src/tls_compliance.rs`

**Purpose**: Real-world validation of TLS 1.3 compliance using actual certificates and cryptographic validation.

**Key Features**:
- **Real Certificate Generation**: Uses `rcgen` to create actual test certificates
- **Actual Certificate Parsing**: Uses `x509-parser` for real X.509 validation
- **Cryptographic Security Validation**: Tests cipher suites, key exchange groups, signature algorithms
- **Protocol Security Testing**: Validates forbidden legacy features are disabled

```rust
// Example: Real-world certificate security validation
let certificates = generate_test_certificates()?;
for (cert_type, cert_der) in certificates {
    match parse_der_certificate(&cert_der) {
        Ok((_, cert)) => {
            let issues = validate_certificate_security(&cert, &cert_type);
            // Real security validation against RFC 8446 requirements
        }
    }
}
```

**Compliance Areas Tested**:
- **Mandatory Cipher Suites**: `TLS_AES_128_GCM_SHA256` (0x1301) - MUST implement
- **Key Exchange Groups**: `secp256r1` (0x0017) - MUST implement, `x25519` (0x001d) - SHOULD implement
- **Signature Schemes**: `rsa_pss_rsae_sha256` (0x0804) - MUST implement
- **AEAD Requirement**: All cipher suites must be AEAD (no CBC, RC4, NULL)
- **Perfect Forward Secrecy**: Ephemeral key exchange validation
- **Forbidden Legacy Features**: Renegotiation, compression, export ciphers disabled

### 3. Certificate Security Validation

**Location**: `test/security-validation/src/certificate_validation.rs`

**Purpose**: Validates certificate handling security using real X.509 certificates.

**Real-World Testing**:
- **Certificate Generation**: Creates actual RSA and ECDSA certificates with different parameters
- **Security Validation**: Tests key sizes, signature algorithms, validity periods
- **Negative Testing**: Validates rejection of weak, expired, or malformed certificates
- **Chain Validation**: Tests certificate chain validation and trust establishment

## 🔒 Private Security Research (Gitignored)

**⚠️ WARNING**: The `/test/private/` directory contains vulnerability research tools and should NEVER be committed to public repositories.

### Purpose

- **Advanced Fuzzing**: Tools designed to find crashes and memory corruption
- **Exploit Development**: Proof-of-concept exploit code and attack utilities
- **Vulnerability Research**: Private security research findings and methodologies
- **Attack Simulation**: Tools for simulating real-world attacks

### Access Control

- **Private Repositories Only**: Use separate private repos for vulnerability research
- **Security Team Access**: Limit access to authorized security researchers only
- **Responsible Disclosure**: Follow coordinated vulnerability disclosure practices

### Guidelines

See `/test/private/README.md` and `SECURITY-DEVELOPMENT.md` for comprehensive guidelines on:
- Responsible vulnerability research
- Legal and ethical considerations
- Emergency incident response procedures
- Vulnerability disclosure timelines

## 🛠️ Development Workflow

### Prerequisites

```bash
# Install Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install WASI-TLS testing tools
cargo install wit-bindgen-cli@0.38.0  
cargo install wasm-tools@1.224.0
cargo install cargo-component@0.15.0
```

### Running Public Security Validation

#### Host-Side Testing (Full System Access)

```bash
# Run comprehensive host-side integration tests
cd test/host-testing
cargo run --bin host-test-runner -- --level comprehensive --verbose

# Run specific test categories
cargo test integration       # End-to-end network testing
cargo test compliance       # RFC 8446 compliance with real TLS
cargo test security         # Host-side security validation

# Run performance benchmarks
cargo bench host_performance

# Generate comprehensive test report
cargo run --bin host-test-runner -- --output host-test-report.json
```

#### Component Testing (WASM Isolate)

```bash
# Run WASM component tests (no system calls)
cd test/component-testing
cargo test --target wasm32-wasi-preview2

# Run component tests with wasm-bindgen-test
wasm-pack test --node

# Run pure logic validation
cargo run --bin component-test-runner -- --wit-content "$(cat ../../wit/types.wit)"

# Build WASM component for testing
cargo component build --release
```

### Testing Commands by Environment

#### Combined Validation Workflow

```bash
# 1. Validate WIT interface syntax
wit-bindgen validate wit/

# 2. Run WASM component tests (pure logic, no system calls)
cd test/component-testing
cargo test --target wasm32-wasi-preview2
cargo component build --release

# 3. Run host-side comprehensive testing (full system access)
cd ../host-testing  
cargo test --all-features
cargo run --bin host-test-runner -- --comprehensive

# 4. Cross-environment validation
cargo run --bin host-test-runner -- --test-components ../component-testing/target/wasm32-wasi-preview2/release/
```

#### Environment-Specific Commands

**Host Environment** (Development/CI):
```bash
cd test/host-testing

# Integration testing with real network
cargo test integration::test_real_tls_handshake
cargo test integration::test_concurrent_connections

# RFC compliance with rustls comparison
cargo test compliance::test_rfc8446_cipher_suites
cargo test compliance::test_mandatory_extensions

# Security validation with real certificates
cargo test security::test_certificate_chain_validation
cargo test security::test_weak_certificate_rejection

# Load testing and performance
cargo bench host_performance
cargo test load_testing --release
```

**WASM Component Environment** (Isolate):
```bash
cd test/component-testing

# Pure logic WIT validation
cargo test wit_validation::test_tls13_only_constraint
cargo test wit_validation::test_security_first_design

# Component unit tests (no system calls)
cargo test unit_tests::test_component_behavior
cargo test unit_tests::test_pure_functions

# Input validation (safe boundaries)
cargo test input_validation::test_boundary_conditions
cargo test --target wasm32-wasi-preview2 --all-features
```

## 📊 Continuous Security Integration

### GitHub Actions Workflow

The project includes comprehensive security validation in CI/CD with environment separation:

**File**: `.github/workflows/security-validation.yml`

**Features**:
- **Dual Environment Testing**: Both host and WASM component testing
- **Multi-level Security Testing**: Basic, RFC 8446, advanced, and integration levels
- **Security Report Generation**: JSON reports with security posture analysis
- **Critical Failure Detection**: Stops deployment on critical security issues
- **WASM Component Validation**: Tests components in actual WASM isolates
- **Performance Regression Detection**: Benchmarks against baseline performance

```yaml
# Example workflow steps
- name: Run WASM component tests (isolate environment)
  run: |
    cd test/component-testing
    cargo test --target wasm32-wasi-preview2 --all-features
    cargo component build --release

- name: Run host-side integration tests (full system access) 
  run: |
    cd test/host-testing
    cargo test --all-features --release
    cargo run --bin host-test-runner -- \
      --level comprehensive \
      --output host-integration-report.json \
      --test-components ../component-testing/target/wasm32-wasi-preview2/release/

- name: Cross-environment validation
  run: |
    cd test/host-testing
    cargo run --bin host-test-runner -- \
      --validate-wasm-components \
      --component-path ../component-testing/target/wasm32-wasi-preview2/release/
```

## 🔍 Test Data and Fixtures

### Safe Test Certificates

**Location**: `test/fixtures/public/`

All test certificates are:
- **Clearly Marked**: "TEST ONLY - DO NOT USE IN PRODUCTION"
- **Short Validity**: Limited validity periods
- **Publicly Shareable**: Safe to include in public repositories
- **Comprehensive Coverage**: Various key types, validity periods, and security scenarios

```rust
// Example: Generating safe test certificates
let (cert_der, key_der) = CertificateFixtures::generate_test_certificate(
    TestCertificateType::Valid,
    "test.example.com"
)?;
```

### Security Test Categories

1. **Valid Certificates**: RSA-2048/4096, ECDSA-P256/P384
2. **Expired Certificates**: For testing proper rejection
3. **Self-Signed Certificates**: For validation testing
4. **Weak Key Certificates**: For security boundary testing
5. **Malformed Certificates**: For parser robustness testing

## ⚡ Performance and Security

### Security Performance Testing

- **Handshake Performance**: < 100ms completion time
- **Memory Usage**: < 10MB per connection baseline
- **CPU Overhead**: < 5% security validation overhead
- **Certificate Validation**: < 50ms per certificate

### Security Benchmarks

```bash
# Run security performance benchmarks
cd test/security-validation  
cargo bench security_performance

# Memory usage validation
cargo test test_memory_usage_limits

# Performance regression testing
cargo bench --baseline security_baseline
```

## 📚 Documentation and Resources

- **RFC 8446 - TLS 1.3**: [The Transport Layer Security (TLS) Protocol Version 1.3](https://tools.ietf.org/html/rfc8446)
- **WASI Security Model**: [WebAssembly System Interface Security](https://github.com/WebAssembly/WASI/blob/main/docs/WASI-security-model.md)
- **OWASP TLS Guidelines**: [Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)
- **Mozilla Security Guidelines**: [Server Side TLS](https://wiki.mozilla.org/Security/Server_Side_TLS)

### Project Documentation

- **`SECURITY-DEVELOPMENT.md`**: Comprehensive security development guidelines
- **`/test/private/README.md`**: Private vulnerability research guidelines
- **`/test/fixtures/README.md`**: Security guidelines for test data

## 🚨 Security Incident Response

### If You Discover a Vulnerability

1. **DO NOT** commit vulnerability details to public repositories
2. **DO NOT** share exploit code publicly
3. **DO** follow responsible disclosure practices
4. **DO** contact the WASI-TLS security team privately
5. **DO** use the guidelines in `SECURITY-DEVELOPMENT.md`

### Emergency Contacts

For security incidents or vulnerability reports, see the responsible disclosure process in `SECURITY-DEVELOPMENT.md`.

## 🎯 Summary

The WASI-TLS testing framework provides:

✅ **Public Defensive Security Testing** - Safe to share, helps improve security across implementations  
✅ **Real-World Validation** - Uses actual certificates and cryptographic validation (no mocks)  
✅ **RFC 8446 Compliance** - Comprehensive TLS 1.3 standard compliance testing  
✅ **Responsible Research Guidelines** - Clear separation of public/private security tools  
✅ **Continuous Security Integration** - Automated security validation in CI/CD  
✅ **Emergency Response Procedures** - Clear incident response and vulnerability disclosure processes  

**The goal is to improve security for everyone while being responsible about the tools and techniques we develop and share.**

---

**🔑 Remember**: All tests MUST validate against the current `wit/types.wit` interface. The WIT file is the single source of truth for all testing targets.