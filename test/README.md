# Testing Guidelines for WASI-TLS

## Overview

This document outlines the comprehensive testing strategy for the WASI-TLS proposal, ensuring that **WIT files are the single source of truth** for all testing targets. All tests must originate from and validate against the latest WIT interface definitions in `wit/types.wit`.

## Testing Architecture

### WIT-Driven Testing Principles

1. **Single Source of Truth**: All test targets MUST be generated from `wit/types.wit`
2. **Version Validation**: Tests MUST verify they're using current WIT definitions (not stale targets)
3. **Interface Compliance**: All implementations MUST satisfy the complete WIT interface contract
4. **Security-First**: All tests MUST validate TLS 1.3-only security constraints

### Test Hierarchy

```
test/
├── README.md              # This file
├── wit-validation/        # WIT consistency and generation tests
├── unit/                  # Component unit tests
├── integration/          # Full end-to-end integration tests
├── implementations/      # Per-language implementation tests
│   ├── rust/             # Rust/WASM testing
│   ├── go/               # Go implementation tests (future)
│   ├── c/                # C implementation tests (future)
│   └── js/               # JavaScript implementation tests (future)
├── security/             # TLS 1.3 security compliance tests
├── fixtures/             # Test certificates, keys, and data
└── tools/                # Testing utilities and scripts
```

## Core Testing Requirements

### 1. WIT Interface Validation

**Location**: `test/wit-validation/`

- **WIT Consistency**: Verify all WIT files are syntactically correct
- **Dependency Integrity**: Validate WASI I/O dependencies are correct versions
- **Target Freshness**: Ensure generated bindings match current WIT definitions
- **ABI Compatibility**: Validate ABI stability across WIT changes

**Tools Required**:
- `wit-bindgen` (exact version specified in CI)
- `wasm-tools` 
- Custom freshness validation scripts

### 2. TLS 1.3 Protocol Compliance

**Location**: `test/security/`

All tests MUST validate the security-first design principles:

#### Mandatory Protocol Requirements
- **TLS 1.3 Only**: Protocol version 0x0304 exclusively
- **Cipher Suites**: Support for mandatory RFC 8446 suites
  - `TLS_AES_128_GCM_SHA256` (0x1301) - MUST implement
  - `TLS_AES_256_GCM_SHA384` (0x1302) - SHOULD implement  
  - `TLS_CHACHA20_POLY1305_SHA256` (0x1303) - SHOULD implement
- **Named Groups**: Key exchange validation
  - `secp256r1` (0x0017) - MUST implement
  - `x25519` (0x001d) - SHOULD implement
- **Signature Schemes**: Certificate signature validation
  - `rsa_pss_rsae_sha256` (0x0804) - MUST implement

#### Security Constraint Validation
- **NO TLS 1.2**: Reject any TLS 1.2 handshake attempts
- **NO 0-RTT**: Verify 0-RTT data is never accepted
- **NO Session Resumption**: Verify no session tickets are used
- **Certificate Validation**: Hostname verification, expiration, trust chain

### 3. Rust/WASM Integration Tests

**Location**: `test/implementations/rust/`

#### Test Structure
```
rust/
├── Cargo.toml           # Test workspace configuration
├── src/
│   ├── lib.rs          # Common test utilities
│   ├── wit_bindings/   # Generated from wit/types.wit (auto-generated)
│   └── fixtures/       # Test certificates and keys
├── tests/
│   ├── client_tests.rs # Client handshake and connection tests
│   ├── server_tests.rs # Server acceptance and connection tests
│   ├── certificate_tests.rs # Certificate resource tests
│   ├── error_tests.rs  # Error handling validation
│   └── security_tests.rs # TLS 1.3 security compliance
└── examples/
    ├── simple_client.rs
    ├── simple_server.rs
    └── mutual_tls.rs
```

#### Client Resource Tests (`client_tests.rs`)

Test all client resource methods from `wit/types.wit`:

```rust
// Test matrix for client::new() - lines 135-142
#[test] fn test_client_new_valid_hostname()
#[test] fn test_client_new_invalid_streams() 
#[test] fn test_client_new_connection_refused()

// Test client::set-alpn-protocols() - lines 147
#[test] fn test_set_alpn_single_protocol()
#[test] fn test_set_alpn_multiple_protocols()
#[test] fn test_set_alpn_empty_list()

// Test client::set-identity() - lines 150
#[test] fn test_set_client_identity_valid()
#[test] fn test_set_client_identity_invalid()

// Test client::finish() - lines 155
#[test] fn test_client_finish_successful_handshake()
#[test] fn test_client_finish_handshake_failure()
#[test] fn test_client_finish_certificate_invalid()

// Test client::subscribe() - lines 158
#[test] fn test_client_subscribe_pollable()
```

#### Server Resource Tests (`server_tests.rs`)

Test all server resource methods from `wit/types.wit`:

```rust  
// Test matrix for server::new() - lines 180-185
#[test] fn test_server_new_valid_streams()
#[test] fn test_server_new_invalid_streams()

// Test server::set-identity() - lines 189
#[test] fn test_server_set_identity_required()
#[test] fn test_server_set_identity_invalid_cert()

// Test server::set-alpn-protocols() - lines 193
#[test] fn test_server_set_alpn_protocols()

// Test server::set-client-auth-required() - lines 197
#[test] fn test_server_require_client_auth()
#[test] fn test_server_optional_client_auth()

// Test server::finish() - lines 202
#[test] fn test_server_finish_successful_handshake()
#[test] fn test_server_finish_no_identity_error()
```

#### Connection Resource Tests (`connection_tests.rs`)

Test all connection methods from `wit/types.wit:104-126`:

```rust
// Test connection inspection methods
#[test] fn test_connection_protocol_version() // line 108
#[test] fn test_connection_cipher_suite()     // line 112  
#[test] fn test_connection_peer_certificate() // line 116
#[test] fn test_connection_alpn_protocol()    // line 120
#[test] fn test_connection_close()            // line 124
```

#### Certificate Resource Tests (`certificate_tests.rs`)

Test certificate resource methods from `wit/types.wit:78-94`:

```rust
#[test] fn test_certificate_subject()         // line 81
#[test] fn test_certificate_issuer()          // line 84
#[test] fn test_certificate_verify_hostname() // line 88
#[test] fn test_certificate_export_der()      // line 92
```

#### Error Handling Tests (`error_tests.rs`)

Test all error-code variants from `wit/types.wit:53-74`:

```rust
// Connection errors
#[test] fn test_connection_refused_error()
#[test] fn test_connection_reset_error()
#[test] fn test_connection_timeout_error()

// TLS protocol errors  
#[test] fn test_protocol_violation_error()
#[test] fn test_handshake_failure_error()
#[test] fn test_certificate_invalid_error()
#[test] fn test_certificate_expired_error()
#[test] fn test_certificate_untrusted_error()

// Configuration errors
#[test] fn test_unsupported_protocol_version_error()
#[test] fn test_no_common_cipher_suite_error()
#[test] fn test_no_common_signature_algorithm_error()

// Operational errors
#[test] fn test_would_block_error()
#[test] fn test_internal_error()
```

#### Security Compliance Tests (`security_tests.rs`)

Critical security validation tests:

```rust
// TLS 1.3 only validation
#[test] fn test_tls12_rejected()
#[test] fn test_tls11_rejected()  
#[test] fn test_only_tls13_accepted()

// Cipher suite compliance
#[test] fn test_mandatory_cipher_aes128_gcm()
#[test] fn test_recommended_cipher_aes256_gcm()
#[test] fn test_recommended_cipher_chacha20()
#[test] fn test_weak_ciphers_rejected()

// Key exchange validation
#[test] fn test_secp256r1_supported()
#[test] fn test_x25519_supported()
#[test] fn test_weak_groups_rejected()

// Certificate validation
#[test] fn test_hostname_verification()
#[test] fn test_certificate_expiration()
#[test] fn test_certificate_chain_validation()
#[test] fn test_self_signed_rejected()
```

### 4. WASM Target Testing

#### WASM Build Validation
- **Component Model**: Validate WASM components correctly implement WIT interfaces
- **Host Integration**: Test WASM targets correctly call host TLS implementations
- **Stream Integration**: Verify WASI I/O stream integration works correctly
- **Memory Safety**: Validate no memory corruption in WASM/host boundary

#### WASM Runtime Testing
```bash
# Build WASM component from Rust
cargo component build --release

# Validate component exports match WIT
wasm-tools component wit target/wasm32-wasi/release/wasi_tls_test.wasm

# Test component in WASI runtime
wasmtime serve --wasi=preview2 target/wasm32-wasi/release/wasi_tls_test.wasm
```

## Installing the Tools

### Required Tools

```bash
# Core WASM/WIT toolchain
cargo install cargo-component@0.15.0
cargo install wit-bindgen-cli@0.38.0  
cargo install wasm-tools@1.224.0

# WASI runtime for testing
curl https://wasmtime.dev/install.sh -sSf | bash

# TLS testing utilities  
cargo install rustls-pemfile  # For certificate parsing
cargo install rcgen          # For test certificate generation
```

### Development Dependencies

```toml
# test/implementations/rust/Cargo.toml
[dependencies]
wit-bindgen = "0.38.0"
wasi = "0.13.0"
anyhow = "1.0"

[dev-dependencies]
tokio-test = "0.4"
rcgen = "0.12"      # Test certificate generation
rustls-pemfile = "1.0" # PEM parsing for tests
tempfile = "3.0"    # Temporary files for testing
```

## Running the Tests

### WIT Validation
```bash
# Validate WIT syntax and dependencies
wit-bindgen validate wit/

# Check generated bindings are current
./test/tools/check-bindings-fresh.sh
```

### Rust/WASM Integration Tests
```bash
# Run all Rust implementation tests
cd test/implementations/rust
cargo test

# Run specific test suites
cargo test client_tests
cargo test server_tests  
cargo test security_tests

# Build and test WASM components
cargo component build --release
cargo test --target wasm32-wasi
```

### Security Compliance Tests
```bash
# Run TLS 1.3 compliance test suite
cargo test --package security_tests

# Validate mandatory cipher suites
cargo test test_mandatory_cipher_aes128_gcm

# Test certificate validation
cargo test certificate_tests
```

### Full Integration Testing
```bash
# Complete test suite (WIT + Rust + WASM + Security)
./test/run-all-tests.sh

# CI validation pipeline
./test/ci-validate.sh
```

### Continuous Integration

#### GitHub Actions Integration
```yaml
# .github/workflows/test.yml additions needed
- name: Test Rust/WASM Implementation  
  run: |
    cd test/implementations/rust
    cargo test --verbose
    cargo component build --release
    cargo test --target wasm32-wasi

- name: Validate WIT Freshness
  run: ./test/tools/check-bindings-fresh.sh

- name: Security Compliance Tests
  run: cargo test --package security_tests
```

## Test Data Management

### Certificate Fixtures
**Location**: `test/fixtures/`
- Valid TLS 1.3 certificates (multiple validity periods)
- Expired certificates (for error testing)
- Self-signed certificates (for rejection testing)  
- Certificate chains (root, intermediate, leaf)
- Client certificates (for mutual TLS testing)

### Test Key Material
- RSA keys (various sizes)
- ECDSA keys (P-256, P-384)
- Invalid/corrupted keys (for error testing)
- **SECURITY**: All test keys MUST be clearly marked as test-only

## Quality Assurance

### Test Coverage Requirements
- **100% WIT Interface Coverage**: Every function, resource, and record must be tested
- **Error Path Coverage**: All error-code variants must have corresponding test cases  
- **Security Edge Cases**: All security constraints must have negative tests
- **Platform Coverage**: Tests must pass on Linux, macOS, and Windows WASI runtimes

### Performance Baselines
- Handshake completion time benchmarks
- Stream throughput measurements  
- Memory usage validation
- WASM component size limits

## Contributing Test Cases

### Adding New Test Cases
1. Identify the WIT interface element being tested
2. Reference the exact line numbers in `wit/types.wit`
3. Create both positive and negative test cases
4. Validate test works with WASM target
5. Update this README with test descriptions

### Test Naming Convention
```rust
// Format: test_{resource}_{method}_{scenario}
#[test] fn test_client_new_valid_hostname()
#[test] fn test_client_finish_certificate_expired()  
#[test] fn test_connection_cipher_suite_aes128()
```

---

**CRITICAL**: All tests MUST validate against the current `wit/types.wit` interface. Any test using outdated or cached bindings will be rejected in CI. The WIT file is the authoritative specification - tests must follow its exact contract.