//! WIT Interface Validation - Security-First Testing
//! 
//! Validates that WIT interface definitions comply with security requirements
//! and prevent common vulnerabilities in TLS implementations.

use crate::{SecurityTestResult, SecurityLevel, VulnerabilityRisk};
use anyhow::Result;
use std::fs;
use std::path::Path;

/// Run all WIT validation tests
pub fn run_all_tests() -> Result<Vec<SecurityTestResult>> {
    let mut results = Vec::new();
    
    // Test WIT file syntax and structure
    results.push(test_wit_syntax_valid()?);
    
    // Test security constraints
    results.extend(test_security_constraints()?);
    
    // Test interface completeness
    results.extend(test_interface_completeness()?);
    
    // Test error handling coverage
    results.push(test_error_coverage()?);
    
    Ok(results)
}

/// Validate WIT file syntax using wit-bindgen
fn test_wit_syntax_valid() -> Result<SecurityTestResult> {
    let wit_dir = find_wit_directory()?;
    
    // Use wit-bindgen to validate syntax
    let output = std::process::Command::new("wit-bindgen")
        .arg("validate")
        .arg(&wit_dir)
        .output();
    
    match output {
        Ok(output) if output.status.success() => {
            Ok(SecurityTestResult::new_passed(
                "WIT syntax validation", 
                SecurityLevel::Basic
            ))
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Ok(SecurityTestResult::new_failed(
                "WIT syntax validation",
                SecurityLevel::Basic,
                VulnerabilityRisk::High,
                &format!("WIT syntax errors: {}", stderr)
            ))
        }
        Err(e) => {
            Ok(SecurityTestResult::new_failed(
                "WIT syntax validation",
                SecurityLevel::Basic,
                VulnerabilityRisk::Medium,
                &format!("Could not run wit-bindgen: {}", e)
            ))
        }
    }
}

/// Test critical security constraints in the WIT interface
fn test_security_constraints() -> Result<Vec<SecurityTestResult>> {
    let mut results = Vec::new();
    let wit_content = read_types_wit()?;
    
    // Test 1: Ensure TLS 1.3 only
    results.push(test_tls13_only(&wit_content)?);
    
    // Test 2: Ensure no 0-RTT support
    results.push(test_no_zero_rtt(&wit_content)?);
    
    // Test 3: Ensure no session resumption
    results.push(test_no_session_resumption(&wit_content)?);
    
    // Test 4: Validate mandatory cipher suites
    results.push(test_mandatory_cipher_suites(&wit_content)?);
    
    // Test 5: Validate certificate validation is required
    results.push(test_certificate_validation_required(&wit_content)?);
    
    Ok(results)
}

fn test_tls13_only(wit_content: &str) -> Result<SecurityTestResult> {
    // Must specify TLS 1.3 (0x0304)
    let has_tls13 = wit_content.contains("0x0304") || 
                    wit_content.contains("TLS 1.3") ||
                    wit_content.contains("TLS_1_3");
    
    // Must NOT specify TLS 1.2 or earlier
    let has_older_tls = wit_content.contains("0x0303") ||  // TLS 1.2
                        wit_content.contains("0x0302") ||  // TLS 1.1
                        wit_content.contains("0x0301") ||  // TLS 1.0
                        wit_content.contains("TLS 1.2") ||
                        wit_content.contains("TLS 1.1") ||
                        wit_content.contains("TLS 1.0");
    
    if has_tls13 && !has_older_tls {
        Ok(SecurityTestResult::new_passed(
            "TLS 1.3 only constraint",
            SecurityLevel::Rfc8446
        ))
    } else {
        Ok(SecurityTestResult::new_failed(
            "TLS 1.3 only constraint",
            SecurityLevel::Rfc8446,
            VulnerabilityRisk::Critical,
            "Interface allows non-TLS 1.3 protocols, enabling downgrade attacks"
        ))
    }
}

fn test_no_zero_rtt(wit_content: &str) -> Result<SecurityTestResult> {
    // Check for 0-RTT related terms that should NOT be present
    let zero_rtt_indicators = [
        "0-rtt", "0rtt", "early-data", "early_data",
        "early-data-size", "max-early-data"
    ];
    
    let has_zero_rtt = zero_rtt_indicators.iter()
        .any(|term| wit_content.to_lowercase().contains(term));
    
    if !has_zero_rtt {
        Ok(SecurityTestResult::new_passed(
            "No 0-RTT support",
            SecurityLevel::Advanced
        ))
    } else {
        Ok(SecurityTestResult::new_failed(
            "No 0-RTT support",
            SecurityLevel::Advanced,
            VulnerabilityRisk::Critical,
            "0-RTT support detected - creates replay attack vulnerability"
        ))
    }
}

fn test_no_session_resumption(wit_content: &str) -> Result<SecurityTestResult> {
    // Check for session resumption terms that should NOT be present
    let resumption_indicators = [
        "session-ticket", "session_ticket", "resume",
        "session-id", "session_id", "psk", "pre-shared"
    ];
    
    let has_resumption = resumption_indicators.iter()
        .any(|term| wit_content.to_lowercase().contains(term));
    
    if !has_resumption {
        Ok(SecurityTestResult::new_passed(
            "No session resumption",
            SecurityLevel::Advanced
        ))
    } else {
        Ok(SecurityTestResult::new_failed(
            "No session resumption",
            SecurityLevel::Advanced,
            VulnerabilityRisk::High,
            "Session resumption support detected - weakens forward secrecy"
        ))
    }
}

fn test_mandatory_cipher_suites(wit_content: &str) -> Result<SecurityTestResult> {
    // Must document mandatory TLS 1.3 cipher suite
    let has_aes128_gcm = wit_content.contains("TLS_AES_128_GCM_SHA256") ||
                         wit_content.contains("0x1301");
    
    let has_must_implement = wit_content.contains("MUST implement") ||
                             wit_content.contains("mandatory");
    
    if has_aes128_gcm && has_must_implement {
        Ok(SecurityTestResult::new_passed(
            "Mandatory cipher suites documented",
            SecurityLevel::Rfc8446
        ))
    } else {
        Ok(SecurityTestResult::new_failed(
            "Mandatory cipher suites documented",
            SecurityLevel::Rfc8446,
            VulnerabilityRisk::Medium,
            "Mandatory TLS 1.3 cipher suite AES_128_GCM not properly documented"
        ))
    }
}

fn test_certificate_validation_required(wit_content: &str) -> Result<SecurityTestResult> {
    // Must have certificate validation functions
    let has_verify_hostname = wit_content.contains("verify-hostname") ||
                              wit_content.contains("verify_hostname");
    
    let has_certificate_methods = wit_content.contains("certificate-invalid") ||
                                  wit_content.contains("certificate-expired") ||
                                  wit_content.contains("certificate-untrusted");
    
    if has_verify_hostname && has_certificate_methods {
        Ok(SecurityTestResult::new_passed(
            "Certificate validation required",
            SecurityLevel::Rfc8446
        ))
    } else {
        Ok(SecurityTestResult::new_failed(
            "Certificate validation required",
            SecurityLevel::Rfc8446,
            VulnerabilityRisk::Critical,
            "Certificate validation not properly required in interface"
        ))
    }
}

/// Test interface completeness for security-critical operations
fn test_interface_completeness() -> Result<Vec<SecurityTestResult>> {
    let mut results = Vec::new();
    let wit_content = read_types_wit()?;
    
    // Test that all required resources are present
    results.push(test_required_resources(&wit_content)?);
    
    // Test that all required error types are present
    results.push(test_required_error_types(&wit_content)?);
    
    Ok(results)
}

fn test_required_resources(wit_content: &str) -> Result<SecurityTestResult> {
    let required_resources = [
        "client-handshake",
        "client-connection", 
        "certificate",
        "private-identity"
    ];
    
    let missing_resources: Vec<_> = required_resources.iter()
        .filter(|&resource| !wit_content.contains(resource))
        .collect();
    
    if missing_resources.is_empty() {
        Ok(SecurityTestResult::new_passed(
            "Required resources present",
            SecurityLevel::Basic
        ))
    } else {
        Ok(SecurityTestResult::new_failed(
            "Required resources present",
            SecurityLevel::Basic,
            VulnerabilityRisk::High,
            &format!("Missing required resources: {:?}", missing_resources)
        ))
    }
}

fn test_required_error_types(wit_content: &str) -> Result<SecurityTestResult> {
    let required_errors = [
        "certificate-invalid",
        "certificate-expired",
        "certificate-untrusted",
        "handshake-failure",
        "protocol-violation"
    ];
    
    let missing_errors: Vec<_> = required_errors.iter()
        .filter(|&error| !wit_content.contains(error))
        .collect();
    
    if missing_errors.is_empty() {
        Ok(SecurityTestResult::new_passed(
            "Required error types present",
            SecurityLevel::Basic
        ))
    } else {
        Ok(SecurityTestResult::new_failed(
            "Required error types present",
            SecurityLevel::Basic,
            VulnerabilityRisk::Medium,
            &format!("Missing required error types: {:?}", missing_errors)
        ))
    }
}

fn test_error_coverage() -> Result<SecurityTestResult> {
    let wit_content = read_types_wit()?;
    
    // Count defined error cases
    let error_count = wit_content.matches("enum error-code").count() +
                      wit_content.matches("error-").count();
    
    // Should have comprehensive error coverage (at least 10 error types)
    if error_count >= 10 {
        Ok(SecurityTestResult::new_passed(
            "Comprehensive error coverage",
            SecurityLevel::Basic
        ))
    } else {
        Ok(SecurityTestResult::new_failed(
            "Comprehensive error coverage",
            SecurityLevel::Basic,
            VulnerabilityRisk::Medium,
            &format!("Insufficient error coverage: only {} error types found", error_count)
        ))
    }
}

/// Helper functions

fn find_wit_directory() -> Result<std::path::PathBuf> {
    let current_dir = std::env::current_dir()?;
    
    // Look for wit directory in project root
    for ancestor in current_dir.ancestors() {
        let wit_path = ancestor.join("wit");
        if wit_path.exists() && wit_path.is_dir() {
            return Ok(wit_path);
        }
    }
    
    Err(anyhow::anyhow!("Could not find wit directory"))
}

fn read_types_wit() -> Result<String> {
    let wit_dir = find_wit_directory()?;
    let types_wit_path = wit_dir.join("types.wit");
    
    if !types_wit_path.exists() {
        return Err(anyhow::anyhow!("types.wit file not found"));
    }
    
    Ok(fs::read_to_string(types_wit_path)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_wit_validation_suite() {
        let results = run_all_tests().expect("WIT validation tests should run");
        
        // Ensure we have comprehensive test coverage
        assert!(!results.is_empty(), "Should have WIT validation tests");
        
        // Check for critical failures
        let critical_failures: Vec<_> = results.iter()
            .filter(|r| !r.passed && r.vulnerability_risk == VulnerabilityRisk::Critical)
            .collect();
        
        if !critical_failures.is_empty() {
            panic!("Critical WIT validation failures: {:?}", critical_failures);
        }
    }
}