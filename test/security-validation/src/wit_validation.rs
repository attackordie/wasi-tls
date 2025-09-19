//! WIT Interface Security Validation
//! 
//! Validates that WIT interface definitions enforce security-first design
//! principles and prevent common TLS vulnerabilities through interface design.

use crate::{ValidationResult, ValidationLevel, RiskLevel};
use anyhow::Result;
use std::fs;
use std::path::Path;

/// Validate WIT interface security constraints
pub fn validate_security_constraints() -> Result<Vec<ValidationResult>> {
    let mut results = Vec::new();
    
    // Find and read WIT types file
    let wit_content = read_wit_types_file()?;
    
    // Validate security-first design principles
    results.push(validate_tls13_only_constraint(&wit_content)?);
    results.push(validate_no_zero_rtt(&wit_content)?);
    results.push(validate_no_session_resumption(&wit_content)?);
    results.push(validate_mandatory_certificate_validation(&wit_content)?);
    results.push(validate_error_handling_coverage(&wit_content)?);
    results.push(validate_secure_defaults(&wit_content)?);
    
    Ok(results)
}

fn validate_tls13_only_constraint(wit_content: &str) -> Result<ValidationResult> {
    // Validate that interface only supports TLS 1.3
    let has_tls13 = wit_content.contains("0x0304") || 
                    wit_content.contains("TLS 1.3");
    
    let has_older_tls = wit_content.contains("0x0303") ||  // TLS 1.2
                        wit_content.contains("0x0302") ||  // TLS 1.1  
                        wit_content.contains("TLS 1.2") ||
                        wit_content.contains("TLS 1.1");
    
    if has_tls13 && !has_older_tls {
        Ok(ValidationResult::new_passed(
            "TLS 1.3 Only Constraint",
            ValidationLevel::Basic,
            "Interface correctly enforces TLS 1.3 only, preventing downgrade attacks"
        ))
    } else {
        Ok(ValidationResult::new_failed(
            "TLS 1.3 Only Constraint",
            ValidationLevel::Basic,
            RiskLevel::Critical,
            "Interface allows non-TLS 1.3 protocols, enabling downgrade attacks"
        ))
    }
}

fn validate_no_zero_rtt(wit_content: &str) -> Result<ValidationResult> {
    // Validate that 0-RTT is not supported (prevents replay attacks)
    let zero_rtt_indicators = [
        "0-rtt", "0rtt", "early-data", "early_data",
        "max-early-data", "early-data-size"
    ];
    
    let has_zero_rtt = zero_rtt_indicators.iter()
        .any(|&indicator| wit_content.to_lowercase().contains(indicator));
    
    if !has_zero_rtt {
        Ok(ValidationResult::new_passed(
            "No 0-RTT Support",
            ValidationLevel::Advanced,
            "Interface correctly prohibits 0-RTT data, preventing replay attacks"
        ))
    } else {
        Ok(ValidationResult::new_failed(
            "No 0-RTT Support", 
            ValidationLevel::Advanced,
            RiskLevel::Critical,
            "Interface supports 0-RTT data, which enables replay attacks (RFC 8446 Section 8)"
        ))
    }
}

fn validate_no_session_resumption(wit_content: &str) -> Result<ValidationResult> {
    // Validate that session resumption is not supported (maintains forward secrecy)
    let resumption_indicators = [
        "session-ticket", "session_ticket", "resume",
        "session-id", "session_id", "psk", "pre-shared"
    ];
    
    let has_resumption = resumption_indicators.iter()
        .any(|&indicator| wit_content.to_lowercase().contains(indicator));
    
    if !has_resumption {
        Ok(ValidationResult::new_passed(
            "No Session Resumption",
            ValidationLevel::Advanced, 
            "Interface correctly prohibits session resumption, maintaining forward secrecy"
        ))
    } else {
        Ok(ValidationResult::new_failed(
            "No Session Resumption",
            ValidationLevel::Advanced,
            RiskLevel::High,
            "Interface supports session resumption, which weakens forward secrecy"
        ))
    }
}

fn validate_mandatory_certificate_validation(wit_content: &str) -> Result<ValidationResult> {
    // Validate that certificate validation is mandatory and comprehensive
    let has_hostname_verify = wit_content.contains("verify-hostname") ||
                              wit_content.contains("verify_hostname");
    
    let has_cert_errors = ["certificate-invalid", "certificate-expired", "certificate-untrusted"]
        .iter()
        .all(|&error| wit_content.contains(error));
    
    if has_hostname_verify && has_cert_errors {
        Ok(ValidationResult::new_passed(
            "Mandatory Certificate Validation",
            ValidationLevel::Rfc8446,
            "Interface enforces comprehensive certificate validation including hostname verification"
        ))
    } else {
        Ok(ValidationResult::new_failed(
            "Mandatory Certificate Validation",
            ValidationLevel::Rfc8446,
            RiskLevel::Critical,
            "Interface does not enforce comprehensive certificate validation"
        ))
    }
}

fn validate_error_handling_coverage(wit_content: &str) -> Result<ValidationResult> {
    // Validate that error handling covers all security-relevant scenarios
    let required_errors = [
        "connection-refused",
        "connection-reset", 
        "protocol-violation",
        "handshake-failure",
        "certificate-invalid",
        "certificate-expired",
        "certificate-untrusted",
        "unsupported-protocol-version"
    ];
    
    let missing_errors: Vec<_> = required_errors.iter()
        .filter(|&&error| !wit_content.contains(error))
        .collect();
    
    if missing_errors.is_empty() {
        Ok(ValidationResult::new_passed(
            "Comprehensive Error Handling",
            ValidationLevel::Basic,
            "Interface provides comprehensive error handling for all security scenarios"
        ))
    } else {
        Ok(ValidationResult::new_failed(
            "Comprehensive Error Handling",
            ValidationLevel::Basic,
            RiskLevel::Medium,
            &format!("Interface missing error types: {:?}", missing_errors)
        ))
    }
}

fn validate_secure_defaults(wit_content: &str) -> Result<ValidationResult> {
    // Validate that interface design enforces secure defaults
    let has_secure_design_comments = wit_content.contains("security-first") ||
                                     wit_content.contains("Security-First") ||
                                     wit_content.contains("secure defaults") ||
                                     wit_content.contains("minimal API surface");
    
    let has_security_documentation = wit_content.contains("RFC 8446") ||
                                     wit_content.contains("prevent") ||
                                     wit_content.contains("security");
    
    if has_secure_design_comments && has_security_documentation {
        Ok(ValidationResult::new_passed(
            "Secure Defaults Design",
            ValidationLevel::Advanced,
            "Interface design explicitly emphasizes security-first principles"
        ))
    } else {
        Ok(ValidationResult::new_failed(
            "Secure Defaults Design",
            ValidationLevel::Advanced,
            RiskLevel::Low,
            "Interface design lacks explicit security-first design documentation"
        ))
    }
}

fn read_wit_types_file() -> Result<String> {
    // Look for wit/types.wit in project root
    let current_dir = std::env::current_dir()?;
    
    // Try different possible locations
    let possible_paths = [
        current_dir.join("wit/types.wit"),
        current_dir.join("../../../wit/types.wit"), // From test directory
        current_dir.join("../../wit/types.wit"),    // Alternative path
    ];
    
    for path in &possible_paths {
        if path.exists() {
            return Ok(fs::read_to_string(path)?);
        }
    }
    
    Err(anyhow::anyhow!("Could not find wit/types.wit file in any expected location"))
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test] 
    async fn test_wit_security_validation() {
        let results = validate_security_constraints()
            .expect("WIT validation should complete");
        
        // Should have comprehensive validation coverage
        assert!(!results.is_empty(), "Should have WIT validation results");
        
        // Critical failures should cause test failure
        let critical_failures: Vec<_> = results.iter()
            .filter(|r| !r.passed && r.risk_level == RiskLevel::Critical)
            .collect();
        
        if !critical_failures.is_empty() {
            panic!("Critical WIT security failures: {:?}", critical_failures);
        }
    }
}