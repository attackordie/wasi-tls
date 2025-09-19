//! WASI-TLS Public Security Validation
//! 
//! This crate provides PUBLIC security validation tools for WASI-TLS.
//! It focuses exclusively on DEFENSIVE security testing - validating that
//! the implementation correctly rejects malicious inputs and maintains
//! security guarantees.
//! 
//! ⚠️  IMPORTANT: This crate does NOT contain:
//! - Vulnerability exploitation tools
//! - Attack payload generators  
//! - Fuzzing harnesses that could be misused
//! - Private security research tools
//!
//! For vulnerability research, use private repositories with proper
//! access controls and responsible disclosure processes.

use anyhow::Result;
use std::fmt;

/// Public security validation levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationLevel {
    /// Basic security constraint validation
    Basic,
    /// RFC 8446 TLS 1.3 compliance validation
    Rfc8446,
    /// Advanced security feature validation
    Advanced,
}

/// Validation result for security requirements
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub test_name: String,
    pub passed: bool,
    pub level: ValidationLevel,
    pub risk_level: RiskLevel,
    pub description: String,
    pub recommendations: Vec<String>,
}

/// Risk assessment levels for validation failures
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RiskLevel {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RiskLevel::Info => write!(f, "INFO"),
            RiskLevel::Low => write!(f, "LOW"),
            RiskLevel::Medium => write!(f, "MEDIUM"), 
            RiskLevel::High => write!(f, "HIGH"),
            RiskLevel::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl ValidationResult {
    pub fn new_passed(name: &str, level: ValidationLevel, description: &str) -> Self {
        Self {
            test_name: name.to_string(),
            passed: true,
            level,
            risk_level: RiskLevel::Info,
            description: description.to_string(),
            recommendations: Vec::new(),
        }
    }
    
    pub fn new_failed(name: &str, level: ValidationLevel, risk: RiskLevel, description: &str) -> Self {
        let recommendations = Self::generate_recommendations(&risk, name);
        
        Self {
            test_name: name.to_string(),
            passed: false,
            level,
            risk_level: risk,
            description: description.to_string(),
            recommendations,
        }
    }
    
    fn generate_recommendations(risk: &RiskLevel, test_name: &str) -> Vec<String> {
        let mut recs = Vec::new();
        
        match risk {
            RiskLevel::Critical => {
                recs.push("URGENT: Stop deployment immediately".to_string());
                recs.push("Conduct security code review".to_string());
                recs.push("Implement additional input validation".to_string());
            }
            RiskLevel::High => {
                recs.push("Address before next release".to_string());
                recs.push("Review security implementation".to_string());
            }
            RiskLevel::Medium => {
                recs.push("Consider addressing in upcoming release".to_string());
            }
            _ => {}
        }
        
        if test_name.contains("certificate") {
            recs.push("Review certificate validation logic".to_string());
        }
        if test_name.contains("protocol") {
            recs.push("Verify TLS 1.3 RFC 8446 compliance".to_string());
        }
        
        recs
    }
}

/// Main security validation suite  
pub struct SecurityValidator {
    pub results: Vec<ValidationResult>,
    pub level: ValidationLevel,
}

impl SecurityValidator {
    pub fn new(level: ValidationLevel) -> Self {
        Self {
            results: Vec::new(),
            level,
        }
    }
    
    /// Run all security validation tests
    pub fn validate_all(&mut self) -> Result<()> {
        tracing::info!("Starting WASI-TLS security validation at level: {:?}", self.level);
        
        // Run different validation categories
        self.validate_wit_interface()?;
        self.validate_tls_compliance()?;
        self.validate_certificate_handling()?;
        
        if matches!(self.level, ValidationLevel::Advanced) {
            self.validate_advanced_security()?;
        }
        
        Ok(())
    }
    
    /// Validate WIT interface security constraints
    fn validate_wit_interface(&mut self) -> Result<()> {
        tracing::info!("Validating WIT interface security constraints");
        
        // These tests validate that the interface PREVENTS vulnerabilities
        self.results.extend(crate::wit_validation::validate_security_constraints()?);
        
        Ok(())
    }
    
    /// Validate TLS 1.3 compliance
    fn validate_tls_compliance(&mut self) -> Result<()> {
        tracing::info!("Validating TLS 1.3 RFC 8446 compliance");
        
        self.results.extend(crate::tls_compliance::validate_rfc8446_compliance()?);
        
        Ok(())
    }
    
    /// Validate certificate handling security
    fn validate_certificate_handling(&mut self) -> Result<()> {
        tracing::info!("Validating certificate handling security");
        
        self.results.extend(crate::certificate_validation::validate_certificate_security()?);
        
        Ok(())
    }
    
    /// Validate advanced security features
    fn validate_advanced_security(&mut self) -> Result<()> {
        tracing::info!("Validating advanced security features");
        
        self.results.extend(crate::advanced_security::validate_advanced_features()?);
        
        Ok(())
    }
    
    /// Check if there are any critical security failures
    pub fn has_critical_failures(&self) -> bool {
        self.results.iter().any(|r| 
            !r.passed && r.risk_level == RiskLevel::Critical
        )
    }
    
    /// Get summary of validation results
    pub fn get_summary(&self) -> ValidationSummary {
        let total = self.results.len();
        let passed = self.results.iter().filter(|r| r.passed).count();
        let failed = total - passed;
        
        let critical = self.results.iter()
            .filter(|r| !r.passed && r.risk_level == RiskLevel::Critical)
            .count();
        let high = self.results.iter()
            .filter(|r| !r.passed && r.risk_level == RiskLevel::High)
            .count();
        
        let status = if critical > 0 {
            "CRITICAL_ISSUES"
        } else if high > 0 {
            "HIGH_RISK_ISSUES"
        } else if failed > 0 {
            "MINOR_ISSUES"
        } else {
            "SECURE"
        };
        
        ValidationSummary {
            total_tests: total,
            passed_tests: passed,
            failed_tests: failed,
            critical_failures: critical,
            high_risk_failures: high,
            overall_status: status.to_string(),
            pass_rate: (passed as f64 / total as f64 * 100.0),
        }
    }
}

/// Summary of validation results
#[derive(Debug, Clone, serde::Serialize)]
pub struct ValidationSummary {
    pub total_tests: usize,
    pub passed_tests: usize, 
    pub failed_tests: usize,
    pub critical_failures: usize,
    pub high_risk_failures: usize,
    pub overall_status: String,
    pub pass_rate: f64,
}

// Public validation modules
pub mod wit_validation;
pub mod tls_compliance; 
pub mod certificate_validation;
pub mod advanced_security;