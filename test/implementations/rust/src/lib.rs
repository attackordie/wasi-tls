//! WASI-TLS Public Security Testing Framework
//! 
//! This crate provides PUBLIC security testing for the WASI-TLS proposal,
//! focusing on DEFENSIVE security validation and compliance with TLS 1.3 requirements.
//! 
//! ⚠️  IMPORTANT: This crate contains only PUBLIC defensive security tests.
//! Vulnerability research tools are maintained in private repositories.

use anyhow::Result;
use std::path::Path;
use tracing_subscriber::prelude::*;

pub mod wit_validation;
pub mod security;
pub mod fixtures;

/// Core testing utilities and shared functionality
pub struct TestContext {
    pub temp_dir: tempfile::TempDir,
    pub logger: tracing_subscriber::Registry,
}

impl TestContext {
    pub fn new() -> Result<Self> {
        let temp_dir = tempfile::tempdir()?;
        
        // Initialize logging for test visibility
        let logger = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer());
        
        Ok(Self { temp_dir, logger })
    }
    
    pub fn temp_path(&self) -> &Path {
        self.temp_dir.path()
    }
}

/// Security validation levels for public testing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// Basic security constraints (TLS 1.3 only, no 0-RTT)
    Basic,
    /// RFC 8446 compliance testing
    Rfc8446,
    /// Advanced security validation (defensive features)
    Advanced,
}

/// Test result with security implications
#[derive(Debug, Clone)]
pub struct SecurityTestResult {
    pub test_name: String,
    pub passed: bool,
    pub security_level: SecurityLevel,
    pub vulnerability_risk: VulnerabilityRisk,
    pub details: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VulnerabilityRisk {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl SecurityTestResult {
    pub fn new_passed(name: &str, level: SecurityLevel) -> Self {
        Self {
            test_name: name.to_string(),
            passed: true,
            security_level: level,
            vulnerability_risk: VulnerabilityRisk::None,
            details: "Test passed".to_string(),
        }
    }
    
    pub fn new_failed(name: &str, level: SecurityLevel, risk: VulnerabilityRisk, details: &str) -> Self {
        Self {
            test_name: name.to_string(),
            passed: false,
            security_level: level,
            vulnerability_risk: risk,
            details: details.to_string(),
        }
    }
}

/// Security test suite runner
pub struct SecurityTestSuite {
    pub results: Vec<SecurityTestResult>,
    pub context: TestContext,
}

impl SecurityTestSuite {
    pub fn new() -> Result<Self> {
        Ok(Self {
            results: Vec::new(),
            context: TestContext::new()?,
        })
    }
    
    pub fn run_all_tests(&mut self) -> Result<()> {
        tracing::info!("Starting WASI-TLS public security validation suite");
        
        // Run WIT interface validation  
        self.run_wit_validation_tests()?;
        
        // Run security compliance tests
        self.run_security_compliance_tests()?;
        
        self.generate_security_report()?;
        
        Ok(())
    }
    
    fn run_wit_validation_tests(&mut self) -> Result<()> {
        tracing::info!("Running WIT interface security validation tests");
        self.results.extend(wit_validation::run_all_tests()?);
        Ok(())
    }
    
    fn run_security_compliance_tests(&mut self) -> Result<()> {
        tracing::info!("Running TLS 1.3 security compliance tests");
        self.results.extend(security::run_all_tests()?);
        Ok(())
    }
    
    fn generate_security_report(&self) -> Result<()> {
        let failed_tests: Vec<_> = self.results.iter()
            .filter(|r| !r.passed)
            .collect();
        
        let critical_failures: Vec<_> = failed_tests.iter()
            .filter(|r| r.vulnerability_risk == VulnerabilityRisk::Critical)
            .collect();
        
        tracing::info!("Security Test Report:");
        tracing::info!("Total tests: {}", self.results.len());
        tracing::info!("Failed tests: {}", failed_tests.len());
        tracing::info!("Critical vulnerabilities: {}", critical_failures.len());
        
        if !critical_failures.is_empty() {
            tracing::error!("CRITICAL SECURITY FAILURES DETECTED:");
            for failure in critical_failures {
                tracing::error!("  - {}: {}", failure.test_name, failure.details);
            }
            return Err(anyhow::anyhow!("Critical security vulnerabilities found"));
        }
        
        Ok(())
    }
    
    pub fn has_critical_failures(&self) -> bool {
        self.results.iter().any(|r| 
            !r.passed && r.vulnerability_risk == VulnerabilityRisk::Critical
        )
    }
}