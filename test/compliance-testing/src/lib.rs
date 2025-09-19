//! WASI-TLS RFC 8446 Compliance Testing
//! 
//! Comprehensive end-to-end compliance testing against RFC 8446 TLS 1.3 
//! using real-world scenarios and actual TLS implementations for comparison.

use anyhow::Result;
use std::time::Duration;

pub mod protocol_compliance;
pub mod interoperability;
pub mod performance_compliance;

/// Compliance test result with detailed analysis
#[derive(Debug, Clone)]
pub struct ComplianceTestResult {
    pub test_name: String,
    pub spec_section: String,  // RFC 8446 section
    pub passed: bool,
    pub compliance_level: ComplianceLevel,
    pub details: String,
    pub measurements: Vec<Measurement>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComplianceLevel {
    Must,      // RFC MUST requirements
    Should,    // RFC SHOULD recommendations  
    May,       // RFC MAY optional features
}

#[derive(Debug, Clone)]
pub struct Measurement {
    pub metric: String,
    pub value: f64,
    pub unit: String,
    pub threshold: Option<f64>,
    pub passed: bool,
}

impl ComplianceTestResult {
    pub fn new_passed(name: &str, section: &str, level: ComplianceLevel, details: &str) -> Self {
        Self {
            test_name: name.to_string(),
            spec_section: section.to_string(),
            passed: true,
            compliance_level: level,
            details: details.to_string(),
            measurements: Vec::new(),
        }
    }
    
    pub fn new_failed(name: &str, section: &str, level: ComplianceLevel, details: &str) -> Self {
        Self {
            test_name: name.to_string(),
            spec_section: section.to_string(),
            passed: false,
            compliance_level: level,
            details: details.to_string(),
            measurements: Vec::new(),
        }
    }
    
    pub fn with_measurements(mut self, measurements: Vec<Measurement>) -> Self {
        self.measurements = measurements;
        self
    }
}

/// Comprehensive RFC 8446 compliance test suite
pub struct ComplianceTestSuite {
    pub results: Vec<ComplianceTestResult>,
    pub rustls_comparison: Option<RustlsComparisonResults>,
}

impl ComplianceTestSuite {
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
            rustls_comparison: None,
        }
    }
    
    /// Run complete RFC 8446 compliance validation
    pub async fn run_full_compliance_suite(&mut self) -> Result<()> {
        tracing::info!("Starting comprehensive RFC 8446 TLS 1.3 compliance testing");
        
        // Protocol compliance testing
        self.run_protocol_compliance_tests().await?;
        
        // Interoperability testing with real TLS stacks
        self.run_interoperability_tests().await?;
        
        // Performance compliance testing
        self.run_performance_compliance_tests().await?;
        
        // Generate comprehensive compliance report
        self.generate_compliance_report()?;
        
        Ok(())
    }
    
    async fn run_protocol_compliance_tests(&mut self) -> Result<()> {
        tracing::info!("Running RFC 8446 protocol compliance tests");
        self.results.extend(protocol_compliance::run_all_tests().await?);
        Ok(())
    }
    
    async fn run_interoperability_tests(&mut self) -> Result<()> {
        tracing::info!("Running interoperability tests against known TLS implementations");
        self.results.extend(interoperability::run_all_tests().await?);
        
        // Compare against rustls as reference implementation
        self.rustls_comparison = Some(interoperability::compare_with_rustls().await?);
        
        Ok(())
    }
    
    async fn run_performance_compliance_tests(&mut self) -> Result<()> {
        tracing::info!("Running performance compliance tests");
        self.results.extend(performance_compliance::run_all_tests().await?);
        Ok(())
    }
    
    fn generate_compliance_report(&self) -> Result<()> {
        let total_tests = self.results.len();
        let passed_tests = self.results.iter().filter(|r| r.passed).count();
        let failed_tests = total_tests - passed_tests;
        
        let must_failures: Vec<_> = self.results.iter()
            .filter(|r| !r.passed && r.compliance_level == ComplianceLevel::Must)
            .collect();
        
        tracing::info!("RFC 8446 Compliance Report:");
        tracing::info!("Total tests: {}", total_tests);
        tracing::info!("Passed: {} ({:.1}%)", passed_tests, (passed_tests as f64 / total_tests as f64) * 100.0);
        tracing::info!("Failed: {}", failed_tests);
        tracing::info!("MUST requirement failures: {}", must_failures.len());
        
        if !must_failures.is_empty() {
            tracing::error!("CRITICAL: RFC MUST REQUIREMENTS FAILED:");
            for failure in must_failures {
                tracing::error!("  - {} ({}): {}", failure.test_name, failure.spec_section, failure.details);
            }
            return Err(anyhow::anyhow!("Critical RFC 8446 MUST requirements failed"));
        }
        
        // Performance summary
        if let Some(ref rustls_results) = self.rustls_comparison {
            tracing::info!("Rustls Comparison:");
            tracing::info!("  Handshake performance: {:.2}ms vs {:.2}ms", 
                rustls_results.wasi_tls_handshake_time, rustls_results.rustls_handshake_time);
            tracing::info!("  Memory usage: {:.2}MB vs {:.2}MB",
                rustls_results.wasi_tls_memory_mb, rustls_results.rustls_memory_mb);
        }
        
        Ok(())
    }
    
    pub fn has_critical_failures(&self) -> bool {
        self.results.iter().any(|r| 
            !r.passed && r.compliance_level == ComplianceLevel::Must
        )
    }
}

/// Rustls comparison results for benchmarking
#[derive(Debug, Clone)]
pub struct RustlsComparisonResults {
    pub wasi_tls_handshake_time: f64,  // milliseconds
    pub rustls_handshake_time: f64,
    pub wasi_tls_memory_mb: f64,
    pub rustls_memory_mb: f64,
    pub feature_parity: f64,  // percentage of features matching
}