//! WASI-TLS Component Testing - WASM Isolate Compatible
//! 
//! Pure component testing that runs inside WASM isolates without system calls.
//! All tests use only computational logic and WASI-provided interfaces.

#![no_std]
extern crate alloc;

use alloc::vec::Vec;
use alloc::string::String;
use core::result::Result as CoreResult;

pub mod wit_validation;
pub mod unit_tests;
pub mod input_validation;

/// WASM-compatible test result (no system dependencies)
#[derive(Debug, Clone)]
pub struct ComponentTestResult {
    pub test_name: String,
    pub passed: bool,
    pub details: String,
    pub test_category: ComponentTestCategory,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComponentTestCategory {
    WitValidation,     // WIT interface logic validation
    UnitTest,          // Pure component unit tests
    InputValidation,   // Input boundary testing
    PropertyTest,      // Property-based pure testing
}

impl ComponentTestResult {
    pub fn new_passed(name: &str, category: ComponentTestCategory) -> Self {
        Self {
            test_name: name.to_string(),
            passed: true,
            details: "Test passed".to_string(),
            test_category: category,
        }
    }
    
    pub fn new_failed(name: &str, category: ComponentTestCategory, details: &str) -> Self {
        Self {
            test_name: name.to_string(),
            passed: false,
            details: details.to_string(),
            test_category: category,
        }
    }
}

/// WASM component test suite (no system calls)
pub struct ComponentTestSuite {
    pub results: Vec<ComponentTestResult>,
}

impl ComponentTestSuite {
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
        }
    }
    
    /// Run all component tests in WASM isolate
    pub fn run_all_component_tests(&mut self) -> CoreResult<(), &'static str> {
        // WIT interface validation (pure logic)
        if let Err(_) = self.run_wit_validation_tests() {
            return Err("WIT validation tests failed");
        }
        
        // Component unit tests (pure functions)
        if let Err(_) = self.run_unit_tests() {
            return Err("Unit tests failed");
        }
        
        // Input validation tests (safe boundaries)
        if let Err(_) = self.run_input_validation_tests() {
            return Err("Input validation tests failed");
        }
        
        self.generate_component_report()
    }
    
    fn run_wit_validation_tests(&mut self) -> CoreResult<(), &'static str> {
        let wit_results = wit_validation::run_all_tests()?;
        self.results.extend(wit_results);
        Ok(())
    }
    
    fn run_unit_tests(&mut self) -> CoreResult<(), &'static str> {
        let unit_results = unit_tests::run_all_tests()?;
        self.results.extend(unit_results);
        Ok(())
    }
    
    fn run_input_validation_tests(&mut self) -> CoreResult<(), &'static str> {
        let input_results = input_validation::run_all_tests()?;
        self.results.extend(input_results);
        Ok(())
    }
    
    fn generate_component_report(&self) -> CoreResult<(), &'static str> {
        let total_tests = self.results.len();
        let passed_tests = self.results.iter().filter(|r| r.passed).count();
        let failed_tests = total_tests - passed_tests;
        
        // Use log crate for WASM-compatible logging
        log::info!("Component Test Report:");
        log::info!("Total tests: {}", total_tests);
        log::info!("Passed: {} ({:.1}%)", passed_tests, (passed_tests as f64 / total_tests as f64) * 100.0);
        log::info!("Failed: {}", failed_tests);
        
        if failed_tests > 0 {
            log::error!("Component test failures detected:");
            for result in self.results.iter().filter(|r| !r.passed) {
                log::error!("  - {}: {}", result.test_name, result.details);
            }
            Err("Component tests failed")
        } else {
            Ok(())
        }
    }
    
    pub fn has_failures(&self) -> bool {
        self.results.iter().any(|r| !r.passed)
    }
}

/// WASM-compatible utilities for component testing
pub struct ComponentTestUtils;

impl ComponentTestUtils {
    /// Generate test data using WASM-compatible RNG
    pub fn generate_test_data(size: usize) -> Vec<u8> {
        use rand::{RngCore, SeedableRng};
        let mut rng = rand::rngs::SmallRng::from_entropy();
        let mut data = alloc::vec![0u8; size];
        rng.fill_bytes(&mut data);
        data
    }
    
    /// Validate input data without system calls
    pub fn validate_input_pure(input: &[u8]) -> bool {
        // Pure validation logic
        !input.is_empty() && input.len() <= 65536
    }
    
    /// Parse WIT content without file I/O (takes content as parameter)
    pub fn parse_wit_content(wit_content: &str) -> CoreResult<WitParseResult, &'static str> {
        if wit_content.is_empty() {
            return Err("Empty WIT content");
        }
        
        let has_tls13_only = wit_content.contains("0x0304") && !wit_content.contains("0x0303");
        let has_security_first = wit_content.contains("Security-First") || wit_content.contains("security-first");
        let has_error_handling = wit_content.contains("error-code") && wit_content.contains("handshake-failure");
        
        Ok(WitParseResult {
            tls13_only: has_tls13_only,
            security_first_design: has_security_first,
            comprehensive_errors: has_error_handling,
        })
    }
}

#[derive(Debug, Clone)]
pub struct WitParseResult {
    pub tls13_only: bool,
    pub security_first_design: bool,
    pub comprehensive_errors: bool,
}

// Export for WASM usage
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn run_component_tests_wasm() -> Result<String, JsValue> {
    let mut suite = ComponentTestSuite::new();
    
    match suite.run_all_component_tests() {
        Ok(_) => Ok(serde_json::to_string(&suite.results).unwrap_or_else(|_| "Serialization error".to_string())),
        Err(e) => Err(JsValue::from_str(e)),
    }
}