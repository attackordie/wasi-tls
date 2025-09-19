//! Security Validator - Comprehensive WASI-TLS Security Testing
//! 
//! Main binary for running comprehensive security validation tests
//! against WASI-TLS implementations.

use anyhow::Result;
use clap::{Arg, Command};
use std::path::PathBuf;
use tracing::{error, info, warn};
use wasi_tls_tests::{SecurityTestSuite, SecurityLevel, VulnerabilityRisk};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .init();
    
    let matches = Command::new("security-validator")
        .about("WASI-TLS Security Validation Tool")
        .version("0.1.0")
        .author("WASI-TLS Security Team")
        .arg(
            Arg::new("level")
                .short('l')
                .long("level")
                .value_name("LEVEL")
                .help("Security validation level")
                .value_parser(["basic", "rfc8446", "advanced", "exploit"])
                .default_value("rfc8446")
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("FILE")
                .help("Output report file (JSON format)")
        )
        .arg(
            Arg::new("wit-path")
                .short('w')
                .long("wit-path")
                .value_name("PATH")
                .help("Path to WIT interface files")
                .default_value("wit/")
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Enable verbose output")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("fail-fast")
                .long("fail-fast")
                .help("Stop on first critical security failure")
                .action(clap::ArgAction::SetTrue)
        )
        .get_matches();
    
    // Parse arguments
    let security_level = parse_security_level(matches.get_one::<String>("level").unwrap())?;
    let output_file = matches.get_one::<String>("output").map(PathBuf::from);
    let wit_path = PathBuf::from(matches.get_one::<String>("wit-path").unwrap());
    let verbose = matches.get_flag("verbose");
    let fail_fast = matches.get_flag("fail-fast");
    
    if verbose {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_target(true)
            .init();
    }
    
    info!("Starting WASI-TLS Security Validation");
    info!("Security Level: {:?}", security_level);
    info!("WIT Path: {}", wit_path.display());
    
    // Verify WIT files exist
    if !wit_path.exists() {
        error!("WIT path does not exist: {}", wit_path.display());
        std::process::exit(1);
    }
    
    // Create and run security test suite
    let mut test_suite = SecurityTestSuite::new()?;
    
    match test_suite.run_all_tests() {
        Ok(()) => {
            info!("Security validation completed successfully");
            
            // Generate report
            let report = generate_security_report(&test_suite, security_level)?;
            
            if let Some(output_path) = output_file {
                write_report_to_file(&report, &output_path)?;
                info!("Security report written to: {}", output_path.display());
            } else {
                print_report_to_console(&report);
            }
            
            // Check for critical failures
            if test_suite.has_critical_failures() {
                error!("CRITICAL SECURITY FAILURES DETECTED");
                print_critical_failures(&test_suite);
                std::process::exit(1);
            }
            
            info!("All security validations passed ✓");
        }
        Err(e) => {
            error!("Security validation failed: {}", e);
            
            if fail_fast || test_suite.has_critical_failures() {
                error!("Stopping due to critical security failures");
                print_critical_failures(&test_suite);
                std::process::exit(1);
            }
        }
    }
    
    Ok(())
}

fn parse_security_level(level_str: &str) -> Result<SecurityLevel> {
    match level_str.to_lowercase().as_str() {
        "basic" => Ok(SecurityLevel::Basic),
        "rfc8446" => Ok(SecurityLevel::Rfc8446),
        "advanced" => Ok(SecurityLevel::Advanced),
        "exploit" => Ok(SecurityLevel::Exploit),
        _ => Err(anyhow::anyhow!("Invalid security level: {}", level_str)),
    }
}

#[derive(serde::Serialize)]
struct SecurityReport {
    timestamp: String,
    security_level: String,
    total_tests: usize,
    passed_tests: usize,
    failed_tests: usize,
    critical_failures: usize,
    high_risk_failures: usize,
    test_results: Vec<TestResult>,
    summary: ReportSummary,
}

#[derive(serde::Serialize)]
struct TestResult {
    name: String,
    passed: bool,
    security_level: String,
    vulnerability_risk: String,
    details: String,
}

#[derive(serde::Serialize)]
struct ReportSummary {
    overall_status: String,
    security_posture: String,
    recommendations: Vec<String>,
    next_steps: Vec<String>,
}

fn generate_security_report(test_suite: &SecurityTestSuite, level: SecurityLevel) -> Result<SecurityReport> {
    let results = &test_suite.results;
    let total_tests = results.len();
    let passed_tests = results.iter().filter(|r| r.passed).count();
    let failed_tests = total_tests - passed_tests;
    
    let critical_failures = results.iter()
        .filter(|r| !r.passed && r.vulnerability_risk == VulnerabilityRisk::Critical)
        .count();
    
    let high_risk_failures = results.iter()
        .filter(|r| !r.passed && r.vulnerability_risk == VulnerabilityRisk::High)
        .count();
    
    let test_results: Vec<TestResult> = results.iter().map(|r| TestResult {
        name: r.test_name.clone(),
        passed: r.passed,
        security_level: format!("{:?}", r.security_level),
        vulnerability_risk: format!("{:?}", r.vulnerability_risk),
        details: r.details.clone(),
    }).collect();
    
    let overall_status = if critical_failures > 0 {
        "CRITICAL_FAILURES"
    } else if high_risk_failures > 0 {
        "HIGH_RISK_ISSUES"
    } else if failed_tests > 0 {
        "MINOR_ISSUES"
    } else {
        "SECURE"
    };
    
    let security_posture = determine_security_posture(critical_failures, high_risk_failures, failed_tests, total_tests);
    let recommendations = generate_recommendations(results);
    let next_steps = generate_next_steps(&level, critical_failures > 0);
    
    let summary = ReportSummary {
        overall_status: overall_status.to_string(),
        security_posture,
        recommendations,
        next_steps,
    };
    
    Ok(SecurityReport {
        timestamp: chrono::Utc::now().to_rfc3339(),
        security_level: format!("{:?}", level),
        total_tests,
        passed_tests,
        failed_tests,
        critical_failures,
        high_risk_failures,
        test_results,
        summary,
    })
}

fn determine_security_posture(critical: usize, high: usize, failed: usize, total: usize) -> String {
    let pass_rate = ((total - failed) as f64 / total as f64) * 100.0;
    
    if critical > 0 {
        "VULNERABLE - Critical security issues require immediate attention".to_string()
    } else if high > 0 {
        format!("AT RISK - {} high-risk security issues identified", high)
    } else if pass_rate < 95.0 {
        format!("NEEDS IMPROVEMENT - {:.1}% test pass rate", pass_rate)
    } else {
        format!("SECURE - {:.1}% test pass rate, no critical issues", pass_rate)
    }
}

fn generate_recommendations(results: &[wasi_tls_tests::SecurityTestResult]) -> Vec<String> {
    let mut recommendations = Vec::new();
    
    let critical_issues: Vec<_> = results.iter()
        .filter(|r| !r.passed && r.vulnerability_risk == VulnerabilityRisk::Critical)
        .collect();
    
    if !critical_issues.is_empty() {
        recommendations.push("URGENT: Address all critical security vulnerabilities immediately".to_string());
        recommendations.push("Review TLS 1.3 RFC 8446 compliance requirements".to_string());
        recommendations.push("Implement additional input validation and bounds checking".to_string());
    }
    
    let has_wit_issues = results.iter().any(|r| 
        !r.passed && r.test_name.contains("WIT") || r.test_name.contains("interface")
    );
    
    if has_wit_issues {
        recommendations.push("Review WIT interface definitions for security constraints".to_string());
    }
    
    let has_fuzzing_failures = results.iter().any(|r| 
        !r.passed && r.test_name.contains("fuzz")
    );
    
    if has_fuzzing_failures {
        recommendations.push("Improve fuzzing test coverage and fix identified crash conditions".to_string());
    }
    
    // Always recommend security best practices
    recommendations.push("Conduct regular security audits and penetration testing".to_string());
    recommendations.push("Keep security testing framework updated with latest threat intelligence".to_string());
    
    recommendations
}

fn generate_next_steps(level: &SecurityLevel, has_critical: bool) -> Vec<String> {
    let mut next_steps = Vec::new();
    
    if has_critical {
        next_steps.push("Stop deployment until critical issues are resolved".to_string());
        next_steps.push("Conduct security code review of affected components".to_string());
        next_steps.push("Re-run security validation after fixes are applied".to_string());
    } else {
        match level {
            SecurityLevel::Basic => {
                next_steps.push("Consider upgrading to RFC 8446 compliance level".to_string());
            }
            SecurityLevel::Rfc8446 => {
                next_steps.push("Consider advanced security testing".to_string());
            }
            SecurityLevel::Advanced => {
                next_steps.push("Consider exploit resistance testing".to_string());
            }
            SecurityLevel::Exploit => {
                next_steps.push("Security validation complete - ready for deployment".to_string());
            }
        }
    }
    
    next_steps.push("Schedule regular security re-validation".to_string());
    next_steps.push("Monitor security advisories for new threats".to_string());
    
    next_steps
}

fn write_report_to_file(report: &SecurityReport, path: &PathBuf) -> Result<()> {
    let json = serde_json::to_string_pretty(report)?;
    std::fs::write(path, json)?;
    Ok(())
}

fn print_report_to_console(report: &SecurityReport) {
    println!("\n=== WASI-TLS SECURITY VALIDATION REPORT ===");
    println!("Timestamp: {}", report.timestamp);
    println!("Security Level: {}", report.security_level);
    println!();
    
    println!("Test Results:");
    println!("  Total Tests: {}", report.total_tests);
    println!("  Passed: {}", report.passed_tests);
    println!("  Failed: {}", report.failed_tests);
    println!("  Critical Failures: {}", report.critical_failures);
    println!("  High Risk Failures: {}", report.high_risk_failures);
    println!();
    
    println!("Overall Status: {}", report.summary.overall_status);
    println!("Security Posture: {}", report.summary.security_posture);
    println!();
    
    if !report.summary.recommendations.is_empty() {
        println!("Recommendations:");
        for rec in &report.summary.recommendations {
            println!("  • {}", rec);
        }
        println!();
    }
    
    if !report.summary.next_steps.is_empty() {
        println!("Next Steps:");
        for step in &report.summary.next_steps {
            println!("  • {}", step);
        }
    }
}

fn print_critical_failures(test_suite: &SecurityTestSuite) {
    let critical_failures: Vec<_> = test_suite.results.iter()
        .filter(|r| !r.passed && r.vulnerability_risk == VulnerabilityRisk::Critical)
        .collect();
    
    if !critical_failures.is_empty() {
        error!("\n🚨 CRITICAL SECURITY FAILURES:");
        for failure in critical_failures {
            error!("  ❌ {}: {}", failure.test_name, failure.details);
        }
        error!("\n⚠️  DO NOT DEPLOY UNTIL THESE ISSUES ARE RESOLVED ⚠️");
    }
    
    let high_failures: Vec<_> = test_suite.results.iter()
        .filter(|r| !r.passed && r.vulnerability_risk == VulnerabilityRisk::High)
        .collect();
    
    if !high_failures.is_empty() {
        warn!("\n⚠️  HIGH RISK SECURITY ISSUES:");
        for failure in high_failures {
            warn!("  ⚠️  {}: {}", failure.test_name, failure.details);
        }
    }
}