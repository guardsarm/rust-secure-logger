//! Basic usage example for Rust Secure Logger
//!
//! This example demonstrates simple logging operations including
//! info, warning, and security event logging.

use rust_secure_logger::{SecureLogger, SecurityLevel};
use serde_json::json;

fn main() {
    println!("=== Rust Secure Logger - Basic Usage Example ===\n");

    // Create a new secure logger instance
    let logger = SecureLogger::new();

    // Log informational messages
    logger.info("Application started successfully");
    logger.info("Configuration loaded");
    logger.info("Database connection established");

    // Log warnings
    logger.warning("High memory usage detected: 85%");
    logger.warning("API response time exceeding threshold");

    // Log security events with metadata
    logger.security_event(
        "Failed login attempt detected",
        Some(json!({
            "ip_address": "192.168.1.100",
            "username": "admin",
            "timestamp": "2024-11-06T10:30:00Z",
            "attempt_count": 3
        })),
    );

    logger.security_event(
        "Suspicious file access detected",
        Some(json!({
            "file_path": "/etc/passwd",
            "user_id": "12345",
            "access_type": "read"
        })),
    );

    // Log critical security incident
    logger.critical(
        "Multiple failed authentication attempts - potential brute force attack",
        Some(json!({
            "source_ip": "203.0.113.45",
            "target_account": "admin",
            "attempt_count": 15,
            "time_window": "5 minutes"
        })),
    );

    // Verify integrity of all logs
    println!("Verifying log integrity...");
    if logger.verify_all_integrity() {
        println!("✓ All log entries verified - no tampering detected\n");
    } else {
        println!("✗ Log integrity check failed - tampering detected!\n");
    }

    // Get statistics
    let total_entries = logger.get_entries().len();
    let info_count = logger.count_by_level(SecurityLevel::Info);
    let warning_count = logger.count_by_level(SecurityLevel::Warning);
    let security_event_count = logger.count_by_level(SecurityLevel::SecurityEvent);
    let critical_count = logger.count_by_level(SecurityLevel::Critical);

    println!("=== Log Statistics ===");
    println!("Total entries: {}", total_entries);
    println!("Info: {}", info_count);
    println!("Warning: {}", warning_count);
    println!("Security Events: {}", security_event_count);
    println!("Critical: {}", critical_count);

    // Export logs as JSON
    println!("\n=== Exported JSON Logs ===");
    match logger.export_json() {
        Ok(json) => println!("{}", json),
        Err(e) => eprintln!("Error exporting JSON: {}", e),
    }
}
