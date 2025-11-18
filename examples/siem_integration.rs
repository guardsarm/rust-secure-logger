//! Example: SIEM Integration with CEF and LEEF exports

use rust_secure_logger::{SecureLogger, SecurityLevel};

fn main() {
    println!("=== SIEM Integration Example ===\n");

    // Create logger with source identifier
    let logger = SecureLogger::with_source("web-app-prod-01");

    // Log some security events
    logger.log_with_category(
        SecurityLevel::SecurityEvent,
        "Failed login attempt",
        Some(serde_json::json!({
            "username": "admin",
            "ip_address": "192.168.1.100",
            "attempt_count": 3
        })),
        "authentication"
    );

    logger.log_with_category(
        SecurityLevel::Critical,
        "SQL injection attempt detected",
        Some(serde_json::json!({
            "source_ip": "10.0.0.45",
            "query": "SELECT * FROM users WHERE id=1' OR '1'='1",
            "blocked": true
        })),
        "web_attack"
    );

    logger.audit(
        "Financial transaction processed",
        Some(serde_json::json!({
            "transaction_id": "TXN-987654",
            "amount": 50000.00,
            "currency": "USD",
            "from_account": "****1234",
            "to_account": "****5678"
        }))
    );

    // Export to CEF format (for ArcSight)
    println!("CEF Format (ArcSight):");
    println!("{}", "=".repeat(80));
    for cef_log in logger.export_cef() {
        println!("{}", cef_log);
    }
    println!();

    // Export to LEEF format (for QRadar)
    println!("LEEF Format (IBM QRadar):");
    println!("{}", "=".repeat(80));
    for leef_log in logger.export_leef() {
        println!("{}", leef_log);
    }
    println!();

    // Export to Syslog RFC 5424
    println!("Syslog RFC 5424:");
    println!("{}", "=".repeat(80));
    for syslog_entry in logger.export_syslog() {
        println!("{}", syslog_entry);
    }
    println!();

    // Export to Splunk HEC format
    println!("Splunk HEC Format:");
    println!("{}", "=".repeat(80));
    for splunk_entry in logger.export_splunk() {
        println!("{}", splunk_entry);
    }
    println!();

    // Show statistics
    let stats = logger.get_statistics();
    println!("Log Statistics:");
    println!("{}", "=".repeat(80));
    println!("Total entries: {}", stats.total_entries);
    println!("Security events: {}", stats.security_event_count);
    println!("Critical events: {}", stats.critical_count);
    println!("Audit events: {}", stats.audit_count);
    println!();

    // Verify integrity
    println!("Integrity Verification:");
    println!("{}", "=".repeat(80));
    if logger.verify_all_integrity() {
        println!("✓ All log entries passed integrity verification");
    } else {
        println!("✗ Some log entries failed integrity verification");
    }
}
