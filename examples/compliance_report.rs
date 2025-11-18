//! Example: Generate compliance reports (SOX, PCI-DSS, GLBA)

use chrono::{Duration, Utc};
use rust_secure_logger::{ComplianceReporter, SecureLogger};

fn main() {
    println!("=== Compliance Reporting Example ===\n");

    // Create logger
    let logger = SecureLogger::with_source("financial-system-01");

    // Simulate a day of operations
    logger.audit(
        "User login",
        Some(serde_json::json!({"user_id": "USR-001", "role": "admin"})),
    );

    logger.audit(
        "Transaction processed",
        Some(serde_json::json!({
            "transaction_id": "TXN-12345",
            "amount": 10000.00,
            "type": "wire_transfer"
        })),
    );

    logger.security_event(
        "Failed authentication attempt",
        Some(serde_json::json!({"username": "admin", "ip": "192.168.1.50"})),
    );

    logger.critical(
        "Unauthorized access attempt",
        Some(serde_json::json!({"resource": "/admin/users", "ip": "10.0.0.100"})),
    );

    logger.info("Daily backup completed");
    logger.warning("High CPU usage detected");

    // Define reporting period
    let period_start = Utc::now() - Duration::hours(24);
    let period_end = Utc::now();

    // Generate SOX Compliance Report
    println!("SOX COMPLIANCE REPORT");
    println!("{}", "=".repeat(80));
    let sox_report = logger.generate_sox_report(period_start, period_end);
    println!(
        "Report Period: {} to {}",
        sox_report.period_start, sox_report.period_end
    );
    println!("Total Events: {}", sox_report.total_events);
    println!("Audit Events: {}", sox_report.audit_events);
    println!("Security Events: {}", sox_report.security_events);
    println!("Critical Events: {}", sox_report.critical_events);
    println!("Integrity Verified: {}", sox_report.integrity_verified);
    println!("\nFindings:");
    for (i, finding) in sox_report.findings.iter().enumerate() {
        println!(
            "  {}. [{:?}] {} - {}",
            i + 1,
            finding.severity,
            finding.control_area,
            finding.description
        );
    }
    println!();

    // Export SOX report as JSON
    if let Ok(json) = ComplianceReporter::export_json(&sox_report) {
        println!("JSON Export (first 500 chars):");
        println!("{}", &json[..json.len().min(500)]);
        println!("...\n");
    }

    // Generate PCI-DSS Report
    println!("PCI-DSS COMPLIANCE REPORT");
    println!("{}", "=".repeat(80));
    let pci_report = logger.generate_pci_report(period_start, period_end);
    println!("Total Events: {}", pci_report.total_events);
    println!("Audit Events (Req 10.2): {}", pci_report.audit_events);
    println!(
        "Integrity Status (Req 10.5): {}",
        if pci_report.integrity_verified {
            "PASS"
        } else {
            "FAIL"
        }
    );
    println!("\nFindings:");
    for (i, finding) in pci_report.findings.iter().enumerate() {
        println!(
            "  {}. [{:?}] {} - {}",
            i + 1,
            finding.severity,
            finding.control_area,
            finding.description
        );
    }
    println!();

    // Generate GLBA Report
    println!("GLBA COMPLIANCE REPORT");
    println!("{}", "=".repeat(80));
    let glba_report = logger.generate_glba_report(period_start, period_end);
    println!("Total Events: {}", glba_report.total_events);
    println!(
        "Safeguards Rule - Audit Events: {}",
        glba_report.audit_events
    );
    println!("\nFindings:");
    for (i, finding) in glba_report.findings.iter().enumerate() {
        println!(
            "  {}. [{:?}] {} - {}",
            i + 1,
            finding.severity,
            finding.control_area,
            finding.description
        );
    }
    println!();

    // Export as CSV
    println!("CSV EXPORT (Sample):");
    println!("{}", "=".repeat(80));
    let csv = ComplianceReporter::export_csv(&sox_report);
    println!("{}", csv);
}
