//! Audit trail example for financial systems
//!
//! This example demonstrates secure logging for financial transactions
//! with tamper detection and regulatory compliance features.

use rust_secure_logger::{SecureLogger, SecurityLevel};
use serde_json::json;

fn main() {
    println!("=== Financial Transaction Audit Trail Example ===\n");

    // Create secure logger for financial system
    let logger = SecureLogger::new();

    // Log user authentication
    logger.audit(
        "User authenticated successfully",
        Some(json!({
            "user_id": "USER-12345",
            "username": "john.trader",
            "authentication_method": "2FA",
            "ip_address": "192.168.1.50",
            "timestamp": "2024-11-06T09:00:00Z"
        })),
    );

    // Log wire transfer initiation
    logger.audit(
        "Wire transfer initiated",
        Some(json!({
            "transaction_id": "TXN-2024-11-06-001",
            "amount": 50000.00,
            "currency": "USD",
            "from_account": "****1234",
            "to_account": "****5678",
            "beneficiary_name": "Corporate Account",
            "initiated_by": "USER-12345",
            "timestamp": "2024-11-06T09:15:00Z",
            "compliance_check": "PASSED"
        })),
    );

    // Log compliance review
    logger.audit(
        "AML/KYC compliance check completed",
        Some(json!({
            "transaction_id": "TXN-2024-11-06-001",
            "check_type": "AML",
            "result": "APPROVED",
            "risk_score": 15,
            "reviewed_by": "SYSTEM-AUTO",
            "timestamp": "2024-11-06T09:15:30Z"
        })),
    );

    // Log transaction approval
    logger.audit(
        "Wire transfer approved",
        Some(json!({
            "transaction_id": "TXN-2024-11-06-001",
            "approved_by": "MANAGER-67890",
            "approval_timestamp": "2024-11-06T09:20:00Z",
            "two_factor_verified": true
        })),
    );

    // Log transaction execution
    logger.audit(
        "Wire transfer executed successfully",
        Some(json!({
            "transaction_id": "TXN-2024-11-06-001",
            "execution_timestamp": "2024-11-06T09:25:00Z",
            "bank_reference": "BANK-REF-987654",
            "status": "COMPLETED"
        })),
    );

    // Log account balance update
    logger.audit(
        "Account balance updated",
        Some(json!({
            "account_number": "****1234",
            "previous_balance": 100000.00,
            "new_balance": 50000.00,
            "transaction_id": "TXN-2024-11-06-001",
            "timestamp": "2024-11-06T09:25:05Z"
        })),
    );

    // Simulate a security event during trading
    logger.security_event(
        "Unusual trading pattern detected",
        Some(json!({
            "user_id": "USER-67890",
            "pattern": "High frequency orders",
            "order_count": 150,
            "time_window": "5 minutes",
            "risk_level": "MEDIUM",
            "action_taken": "Flagged for review"
        })),
    );

    // Log regulatory report generation
    logger.audit(
        "Daily regulatory report generated",
        Some(json!({
            "report_type": "SOX_COMPLIANCE",
            "report_id": "RPT-2024-11-06",
            "transaction_count": 247,
            "total_volume": 12500000.00,
            "generated_by": "SYSTEM-AUTO",
            "timestamp": "2024-11-06T23:59:59Z"
        })),
    );

    // Verify integrity of audit trail
    println!("Verifying audit trail integrity...");
    if logger.verify_all_integrity() {
        println!("✓ Audit trail verified - no tampering detected\n");
    } else {
        println!("✗ ALERT: Audit trail integrity compromised!\n");
        return;
    }

    // Get audit statistics
    let audit_entries = logger.get_entries_by_level(SecurityLevel::Audit);
    let security_events = logger.get_entries_by_level(SecurityLevel::SecurityEvent);

    println!("=== Audit Trail Statistics ===");
    println!("Total audit entries: {}", audit_entries.len());
    println!("Security events: {}", security_events.len());
    println!("Total entries: {}", logger.get_entries().len());

    // Display audit entries
    println!("\n=== Audit Trail Entries ===");
    for (i, entry) in audit_entries.iter().enumerate() {
        println!("\n[{}] {}", i + 1, entry.timestamp.format("%Y-%m-%d %H:%M:%S UTC"));
        println!("    Message: {}", entry.message);
        if let Some(metadata) = &entry.metadata {
            println!("    Metadata: {}", serde_json::to_string_pretty(metadata).unwrap());
        }
        println!("    Integrity Hash: {}...", &entry.integrity_hash[..16]);
        println!("    Verified: {}", entry.verify_integrity());
    }

    // Export complete audit trail
    println!("\n=== Complete Audit Trail (JSON) ===");
    match logger.export_json() {
        Ok(json) => {
            // In production, this would be saved to secure storage
            println!("{}", json);
        }
        Err(e) => eprintln!("Error exporting audit trail: {}", e),
    }

    println!("\n=== Compliance Notes ===");
    println!("✓ All transactions logged with cryptographic integrity");
    println!("✓ Tamper detection enabled via SHA-256 hashing");
    println!("✓ Thread-safe logging for concurrent operations");
    println!("✓ Structured JSON format for SIEM integration");
    println!("✓ Audit trail suitable for SOX, GLBA, PCI-DSS compliance");
}
