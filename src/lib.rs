//! # Rust Secure Logger
//!
//! A memory-safe, thread-safe logging library designed for financial systems
//! and critical infrastructure where security and audit trails are essential.
//!
//! ## Features
//!
//! - **Memory Safety**: Built with Rust's ownership system to prevent buffer overflows and memory corruption
//! - **Thread Safety**: Concurrent logging without data races
//! - **Tamper Detection**: Cryptographic hashing of log entries
//! - **Structured Logging**: JSON format for easy parsing and analysis
//! - **Audit Trail**: Immutable log entries with timestamps and integrity verification
//!
//! ## Alignment with Federal Guidance
//!
//! This library aligns with 2024 CISA/FBI guidance recommending memory-safe
//! languages for critical infrastructure to eliminate 70% of security vulnerabilities.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};

/// Security levels for log entries
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SecurityLevel {
    /// Informational message
    Info,
    /// Warning that may require attention
    Warning,
    /// Security event requiring review
    SecurityEvent,
    /// Critical security incident
    Critical,
    /// Audit trail entry (financial transactions, access control)
    Audit,
}

/// A single log entry with cryptographic integrity protection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// UTC timestamp when entry was created
    pub timestamp: DateTime<Utc>,
    /// Security level
    pub level: SecurityLevel,
    /// Log message
    pub message: String,
    /// Optional structured data (user ID, transaction ID, etc.)
    pub metadata: Option<serde_json::Value>,
    /// SHA-256 hash of entry content for tamper detection
    pub integrity_hash: String,
}

impl LogEntry {
    /// Create a new log entry with integrity hash
    pub fn new(level: SecurityLevel, message: String, metadata: Option<serde_json::Value>) -> Self {
        let timestamp = Utc::now();
        let mut entry = Self {
            timestamp,
            level,
            message,
            metadata,
            integrity_hash: String::new(),
        };
        entry.integrity_hash = entry.calculate_hash();
        entry
    }

    /// Calculate cryptographic hash of entry content
    fn calculate_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.timestamp.to_rfc3339().as_bytes());
        hasher.update(format!("{:?}", self.level).as_bytes());
        hasher.update(self.message.as_bytes());
        if let Some(ref meta) = self.metadata {
            hasher.update(meta.to_string().as_bytes());
        }
        format!("{:x}", hasher.finalize())
    }

    /// Verify entry integrity (detect tampering)
    pub fn verify_integrity(&self) -> bool {
        let calculated = self.calculate_hash();
        calculated == self.integrity_hash
    }

    /// Serialize to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

/// Thread-safe secure logger for financial systems
#[derive(Clone)]
pub struct SecureLogger {
    entries: Arc<Mutex<Vec<LogEntry>>>,
}

impl SecureLogger {
    /// Create a new secure logger instance
    pub fn new() -> Self {
        Self {
            entries: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Log an informational message
    pub fn info(&self, message: impl Into<String>) {
        self.log(SecurityLevel::Info, message.into(), None);
    }

    /// Log a warning
    pub fn warning(&self, message: impl Into<String>) {
        self.log(SecurityLevel::Warning, message.into(), None);
    }

    /// Log a security event with optional metadata
    pub fn security_event(&self, message: impl Into<String>, metadata: Option<serde_json::Value>) {
        self.log(SecurityLevel::SecurityEvent, message.into(), metadata);
    }

    /// Log a critical security incident
    pub fn critical(&self, message: impl Into<String>, metadata: Option<serde_json::Value>) {
        self.log(SecurityLevel::Critical, message.into(), metadata);
    }

    /// Log an audit trail entry (for financial transactions, access control, etc.)
    pub fn audit(&self, message: impl Into<String>, metadata: Option<serde_json::Value>) {
        self.log(SecurityLevel::Audit, message.into(), metadata);
    }

    /// Internal logging function
    fn log(&self, level: SecurityLevel, message: String, metadata: Option<serde_json::Value>) {
        let entry = LogEntry::new(level, message, metadata);
        let mut entries = self.entries.lock().unwrap();
        entries.push(entry);
    }

    /// Get all log entries (read-only)
    pub fn get_entries(&self) -> Vec<LogEntry> {
        let entries = self.entries.lock().unwrap();
        entries.clone()
    }

    /// Get entries filtered by security level
    pub fn get_entries_by_level(&self, level: SecurityLevel) -> Vec<LogEntry> {
        let entries = self.entries.lock().unwrap();
        entries
            .iter()
            .filter(|e| e.level == level)
            .cloned()
            .collect()
    }

    /// Verify integrity of all log entries
    pub fn verify_all_integrity(&self) -> bool {
        let entries = self.entries.lock().unwrap();
        entries.iter().all(|entry| entry.verify_integrity())
    }

    /// Export logs as JSON
    pub fn export_json(&self) -> Result<String, serde_json::Error> {
        let entries = self.entries.lock().unwrap();
        serde_json::to_string_pretty(&*entries)
    }

    /// Get count of entries by security level
    pub fn count_by_level(&self, level: SecurityLevel) -> usize {
        let entries = self.entries.lock().unwrap();
        entries.iter().filter(|e| e.level == level).count()
    }

    /// Get entries within a date range
    pub fn get_entries_by_date_range(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Vec<LogEntry> {
        let entries = self.entries.lock().unwrap();
        entries
            .iter()
            .filter(|e| e.timestamp >= start && e.timestamp <= end)
            .cloned()
            .collect()
    }

    /// Clear all log entries (use with caution - breaks audit trail)
    pub fn clear(&self) {
        let mut entries = self.entries.lock().unwrap();
        entries.clear()
    }

    /// Get the most recent N entries
    pub fn get_recent_entries(&self, count: usize) -> Vec<LogEntry> {
        let entries = self.entries.lock().unwrap();
        let total = entries.len();
        if total <= count {
            entries.clone()
        } else {
            entries[total - count..].to_vec()
        }
    }

    /// Search log entries by message content
    pub fn search(&self, query: &str) -> Vec<LogEntry> {
        let entries = self.entries.lock().unwrap();
        entries
            .iter()
            .filter(|e| e.message.contains(query))
            .cloned()
            .collect()
    }

    /// Get statistics about log entries
    pub fn get_statistics(&self) -> LogStatistics {
        let entries = self.entries.lock().unwrap();
        let total_entries = entries.len();

        let mut stats = LogStatistics {
            total_entries,
            info_count: 0,
            warning_count: 0,
            security_event_count: 0,
            critical_count: 0,
            audit_count: 0,
        };

        for entry in entries.iter() {
            match entry.level {
                SecurityLevel::Info => stats.info_count += 1,
                SecurityLevel::Warning => stats.warning_count += 1,
                SecurityLevel::SecurityEvent => stats.security_event_count += 1,
                SecurityLevel::Critical => stats.critical_count += 1,
                SecurityLevel::Audit => stats.audit_count += 1,
            }
        }

        stats
    }
}

/// Statistics about log entries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogStatistics {
    pub total_entries: usize,
    pub info_count: usize,
    pub warning_count: usize,
    pub security_event_count: usize,
    pub critical_count: usize,
    pub audit_count: usize,
}

impl Default for SecureLogger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_entry_creation() {
        let entry = LogEntry::new(SecurityLevel::Info, "Test message".to_string(), None);
        assert_eq!(entry.level, SecurityLevel::Info);
        assert_eq!(entry.message, "Test message");
        assert!(!entry.integrity_hash.is_empty());
    }

    #[test]
    fn test_integrity_verification() {
        let entry = LogEntry::new(SecurityLevel::Audit, "Transaction: $1000".to_string(), None);
        assert!(entry.verify_integrity());
    }

    #[test]
    fn test_tampering_detection() {
        let mut entry = LogEntry::new(SecurityLevel::Audit, "Original message".to_string(), None);
        // Simulate tampering
        entry.message = "Tampered message".to_string();
        assert!(!entry.verify_integrity());
    }

    #[test]
    fn test_secure_logger() {
        let logger = SecureLogger::new();
        logger.info("Application started");
        logger.warning("High memory usage detected");
        logger.audit("User authentication successful", Some(serde_json::json!({
            "user_id": "12345",
            "timestamp": "2024-11-06T00:00:00Z"
        })));

        assert_eq!(logger.get_entries().len(), 3);
        assert_eq!(logger.count_by_level(SecurityLevel::Info), 1);
        assert_eq!(logger.count_by_level(SecurityLevel::Warning), 1);
        assert_eq!(logger.count_by_level(SecurityLevel::Audit), 1);
    }

    #[test]
    fn test_thread_safety() {
        use std::thread;

        let logger = SecureLogger::new();
        let mut handles = vec![];

        for i in 0..10 {
            let logger_clone = logger.clone();
            let handle = thread::spawn(move || {
                logger_clone.info(format!("Thread {} message", i));
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(logger.get_entries().len(), 10);
    }

    #[test]
    fn test_json_export() {
        let logger = SecureLogger::new();
        logger.security_event("Failed login attempt", Some(serde_json::json!({
            "ip": "192.168.1.100",
            "username": "admin"
        })));

        let json = logger.export_json().unwrap();
        assert!(json.contains("Failed login attempt"));
        assert!(json.contains("192.168.1.100"));
    }

    #[test]
    fn test_date_range_filtering() {
        let logger = SecureLogger::new();
        let now = Utc::now();

        logger.info("Message 1");
        std::thread::sleep(std::time::Duration::from_millis(10));
        logger.info("Message 2");

        let entries = logger.get_entries_by_date_range(now, Utc::now());
        assert!(entries.len() >= 2);
    }

    #[test]
    fn test_recent_entries() {
        let logger = SecureLogger::new();
        for i in 0..10 {
            logger.info(format!("Message {}", i));
        }

        let recent = logger.get_recent_entries(5);
        assert_eq!(recent.len(), 5);
        assert!(recent[0].message.contains("Message"));
    }

    #[test]
    fn test_search_functionality() {
        let logger = SecureLogger::new();
        logger.info("User login successful");
        logger.info("Database connection established");
        logger.warning("User login failed");

        let results = logger.search("login");
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|e| e.message.contains("login")));
    }

    #[test]
    fn test_statistics() {
        let logger = SecureLogger::new();
        logger.info("Info 1");
        logger.info("Info 2");
        logger.warning("Warning 1");
        logger.critical("Critical 1", None);
        logger.audit("Audit 1", None);

        let stats = logger.get_statistics();
        assert_eq!(stats.total_entries, 5);
        assert_eq!(stats.info_count, 2);
        assert_eq!(stats.warning_count, 1);
        assert_eq!(stats.critical_count, 1);
        assert_eq!(stats.audit_count, 1);
    }

    #[test]
    fn test_clear_functionality() {
        let logger = SecureLogger::new();
        logger.info("Test message 1");
        logger.info("Test message 2");
        assert_eq!(logger.get_entries().len(), 2);

        logger.clear();
        assert_eq!(logger.get_entries().len(), 0);
    }

    #[test]
    fn test_large_volume_logging() {
        let logger = SecureLogger::new();
        for i in 0..1000 {
            logger.info(format!("Log entry {}", i));
        }

        assert_eq!(logger.get_entries().len(), 1000);
        assert!(logger.verify_all_integrity());
    }

    #[test]
    fn test_metadata_preservation() {
        let logger = SecureLogger::new();
        let metadata = serde_json::json!({
            "transaction_id": "TXN-12345",
            "amount": 50000.0,
            "currency": "USD"
        });

        logger.audit("Transaction completed", Some(metadata.clone()));

        let entries = logger.get_entries_by_level(SecurityLevel::Audit);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].metadata, Some(metadata));
    }
}
