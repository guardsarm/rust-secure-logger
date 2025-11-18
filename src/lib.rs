//! # Rust Secure Logger
//!
//! A production-ready, memory-safe logging library for financial systems and critical infrastructure.
//!
//! ## Features
//!
//! - **Memory Safety**: Built with Rust's ownership system to prevent buffer overflows and memory corruption
//! - **Thread Safety**: Concurrent logging without data races using Arc<Mutex>
//! - **Cryptographic Integrity**: SHA-256 hashing for tamper detection
//! - **File Persistence**: Log rotation and disk persistence
//! - **SIEM Integration**: CEF, LEEF, Syslog, and Splunk HEC formats
//! - **Compliance Reporting**: SOX, GLBA, PCI-DSS automated reports
//! - **Audit Trail**: Immutable log entries with timestamps
//!
//! ## Alignment with Federal Guidance
//!
//! This library aligns with 2024 CISA/FBI guidance recommending memory-safe
//! languages for critical infrastructure to eliminate 70% of security vulnerabilities.
//!
//! ## Quick Start
//!
//! ```rust
//! use rust_secure_logger::SecureLogger;
//!
//! let logger = SecureLogger::new();
//! logger.info("Application started");
//! logger.audit("User authentication successful", Some(serde_json::json!({
//!     "user_id": "12345",
//!     "ip_address": "192.168.1.100"
//! })));
//! ```

pub mod entry;
pub mod persistence;
pub mod formats;
pub mod compliance;

pub use entry::{LogEntry, SecurityLevel};
pub use persistence::{LogWriter, PersistenceConfig};
pub use formats::{CEFFormatter, LEEFFormatter, SyslogFormatter, SplunkFormatter};
pub use compliance::{ComplianceFramework, ComplianceReport, ComplianceReporter};

use std::sync::{Arc, Mutex};

/// Thread-safe secure logger for financial systems
#[derive(Clone)]
pub struct SecureLogger {
    entries: Arc<Mutex<Vec<LogEntry>>>,
    source: Option<String>,
}

impl SecureLogger {
    /// Create a new secure logger instance
    pub fn new() -> Self {
        Self {
            entries: Arc::new(Mutex::new(Vec::new())),
            source: None,
        }
    }

    /// Create a logger with a source identifier (hostname, service name)
    pub fn with_source(source: impl Into<String>) -> Self {
        Self {
            entries: Arc::new(Mutex::new(Vec::new())),
            source: Some(source.into()),
        }
    }

    /// Log an informational message
    pub fn info(&self, message: impl Into<String>) {
        self.log(SecurityLevel::Info, message.into(), None, None);
    }

    /// Log a warning
    pub fn warning(&self, message: impl Into<String>) {
        self.log(SecurityLevel::Warning, message.into(), None, None);
    }

    /// Log a security event with optional metadata
    pub fn security_event(&self, message: impl Into<String>, metadata: Option<serde_json::Value>) {
        self.log(SecurityLevel::SecurityEvent, message.into(), metadata, None);
    }

    /// Log a critical security incident
    pub fn critical(&self, message: impl Into<String>, metadata: Option<serde_json::Value>) {
        self.log(SecurityLevel::Critical, message.into(), metadata, None);
    }

    /// Log an audit trail entry (for financial transactions, access control, etc.)
    pub fn audit(&self, message: impl Into<String>, metadata: Option<serde_json::Value>) {
        self.log(SecurityLevel::Audit, message.into(), metadata, None);
    }

    /// Log with category
    pub fn log_with_category(
        &self,
        level: SecurityLevel,
        message: impl Into<String>,
        metadata: Option<serde_json::Value>,
        category: impl Into<String>,
    ) {
        self.log(level, message.into(), metadata, Some(category.into()));
    }

    /// Internal logging function
    fn log(&self, level: SecurityLevel, message: String, metadata: Option<serde_json::Value>, category: Option<String>) {
        let entry = LogEntry::new_with_context(level, message, metadata, self.source.clone(), category);
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

    /// Get entries by category
    pub fn get_entries_by_category(&self, category: &str) -> Vec<LogEntry> {
        let entries = self.entries.lock().unwrap();
        entries
            .iter()
            .filter(|e| e.category.as_deref() == Some(category))
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

    /// Export logs in CEF format (for ArcSight)
    pub fn export_cef(&self) -> Vec<String> {
        let entries = self.entries.lock().unwrap();
        entries.iter().map(|e| CEFFormatter::format(e)).collect()
    }

    /// Export logs in LEEF format (for QRadar)
    pub fn export_leef(&self) -> Vec<String> {
        let entries = self.entries.lock().unwrap();
        entries.iter().map(|e| LEEFFormatter::format(e)).collect()
    }

    /// Export logs in Syslog format
    pub fn export_syslog(&self) -> Vec<String> {
        let entries = self.entries.lock().unwrap();
        entries.iter().map(|e| SyslogFormatter::format(e)).collect()
    }

    /// Export logs in Splunk HEC format
    pub fn export_splunk(&self) -> Vec<String> {
        let entries = self.entries.lock().unwrap();
        entries.iter().map(|e| SplunkFormatter::format(e)).collect()
    }

    /// Get count of entries by security level
    pub fn count_by_level(&self, level: SecurityLevel) -> usize {
        let entries = self.entries.lock().unwrap();
        entries.iter().filter(|e| e.level == level).count()
    }

    /// Get entries within a date range
    pub fn get_entries_by_date_range(
        &self,
        start: chrono::DateTime<chrono::Utc>,
        end: chrono::DateTime<chrono::Utc>,
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

    /// Generate SOX compliance report
    pub fn generate_sox_report(
        &self,
        period_start: chrono::DateTime<chrono::Utc>,
        period_end: chrono::DateTime<chrono::Utc>,
    ) -> ComplianceReport {
        let entries = self.get_entries();
        ComplianceReporter::generate_sox_report(&entries, period_start, period_end)
    }

    /// Generate PCI-DSS compliance report
    pub fn generate_pci_report(
        &self,
        period_start: chrono::DateTime<chrono::Utc>,
        period_end: chrono::DateTime<chrono::Utc>,
    ) -> ComplianceReport {
        let entries = self.get_entries();
        ComplianceReporter::generate_pci_report(&entries, period_start, period_end)
    }

    /// Generate GLBA compliance report
    pub fn generate_glba_report(
        &self,
        period_start: chrono::DateTime<chrono::Utc>,
        period_end: chrono::DateTime<chrono::Utc>,
    ) -> ComplianceReport {
        let entries = self.get_entries();
        ComplianceReporter::generate_glba_report(&entries, period_start, period_end)
    }
}

/// Statistics about log entries
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
    fn test_cef_export() {
        let logger = SecureLogger::new();
        logger.security_event("Failed login attempt", Some(serde_json::json!({
            "username": "admin"
        })));

        let cef_logs = logger.export_cef();
        assert_eq!(cef_logs.len(), 1);
        assert!(cef_logs[0].starts_with("CEF:0|"));
    }

    #[test]
    fn test_leef_export() {
        let logger = SecureLogger::new();
        logger.critical("Security breach detected", None);

        let leef_logs = logger.export_leef();
        assert_eq!(leef_logs.len(), 1);
        assert!(leef_logs[0].starts_with("LEEF:2.0|"));
    }

    #[test]
    fn test_compliance_reporting() {
        let logger = SecureLogger::new();
        logger.audit("Transaction processed", Some(serde_json::json!({
            "amount": 1000,
            "currency": "USD"
        })));

        let start = chrono::Utc::now() - chrono::Duration::hours(1);
        let end = chrono::Utc::now();

        let sox_report = logger.generate_sox_report(start, end);
        assert_eq!(sox_report.framework, ComplianceFramework::SOX);
        assert_eq!(sox_report.audit_events, 1);
    }

    #[test]
    fn test_logger_with_source() {
        let logger = SecureLogger::with_source("web-server-01");
        logger.info("Server started");

        let entries = logger.get_entries();
        assert_eq!(entries[0].source, Some("web-server-01".to_string()));
    }

    #[test]
    fn test_category_filtering() {
        let logger = SecureLogger::new();
        logger.log_with_category(
            SecurityLevel::SecurityEvent,
            "Login failed",
            None,
            "authentication"
        );
        logger.log_with_category(
            SecurityLevel::Info,
            "Page loaded",
            None,
            "web"
        );

        let auth_events = logger.get_entries_by_category("authentication");
        assert_eq!(auth_events.len(), 1);
        assert_eq!(auth_events[0].message, "Login failed");
    }
}
