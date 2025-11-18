//! Log entry structure with cryptographic integrity

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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

impl SecurityLevel {
    /// Get string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            SecurityLevel::Info => "INFO",
            SecurityLevel::Warning => "WARNING",
            SecurityLevel::SecurityEvent => "SECURITY_EVENT",
            SecurityLevel::Critical => "CRITICAL",
            SecurityLevel::Audit => "AUDIT",
        }
    }

    /// Get numeric severity (for SIEM integration)
    pub fn severity(&self) -> u8 {
        match self {
            SecurityLevel::Info => 1,
            SecurityLevel::Warning => 3,
            SecurityLevel::SecurityEvent => 5,
            SecurityLevel::Critical => 8,
            SecurityLevel::Audit => 6,
        }
    }
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
    /// Optional source identifier (hostname, service name)
    pub source: Option<String>,
    /// Optional category for filtering
    pub category: Option<String>,
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
            source: None,
            category: None,
        };
        entry.integrity_hash = entry.calculate_hash();
        entry
    }

    /// Create a new log entry with source and category
    pub fn new_with_context(
        level: SecurityLevel,
        message: String,
        metadata: Option<serde_json::Value>,
        source: Option<String>,
        category: Option<String>,
    ) -> Self {
        let timestamp = Utc::now();
        let mut entry = Self {
            timestamp,
            level,
            message,
            metadata,
            integrity_hash: String::new(),
            source,
            category,
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
        if let Some(ref source) = self.source {
            hasher.update(source.as_bytes());
        }
        if let Some(ref category) = self.category {
            hasher.update(category.as_bytes());
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

    /// Serialize to pretty JSON
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Get formatted log line for file output
    pub fn to_log_line(&self) -> String {
        format!(
            "[{}] [{}] {} {}",
            self.timestamp.to_rfc3339(),
            self.level.as_str(),
            self.message,
            if let Some(ref meta) = self.metadata {
                format!("| metadata: {}", meta)
            } else {
                String::new()
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_level_string() {
        assert_eq!(SecurityLevel::Info.as_str(), "INFO");
        assert_eq!(SecurityLevel::Critical.as_str(), "CRITICAL");
    }

    #[test]
    fn test_security_level_severity() {
        assert_eq!(SecurityLevel::Info.severity(), 1);
        assert_eq!(SecurityLevel::Critical.severity(), 8);
    }

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
        entry.message = "Tampered message".to_string();
        assert!(!entry.verify_integrity());
    }

    #[test]
    fn test_entry_with_context() {
        let entry = LogEntry::new_with_context(
            SecurityLevel::SecurityEvent,
            "Login failed".to_string(),
            None,
            Some("web-server-01".to_string()),
            Some("authentication".to_string()),
        );
        assert_eq!(entry.source, Some("web-server-01".to_string()));
        assert_eq!(entry.category, Some("authentication".to_string()));
        assert!(entry.verify_integrity());
    }

    #[test]
    fn test_to_log_line() {
        let entry = LogEntry::new(SecurityLevel::Warning, "High CPU usage".to_string(), None);
        let log_line = entry.to_log_line();
        assert!(log_line.contains("WARNING"));
        assert!(log_line.contains("High CPU usage"));
    }
}
