//! SIEM export formats (CEF, LEEF, Syslog)

use crate::entry::{LogEntry, SecurityLevel};

/// Common Event Format (CEF) - ArcSight standard
pub struct CEFFormatter;

impl CEFFormatter {
    /// Convert log entry to CEF format
    /// Format: CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|Extension
    pub fn format(entry: &LogEntry) -> String {
        let device_vendor = "GuardsArm";
        let device_product = "SecureLogger";
        let device_version = "1.0";
        let event_class_id = Self::get_event_class_id(&entry.level);
        let name = &entry.message;
        let severity = entry.level.severity();

        // Build extension fields
        let mut extensions = Vec::new();
        extensions.push(format!("rt={}", entry.timestamp.timestamp_millis()));

        if let Some(ref source) = entry.source {
            extensions.push(format!("shost={}", source));
        }

        if let Some(ref category) = entry.category {
            extensions.push(format!("cat={}", category));
        }

        if let Some(ref meta) = entry.metadata {
            extensions.push(format!("cs1={}", meta));
            extensions.push("cs1Label=metadata".to_string());
        }

        extensions.push(format!("msg={}", entry.message));

        format!(
            "CEF:0|{}|{}|{}|{}|{}|{}|{}",
            device_vendor,
            device_product,
            device_version,
            event_class_id,
            name,
            severity,
            extensions.join(" ")
        )
    }

    fn get_event_class_id(level: &SecurityLevel) -> &'static str {
        match level {
            SecurityLevel::Info => "INFO-001",
            SecurityLevel::Warning => "WARN-002",
            SecurityLevel::SecurityEvent => "SEC-003",
            SecurityLevel::Critical => "CRIT-004",
            SecurityLevel::Audit => "AUDIT-005",
        }
    }
}

/// Log Event Extended Format (LEEF) - IBM QRadar standard
pub struct LEEFFormatter;

impl LEEFFormatter {
    /// Convert log entry to LEEF format
    /// Format: LEEF:Version|Vendor|Product|Version|EventID|Delimiter|Key=Value pairs
    pub fn format(entry: &LogEntry) -> String {
        let vendor = "GuardsArm";
        let product = "SecureLogger";
        let version = "1.0";
        let event_id = Self::get_event_id(&entry.level);
        let delimiter = "\t";

        let mut fields = Vec::new();
        fields.push(format!("devTime={}", entry.timestamp.to_rfc3339()));
        fields.push(format!("severity={}", entry.level.severity()));
        fields.push(format!("cat={}", entry.level.as_str()));
        fields.push(format!("msg={}", entry.message));

        if let Some(ref source) = entry.source {
            fields.push(format!("src={}", source));
        }

        if let Some(ref category) = entry.category {
            fields.push(format!("eventCategory={}", category));
        }

        if let Some(ref meta) = entry.metadata {
            fields.push(format!("usrName={}", meta));
        }

        format!(
            "LEEF:2.0|{}|{}|{}|{}|{}|{}",
            vendor,
            product,
            version,
            event_id,
            delimiter,
            fields.join(delimiter)
        )
    }

    fn get_event_id(level: &SecurityLevel) -> &'static str {
        match level {
            SecurityLevel::Info => "1000",
            SecurityLevel::Warning => "2000",
            SecurityLevel::SecurityEvent => "3000",
            SecurityLevel::Critical => "4000",
            SecurityLevel::Audit => "5000",
        }
    }
}

/// Syslog RFC 5424 format
pub struct SyslogFormatter;

impl SyslogFormatter {
    /// Convert log entry to Syslog RFC 5424 format
    pub fn format(entry: &LogEntry) -> String {
        let priority = Self::calculate_priority(&entry.level);
        let version = 1;
        let timestamp = entry.timestamp.to_rfc3339();
        let hostname = entry.source.as_deref().unwrap_or("-");
        let app_name = "SecureLogger";
        let proc_id = std::process::id();
        let msg_id = entry.level.as_str();

        // Structured data
        let structured_data = if let Some(ref meta) = entry.metadata {
            format!(
                "[metadata@32473 data=\"{}\"]",
                meta.to_string().replace('"', "\\\"")
            )
        } else {
            "-".to_string()
        };

        format!(
            "<{}>{} {} {} {} {} {} {} {}",
            priority,
            version,
            timestamp,
            hostname,
            app_name,
            proc_id,
            msg_id,
            structured_data,
            entry.message
        )
    }

    fn calculate_priority(level: &SecurityLevel) -> u8 {
        // Facility: 16 (local use 0)
        // Severity mapping
        let severity = match level {
            SecurityLevel::Info => 6,          // Informational
            SecurityLevel::Warning => 4,       // Warning
            SecurityLevel::SecurityEvent => 2, // Critical
            SecurityLevel::Critical => 1,      // Alert
            SecurityLevel::Audit => 5,         // Notice
        };
        (16 * 8) + severity
    }
}

/// Splunk HEC (HTTP Event Collector) format
pub struct SplunkFormatter;

impl SplunkFormatter {
    /// Convert log entry to Splunk HEC JSON format
    pub fn format(entry: &LogEntry) -> String {
        let event = serde_json::json!({
            "time": entry.timestamp.timestamp(),
            "host": entry.source.as_ref().unwrap_or(&"unknown".to_string()),
            "source": "secure_logger",
            "sourcetype": "_json",
            "event": {
                "level": entry.level.as_str(),
                "message": entry.message,
                "severity": entry.level.severity(),
                "category": entry.category,
                "metadata": entry.metadata,
                "integrity_hash": entry.integrity_hash,
            }
        });

        event.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_entry() -> LogEntry {
        LogEntry::new_with_context(
            SecurityLevel::SecurityEvent,
            "Failed login attempt".to_string(),
            Some(serde_json::json!({"username": "admin", "ip": "192.168.1.100"})),
            Some("web-server-01".to_string()),
            Some("authentication".to_string()),
        )
    }

    #[test]
    fn test_cef_format() {
        let entry = create_test_entry();
        let cef = CEFFormatter::format(&entry);

        assert!(cef.starts_with("CEF:0|"));
        assert!(cef.contains("GuardsArm"));
        assert!(cef.contains("SecureLogger"));
        assert!(cef.contains("SEC-003"));
        assert!(cef.contains("Failed login attempt"));
    }

    #[test]
    fn test_leef_format() {
        let entry = create_test_entry();
        let leef = LEEFFormatter::format(&entry);

        assert!(leef.starts_with("LEEF:2.0|"));
        assert!(leef.contains("GuardsArm"));
        assert!(leef.contains("SecureLogger"));
        assert!(leef.contains("3000"));
        assert!(leef.contains("Failed login attempt"));
    }

    #[test]
    fn test_syslog_format() {
        let entry = create_test_entry();
        let syslog = SyslogFormatter::format(&entry);

        assert!(syslog.starts_with("<130>1")); // Priority 130, version 1
        assert!(syslog.contains("SecureLogger"));
        assert!(syslog.contains("Failed login attempt"));
    }

    #[test]
    fn test_splunk_format() {
        let entry = create_test_entry();
        let splunk = SplunkFormatter::format(&entry);

        assert!(splunk.contains("\"source\":\"secure_logger\""));
        assert!(splunk.contains("\"level\":\"SECURITY_EVENT\""));
        assert!(splunk.contains("Failed login attempt"));
    }

    #[test]
    fn test_cef_severity_levels() {
        let levels = vec![
            (SecurityLevel::Info, "1"),
            (SecurityLevel::Warning, "3"),
            (SecurityLevel::SecurityEvent, "5"),
            (SecurityLevel::Critical, "8"),
        ];

        for (level, expected_sev) in levels {
            let entry = LogEntry::new(level, "Test".to_string(), None);
            let cef = CEFFormatter::format(&entry);
            assert!(cef.contains(&format!("|{}|", expected_sev)));
        }
    }

    #[test]
    fn test_leef_event_ids() {
        let levels = vec![
            (SecurityLevel::Info, "1000"),
            (SecurityLevel::Warning, "2000"),
            (SecurityLevel::SecurityEvent, "3000"),
            (SecurityLevel::Critical, "4000"),
            (SecurityLevel::Audit, "5000"),
        ];

        for (level, expected_id) in levels {
            let entry = LogEntry::new(level, "Test".to_string(), None);
            let leef = LEEFFormatter::format(&entry);
            assert!(leef.contains(expected_id));
        }
    }
}
