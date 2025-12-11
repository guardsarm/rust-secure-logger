//! Compliance reporting for SOX, GLBA, PCI-DSS

use crate::entry::{LogEntry, SecurityLevel};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Compliance framework types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComplianceFramework {
    /// Sarbanes-Oxley Act - Financial reporting controls
    SOX,
    /// Gramm-Leach-Bliley Act - Financial privacy
    GLBA,
    /// Payment Card Industry Data Security Standard
    PCIDSS,
    /// HIPAA - Healthcare data privacy
    HIPAA,
    /// General Data Protection Regulation
    GDPR,
}

/// Compliance report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    /// Framework being reported on
    pub framework: ComplianceFramework,
    /// Report generation timestamp
    pub generated_at: DateTime<Utc>,
    /// Report period start
    pub period_start: DateTime<Utc>,
    /// Report period end
    pub period_end: DateTime<Utc>,
    /// Total events in period
    pub total_events: usize,
    /// Audit events (high importance)
    pub audit_events: usize,
    /// Security events
    pub security_events: usize,
    /// Critical events
    pub critical_events: usize,
    /// Integrity verification status
    pub integrity_verified: bool,
    /// Failed integrity checks
    pub integrity_failures: usize,
    /// Specific compliance findings
    pub findings: Vec<ComplianceFinding>,
}

/// Individual compliance finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceFinding {
    /// Finding severity
    pub severity: FindingSeverity,
    /// Control area affected
    pub control_area: String,
    /// Description of finding
    pub description: String,
    /// Evidence (log entry IDs or samples)
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Compliance report generator
pub struct ComplianceReporter;

impl ComplianceReporter {
    /// Generate SOX compliance report
    pub fn generate_sox_report(
        entries: &[LogEntry],
        period_start: DateTime<Utc>,
        period_end: DateTime<Utc>,
    ) -> ComplianceReport {
        let filtered: Vec<_> = entries
            .iter()
            .filter(|e| e.timestamp >= period_start && e.timestamp <= period_end)
            .collect();

        let total_events = filtered.len();
        let audit_events = filtered
            .iter()
            .filter(|e| e.level == SecurityLevel::Audit)
            .count();
        let security_events = filtered
            .iter()
            .filter(|e| e.level == SecurityLevel::SecurityEvent)
            .count();
        let critical_events = filtered
            .iter()
            .filter(|e| e.level == SecurityLevel::Critical)
            .count();

        let integrity_failures = filtered.iter().filter(|e| !e.verify_integrity()).count();
        let integrity_verified = integrity_failures == 0;

        let mut findings = Vec::new();

        // SOX Section 404 - Internal Controls
        if audit_events == 0 {
            findings.push(ComplianceFinding {
                severity: FindingSeverity::High,
                control_area: "SOX Section 404 - Audit Trail".to_string(),
                description: "No audit trail events recorded during reporting period".to_string(),
                evidence: vec![],
            });
        }

        // Integrity failures
        if integrity_failures > 0 {
            findings.push(ComplianceFinding {
                severity: FindingSeverity::Critical,
                control_area: "SOX Section 404 - Data Integrity".to_string(),
                description: format!(
                    "{} log entries failed integrity verification",
                    integrity_failures
                ),
                evidence: vec![],
            });
        }

        // Critical events requiring review
        if critical_events > 0 {
            findings.push(ComplianceFinding {
                severity: FindingSeverity::High,
                control_area: "SOX Section 302 - Management Certification".to_string(),
                description: format!(
                    "{} critical security events require management review",
                    critical_events
                ),
                evidence: vec![],
            });
        }

        ComplianceReport {
            framework: ComplianceFramework::SOX,
            generated_at: Utc::now(),
            period_start,
            period_end,
            total_events,
            audit_events,
            security_events,
            critical_events,
            integrity_verified,
            integrity_failures,
            findings,
        }
    }

    /// Generate PCI-DSS compliance report
    pub fn generate_pci_report(
        entries: &[LogEntry],
        period_start: DateTime<Utc>,
        period_end: DateTime<Utc>,
    ) -> ComplianceReport {
        let filtered: Vec<_> = entries
            .iter()
            .filter(|e| e.timestamp >= period_start && e.timestamp <= period_end)
            .collect();

        let total_events = filtered.len();
        let audit_events = filtered
            .iter()
            .filter(|e| e.level == SecurityLevel::Audit)
            .count();
        let security_events = filtered
            .iter()
            .filter(|e| e.level == SecurityLevel::SecurityEvent)
            .count();
        let critical_events = filtered
            .iter()
            .filter(|e| e.level == SecurityLevel::Critical)
            .count();

        let integrity_failures = filtered.iter().filter(|e| !e.verify_integrity()).count();
        let integrity_verified = integrity_failures == 0;

        let mut findings = Vec::new();

        // PCI-DSS Requirement 10.2 - Audit trail for all access
        if audit_events == 0 {
            findings.push(ComplianceFinding {
                severity: FindingSeverity::Critical,
                control_area: "PCI-DSS Requirement 10.2".to_string(),
                description: "Audit trail requirements not met - no access events logged"
                    .to_string(),
                evidence: vec![],
            });
        }

        // PCI-DSS Requirement 10.5 - Log integrity
        if !integrity_verified {
            findings.push(ComplianceFinding {
                severity: FindingSeverity::Critical,
                control_area: "PCI-DSS Requirement 10.5".to_string(),
                description: "Log file integrity protection failure detected".to_string(),
                evidence: vec![],
            });
        }

        // PCI-DSS Requirement 10.6 - Daily log review
        if security_events > 0 || critical_events > 0 {
            findings.push(ComplianceFinding {
                severity: FindingSeverity::Medium,
                control_area: "PCI-DSS Requirement 10.6".to_string(),
                description: format!(
                    "{} security events require daily review",
                    security_events + critical_events
                ),
                evidence: vec![],
            });
        }

        ComplianceReport {
            framework: ComplianceFramework::PCIDSS,
            generated_at: Utc::now(),
            period_start,
            period_end,
            total_events,
            audit_events,
            security_events,
            critical_events,
            integrity_verified,
            integrity_failures,
            findings,
        }
    }

    /// Generate GLBA compliance report
    pub fn generate_glba_report(
        entries: &[LogEntry],
        period_start: DateTime<Utc>,
        period_end: DateTime<Utc>,
    ) -> ComplianceReport {
        let filtered: Vec<_> = entries
            .iter()
            .filter(|e| e.timestamp >= period_start && e.timestamp <= period_end)
            .collect();

        let total_events = filtered.len();
        let audit_events = filtered
            .iter()
            .filter(|e| e.level == SecurityLevel::Audit)
            .count();
        let security_events = filtered
            .iter()
            .filter(|e| e.level == SecurityLevel::SecurityEvent)
            .count();
        let critical_events = filtered
            .iter()
            .filter(|e| e.level == SecurityLevel::Critical)
            .count();

        let integrity_failures = filtered.iter().filter(|e| !e.verify_integrity()).count();
        let integrity_verified = integrity_failures == 0;

        let mut findings = Vec::new();

        // GLBA Safeguards Rule - Access controls
        let access_events = filtered
            .iter()
            .filter(|e| {
                e.category
                    .as_ref()
                    .is_some_and(|c| c.contains("authentication") || c.contains("access"))
            })
            .count();

        if access_events == 0 {
            findings.push(ComplianceFinding {
                severity: FindingSeverity::Medium,
                control_area: "GLBA Safeguards Rule - Access Controls".to_string(),
                description: "No access control events logged".to_string(),
                evidence: vec![],
            });
        }

        ComplianceReport {
            framework: ComplianceFramework::GLBA,
            generated_at: Utc::now(),
            period_start,
            period_end,
            total_events,
            audit_events,
            security_events,
            critical_events,
            integrity_verified,
            integrity_failures,
            findings,
        }
    }

    /// Export report as JSON
    pub fn export_json(report: &ComplianceReport) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(report)
    }

    /// Export report as CSV summary
    pub fn export_csv(report: &ComplianceReport) -> String {
        let mut csv = String::from("Metric,Value\n");
        csv.push_str(&format!("Framework,{:?}\n", report.framework));
        csv.push_str(&format!("Generated At,{}\n", report.generated_at));
        csv.push_str(&format!("Period Start,{}\n", report.period_start));
        csv.push_str(&format!("Period End,{}\n", report.period_end));
        csv.push_str(&format!("Total Events,{}\n", report.total_events));
        csv.push_str(&format!("Audit Events,{}\n", report.audit_events));
        csv.push_str(&format!("Security Events,{}\n", report.security_events));
        csv.push_str(&format!("Critical Events,{}\n", report.critical_events));
        csv.push_str(&format!(
            "Integrity Verified,{}\n",
            report.integrity_verified
        ));
        csv.push_str(&format!(
            "Integrity Failures,{}\n",
            report.integrity_failures
        ));
        csv.push_str(&format!("Total Findings,{}\n", report.findings.len()));
        csv
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_entries() -> Vec<LogEntry> {
        vec![
            LogEntry::new(SecurityLevel::Audit, "User login".to_string(), None),
            LogEntry::new(SecurityLevel::Info, "System start".to_string(), None),
            LogEntry::new_with_context(
                SecurityLevel::SecurityEvent,
                "Failed login".to_string(),
                None,
                None,
                Some("authentication".to_string()),
            ),
            LogEntry::new(SecurityLevel::Critical, "Breach detected".to_string(), None),
        ]
    }

    #[test]
    fn test_sox_report_generation() {
        let entries = create_test_entries();
        let start = Utc::now() - chrono::Duration::hours(1);
        let end = Utc::now();

        let report = ComplianceReporter::generate_sox_report(&entries, start, end);

        assert_eq!(report.framework, ComplianceFramework::SOX);
        assert_eq!(report.total_events, 4);
        assert_eq!(report.audit_events, 1);
        assert_eq!(report.security_events, 1);
        assert_eq!(report.critical_events, 1);
    }

    #[test]
    fn test_pci_report_generation() {
        let entries = create_test_entries();
        let start = Utc::now() - chrono::Duration::hours(1);
        let end = Utc::now();

        let report = ComplianceReporter::generate_pci_report(&entries, start, end);

        assert_eq!(report.framework, ComplianceFramework::PCIDSS);
        assert!(report.integrity_verified);
    }

    #[test]
    fn test_glba_report_generation() {
        let entries = create_test_entries();
        let start = Utc::now() - chrono::Duration::hours(1);
        let end = Utc::now();

        let report = ComplianceReporter::generate_glba_report(&entries, start, end);

        assert_eq!(report.framework, ComplianceFramework::GLBA);
        assert!(report.total_events > 0);
    }

    #[test]
    fn test_json_export() {
        let entries = create_test_entries();
        let start = Utc::now() - chrono::Duration::hours(1);
        let end = Utc::now();

        let report = ComplianceReporter::generate_sox_report(&entries, start, end);
        let json = ComplianceReporter::export_json(&report).unwrap();

        assert!(json.contains("SOX"));
        assert!(json.contains("total_events"));
    }

    #[test]
    fn test_csv_export() {
        let entries = create_test_entries();
        let start = Utc::now() - chrono::Duration::hours(1);
        let end = Utc::now();

        let report = ComplianceReporter::generate_sox_report(&entries, start, end);
        let csv = ComplianceReporter::export_csv(&report);

        assert!(csv.contains("Framework,SOX"));
        assert!(csv.contains("Total Events,4"));
    }
}
