//! Logging metrics module for monitoring v2.0
//!
//! Provides detailed metrics and statistics for log analysis.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Logging metrics collector
#[derive(Debug, Clone)]
pub struct LogMetrics {
    total_logs: u64,
    logs_by_level: HashMap<String, u64>,
    logs_by_category: HashMap<String, u64>,
    bytes_logged: u64,
    errors_count: u64,
    rate_limited_count: u64,
    redacted_count: u64,
    encrypted_count: u64,
    start_time: DateTime<Utc>,
    last_log_time: Option<DateTime<Utc>>,
    peak_rate: u64,
    current_rate: u64,
}

impl LogMetrics {
    /// Create a new metrics collector
    pub fn new() -> Self {
        Self {
            total_logs: 0,
            logs_by_level: HashMap::new(),
            logs_by_category: HashMap::new(),
            bytes_logged: 0,
            errors_count: 0,
            rate_limited_count: 0,
            redacted_count: 0,
            encrypted_count: 0,
            start_time: Utc::now(),
            last_log_time: None,
            peak_rate: 0,
            current_rate: 0,
        }
    }

    /// Record a new log entry
    pub fn record_log(&mut self, level: &str, category: Option<&str>, bytes: usize) {
        self.total_logs += 1;
        self.bytes_logged += bytes as u64;
        self.last_log_time = Some(Utc::now());

        *self.logs_by_level.entry(level.to_string()).or_insert(0) += 1;

        if let Some(cat) = category {
            *self.logs_by_category.entry(cat.to_string()).or_insert(0) += 1;
        }
    }

    /// Record an error
    pub fn record_error(&mut self) {
        self.errors_count += 1;
    }

    /// Record rate limited event
    pub fn record_rate_limited(&mut self) {
        self.rate_limited_count += 1;
    }

    /// Record redacted log
    pub fn record_redaction(&mut self) {
        self.redacted_count += 1;
    }

    /// Record encrypted log
    pub fn record_encryption(&mut self) {
        self.encrypted_count += 1;
    }

    /// Update current rate
    pub fn update_rate(&mut self, rate: u64) {
        self.current_rate = rate;
        if rate > self.peak_rate {
            self.peak_rate = rate;
        }
    }

    /// Get snapshot of current metrics
    pub fn snapshot(&self) -> MetricsSnapshot {
        let uptime = Utc::now().signed_duration_since(self.start_time);
        let uptime_secs = uptime.num_seconds().max(1) as f64;

        MetricsSnapshot {
            total_logs: self.total_logs,
            logs_by_level: self.logs_by_level.clone(),
            logs_by_category: self.logs_by_category.clone(),
            bytes_logged: self.bytes_logged,
            errors_count: self.errors_count,
            rate_limited_count: self.rate_limited_count,
            redacted_count: self.redacted_count,
            encrypted_count: self.encrypted_count,
            uptime_seconds: uptime.num_seconds() as u64,
            average_rate: self.total_logs as f64 / uptime_secs,
            peak_rate: self.peak_rate,
            current_rate: self.current_rate,
            last_log_time: self.last_log_time,
            snapshot_time: Utc::now(),
        }
    }

    /// Reset metrics
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

impl Default for LogMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of metrics at a point in time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub total_logs: u64,
    pub logs_by_level: HashMap<String, u64>,
    pub logs_by_category: HashMap<String, u64>,
    pub bytes_logged: u64,
    pub errors_count: u64,
    pub rate_limited_count: u64,
    pub redacted_count: u64,
    pub encrypted_count: u64,
    pub uptime_seconds: u64,
    pub average_rate: f64,
    pub peak_rate: u64,
    pub current_rate: u64,
    pub last_log_time: Option<DateTime<Utc>>,
    pub snapshot_time: DateTime<Utc>,
}

impl MetricsSnapshot {
    /// Export metrics as JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Get human-readable summary
    pub fn summary(&self) -> String {
        format!(
            "Logs: {} | Errors: {} | Rate Limited: {} | Redacted: {} | Encrypted: {} | Avg Rate: {:.2}/s",
            self.total_logs,
            self.errors_count,
            self.rate_limited_count,
            self.redacted_count,
            self.encrypted_count,
            self.average_rate
        )
    }

    /// Get bytes logged in human-readable format
    pub fn bytes_human_readable(&self) -> String {
        let bytes = self.bytes_logged;
        if bytes < 1024 {
            format!("{} B", bytes)
        } else if bytes < 1024 * 1024 {
            format!("{:.2} KB", bytes as f64 / 1024.0)
        } else if bytes < 1024 * 1024 * 1024 {
            format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
        } else {
            format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
        }
    }

    /// Get percentage of errors
    pub fn error_percentage(&self) -> f64 {
        if self.total_logs == 0 {
            0.0
        } else {
            (self.errors_count as f64 / self.total_logs as f64) * 100.0
        }
    }

    /// Get percentage of redacted logs
    pub fn redaction_percentage(&self) -> f64 {
        if self.total_logs == 0 {
            0.0
        } else {
            (self.redacted_count as f64 / self.total_logs as f64) * 100.0
        }
    }
}

/// Metrics aggregator for multiple loggers
pub struct MetricsAggregator {
    snapshots: Vec<MetricsSnapshot>,
}

impl MetricsAggregator {
    /// Create a new aggregator
    pub fn new() -> Self {
        Self {
            snapshots: Vec::new(),
        }
    }

    /// Add a metrics snapshot
    pub fn add_snapshot(&mut self, snapshot: MetricsSnapshot) {
        self.snapshots.push(snapshot);
    }

    /// Get combined metrics
    pub fn aggregate(&self) -> AggregatedMetrics {
        let total_logs: u64 = self.snapshots.iter().map(|s| s.total_logs).sum();
        let total_bytes: u64 = self.snapshots.iter().map(|s| s.bytes_logged).sum();
        let total_errors: u64 = self.snapshots.iter().map(|s| s.errors_count).sum();
        let total_rate_limited: u64 = self.snapshots.iter().map(|s| s.rate_limited_count).sum();
        let peak_rate: u64 = self.snapshots.iter().map(|s| s.peak_rate).max().unwrap_or(0);

        AggregatedMetrics {
            logger_count: self.snapshots.len(),
            total_logs,
            total_bytes,
            total_errors,
            total_rate_limited,
            peak_rate,
        }
    }
}

impl Default for MetricsAggregator {
    fn default() -> Self {
        Self::new()
    }
}

/// Aggregated metrics from multiple sources
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedMetrics {
    pub logger_count: usize,
    pub total_logs: u64,
    pub total_bytes: u64,
    pub total_errors: u64,
    pub total_rate_limited: u64,
    pub peak_rate: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_recording() {
        let mut metrics = LogMetrics::new();

        metrics.record_log("INFO", Some("auth"), 100);
        metrics.record_log("ERROR", Some("auth"), 200);
        metrics.record_log("INFO", None, 50);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.total_logs, 3);
        assert_eq!(snapshot.bytes_logged, 350);
        assert_eq!(snapshot.logs_by_level.get("INFO"), Some(&2));
        assert_eq!(snapshot.logs_by_level.get("ERROR"), Some(&1));
        assert_eq!(snapshot.logs_by_category.get("auth"), Some(&2));
    }

    #[test]
    fn test_error_recording() {
        let mut metrics = LogMetrics::new();

        metrics.record_error();
        metrics.record_error();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.errors_count, 2);
    }

    #[test]
    fn test_rate_limiting_recording() {
        let mut metrics = LogMetrics::new();

        metrics.record_rate_limited();
        metrics.record_rate_limited();
        metrics.record_rate_limited();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.rate_limited_count, 3);
    }

    #[test]
    fn test_bytes_human_readable() {
        let mut metrics = LogMetrics::new();

        metrics.record_log("INFO", None, 500);
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.bytes_human_readable(), "500 B");

        let mut metrics2 = LogMetrics::new();
        for _ in 0..1000 {
            metrics2.record_log("INFO", None, 1024);
        }
        let snapshot2 = metrics2.snapshot();
        assert!(snapshot2.bytes_human_readable().contains("KB") || snapshot2.bytes_human_readable().contains("MB"));
    }

    #[test]
    fn test_summary() {
        let mut metrics = LogMetrics::new();

        for _ in 0..100 {
            metrics.record_log("INFO", None, 100);
        }
        metrics.record_error();

        let snapshot = metrics.snapshot();
        let summary = snapshot.summary();
        assert!(summary.contains("100"));
        assert!(summary.contains("Errors: 1"));
    }

    #[test]
    fn test_aggregator() {
        let mut agg = MetricsAggregator::new();

        let mut metrics1 = LogMetrics::new();
        metrics1.record_log("INFO", None, 100);
        agg.add_snapshot(metrics1.snapshot());

        let mut metrics2 = LogMetrics::new();
        metrics2.record_log("INFO", None, 200);
        metrics2.record_log("ERROR", None, 150);
        agg.add_snapshot(metrics2.snapshot());

        let aggregated = agg.aggregate();
        assert_eq!(aggregated.logger_count, 2);
        assert_eq!(aggregated.total_logs, 3);
        assert_eq!(aggregated.total_bytes, 450);
    }

    #[test]
    fn test_error_percentage() {
        let mut metrics = LogMetrics::new();

        for _ in 0..100 {
            metrics.record_log("INFO", None, 10);
        }
        for _ in 0..10 {
            metrics.record_error();
        }

        let snapshot = metrics.snapshot();
        assert!((snapshot.error_percentage() - 10.0).abs() < 0.01);
    }

    #[test]
    fn test_reset() {
        let mut metrics = LogMetrics::new();

        metrics.record_log("INFO", None, 100);
        metrics.record_error();

        metrics.reset();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.total_logs, 0);
        assert_eq!(snapshot.errors_count, 0);
    }
}
