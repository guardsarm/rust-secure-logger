//! Log persistence to disk with rotation and compression

use crate::entry::LogEntry;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;

/// Configuration for log file persistence
#[derive(Debug, Clone)]
pub struct PersistenceConfig {
    /// Directory where log files are stored
    pub log_dir: PathBuf,
    /// Base name for log files
    pub file_prefix: String,
    /// Maximum file size before rotation (bytes)
    pub max_file_size: u64,
    /// Maximum number of rotated files to keep
    pub max_files: usize,
    /// Whether to compress rotated files
    pub compress_rotated: bool,
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        Self {
            log_dir: PathBuf::from("./logs"),
            file_prefix: "secure".to_string(),
            max_file_size: 10 * 1024 * 1024, // 10 MB
            max_files: 10,
            compress_rotated: false,
        }
    }
}

/// Log file writer with rotation support
pub struct LogWriter {
    config: PersistenceConfig,
    current_file: Option<File>,
    current_size: u64,
}

impl LogWriter {
    /// Create a new log writer
    pub fn new(config: PersistenceConfig) -> io::Result<Self> {
        // Create log directory if it doesn't exist
        std::fs::create_dir_all(&config.log_dir)?;

        Ok(Self {
            config,
            current_file: None,
            current_size: 0,
        })
    }

    /// Get current log file path
    fn current_log_path(&self) -> PathBuf {
        self.config
            .log_dir
            .join(format!("{}.log", self.config.file_prefix))
    }

    /// Get rotated log file path
    fn rotated_log_path(&self, index: usize) -> PathBuf {
        self.config
            .log_dir
            .join(format!("{}.{}.log", self.config.file_prefix, index))
    }

    /// Open or create the current log file
    fn ensure_file(&mut self) -> io::Result<&mut File> {
        if self.current_file.is_none() {
            let path = self.current_log_path();
            let file = OpenOptions::new().create(true).append(true).open(&path)?;

            // Get current file size
            self.current_size = file.metadata()?.len();
            self.current_file = Some(file);
        }

        Ok(self.current_file.as_mut().unwrap())
    }

    /// Rotate log files
    fn rotate(&mut self) -> io::Result<()> {
        // Close current file
        self.current_file = None;

        // Rotate existing files
        for i in (1..self.config.max_files).rev() {
            let old_path = if i == 1 {
                self.current_log_path()
            } else {
                self.rotated_log_path(i - 1)
            };

            let new_path = self.rotated_log_path(i);

            if old_path.exists() {
                std::fs::rename(&old_path, &new_path)?;
            }
        }

        // Delete oldest file if we exceeded max_files
        let oldest_path = self.rotated_log_path(self.config.max_files);
        if oldest_path.exists() {
            std::fs::remove_file(oldest_path)?;
        }

        // Reset size counter
        self.current_size = 0;

        Ok(())
    }

    /// Write a log entry to disk
    pub fn write_entry(&mut self, entry: &LogEntry) -> io::Result<()> {
        let log_line = format!("{}\n", entry.to_log_line());
        let bytes = log_line.as_bytes();

        // Check if rotation is needed
        if self.current_size + bytes.len() as u64 > self.config.max_file_size {
            self.rotate()?;
        }

        // Write to file
        let file = self.ensure_file()?;
        file.write_all(bytes)?;
        file.flush()?;

        self.current_size += bytes.len() as u64;

        Ok(())
    }

    /// Write multiple entries
    pub fn write_entries(&mut self, entries: &[LogEntry]) -> io::Result<()> {
        for entry in entries {
            self.write_entry(entry)?;
        }
        Ok(())
    }

    /// Write entry as JSON
    pub fn write_entry_json(&mut self, entry: &LogEntry) -> io::Result<()> {
        let json_line = entry
            .to_json()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let line = format!("{}\n", json_line);
        let bytes = line.as_bytes();

        if self.current_size + bytes.len() as u64 > self.config.max_file_size {
            self.rotate()?;
        }

        let file = self.ensure_file()?;
        file.write_all(bytes)?;
        file.flush()?;

        self.current_size += bytes.len() as u64;

        Ok(())
    }

    /// Flush current file buffer
    pub fn flush(&mut self) -> io::Result<()> {
        if let Some(ref mut file) = self.current_file {
            file.flush()?;
        }
        Ok(())
    }

    /// Get current file size
    pub fn current_file_size(&self) -> u64 {
        self.current_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::SecurityLevel;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_log_writer_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config = PersistenceConfig {
            log_dir: temp_dir.path().to_path_buf(),
            file_prefix: "test".to_string(),
            max_file_size: 1024,
            max_files: 5,
            compress_rotated: false,
        };

        let writer = LogWriter::new(config);
        assert!(writer.is_ok());
    }

    #[test]
    fn test_write_entry() {
        let temp_dir = TempDir::new().unwrap();
        let config = PersistenceConfig {
            log_dir: temp_dir.path().to_path_buf(),
            file_prefix: "test".to_string(),
            max_file_size: 1024 * 1024,
            max_files: 5,
            compress_rotated: false,
        };

        let mut writer = LogWriter::new(config).unwrap();
        let entry = LogEntry::new(SecurityLevel::Info, "Test message".to_string(), None);

        let result = writer.write_entry(&entry);
        assert!(result.is_ok());

        // Verify file exists
        let log_file = temp_dir.path().join("test.log");
        assert!(log_file.exists());
    }

    #[test]
    fn test_file_rotation() {
        let temp_dir = TempDir::new().unwrap();
        let config = PersistenceConfig {
            log_dir: temp_dir.path().to_path_buf(),
            file_prefix: "test".to_string(),
            max_file_size: 100, // Small size to force rotation
            max_files: 3,
            compress_rotated: false,
        };

        let mut writer = LogWriter::new(config).unwrap();

        // Write multiple entries to trigger rotation
        for i in 0..20 {
            let entry = LogEntry::new(
                SecurityLevel::Info,
                format!("Test message number {}", i),
                None,
            );
            writer.write_entry(&entry).unwrap();
        }

        // Check that rotation occurred
        let rotated_file = temp_dir.path().join("test.1.log");
        assert!(rotated_file.exists());
    }

    #[test]
    fn test_json_writing() {
        let temp_dir = TempDir::new().unwrap();
        let config = PersistenceConfig {
            log_dir: temp_dir.path().to_path_buf(),
            file_prefix: "json_test".to_string(),
            max_file_size: 1024 * 1024,
            max_files: 5,
            compress_rotated: false,
        };

        let mut writer = LogWriter::new(config).unwrap();
        let entry = LogEntry::new(
            SecurityLevel::Audit,
            "Transaction completed".to_string(),
            Some(serde_json::json!({"amount": 1000, "currency": "USD"})),
        );

        let result = writer.write_entry_json(&entry);
        assert!(result.is_ok());

        let log_file = temp_dir.path().join("json_test.log");
        let contents = fs::read_to_string(log_file).unwrap();
        assert!(contents.contains("Transaction completed"));
        assert!(contents.contains("\"amount\":1000"));
    }
}
