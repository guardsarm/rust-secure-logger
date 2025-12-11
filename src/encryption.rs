//! Log encryption module for secure logging v2.0
//!
//! Provides AES-256-GCM encryption for sensitive log entries.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Encryption errors
#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Invalid key length")]
    InvalidKeyLength,

    #[error("Base64 decode error: {0}")]
    Base64Error(String),
}

/// Encrypted log entry structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedLogEntry {
    pub ciphertext: String, // Base64 encoded
    pub nonce: String,      // Base64 encoded
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub entry_id: String,
}

/// Log encryption key with secure handling
pub struct EncryptionKey {
    key: Vec<u8>,
}

impl EncryptionKey {
    /// Generate a new random encryption key
    pub fn generate() -> Self {
        let mut key = vec![0u8; 32];
        OsRng.fill_bytes(&mut key);
        Self { key }
    }

    /// Create from existing bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EncryptionError> {
        if bytes.len() != 32 {
            return Err(EncryptionError::InvalidKeyLength);
        }
        Ok(Self {
            key: bytes.to_vec(),
        })
    }

    /// Get key bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }
}

impl Drop for EncryptionKey {
    fn drop(&mut self) {
        // Zero out key on drop for security
        for byte in &mut self.key {
            *byte = 0;
        }
    }
}

/// Log encryptor for secure log entries
pub struct LogEncryptor {
    cipher: Aes256Gcm,
}

impl LogEncryptor {
    /// Create a new log encryptor with the given key
    pub fn new(key: &EncryptionKey) -> Result<Self, EncryptionError> {
        let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
            .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;
        Ok(Self { cipher })
    }

    /// Encrypt a log entry
    pub fn encrypt(&self, plaintext: &str, entry_id: &str) -> Result<EncryptedLogEntry, EncryptionError> {
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| EncryptionError::EncryptionFailed(e.to_string()))?;

        Ok(EncryptedLogEntry {
            ciphertext: BASE64.encode(&ciphertext),
            nonce: BASE64.encode(nonce_bytes),
            timestamp: chrono::Utc::now(),
            entry_id: entry_id.to_string(),
        })
    }

    /// Decrypt a log entry
    pub fn decrypt(&self, encrypted: &EncryptedLogEntry) -> Result<String, EncryptionError> {
        let ciphertext = BASE64
            .decode(&encrypted.ciphertext)
            .map_err(|e| EncryptionError::Base64Error(e.to_string()))?;

        let nonce_bytes = BASE64
            .decode(&encrypted.nonce)
            .map_err(|e| EncryptionError::Base64Error(e.to_string()))?;

        if nonce_bytes.len() != 12 {
            return Err(EncryptionError::DecryptionFailed("Invalid nonce length".to_string()));
        }

        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))?;

        String::from_utf8(plaintext)
            .map_err(|e| EncryptionError::DecryptionFailed(e.to_string()))
    }

    /// Encrypt multiple log entries in batch
    pub fn encrypt_batch(&self, entries: &[(&str, &str)]) -> Vec<Result<EncryptedLogEntry, EncryptionError>> {
        entries
            .iter()
            .map(|(plaintext, entry_id)| self.encrypt(plaintext, entry_id))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_decryption() {
        let key = EncryptionKey::generate();
        let encryptor = LogEncryptor::new(&key).unwrap();

        let plaintext = "Sensitive log entry: User 12345 accessed financial records";
        let entry_id = "LOG-001";

        let encrypted = encryptor.encrypt(plaintext, entry_id).unwrap();
        let decrypted = encryptor.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted);
        assert_eq!(encrypted.entry_id, entry_id);
    }

    #[test]
    fn test_different_nonces() {
        let key = EncryptionKey::generate();
        let encryptor = LogEncryptor::new(&key).unwrap();

        let plaintext = "Same message";
        let enc1 = encryptor.encrypt(plaintext, "LOG-001").unwrap();
        let enc2 = encryptor.encrypt(plaintext, "LOG-002").unwrap();

        // Same plaintext should produce different ciphertext due to random nonce
        assert_ne!(enc1.ciphertext, enc2.ciphertext);
        assert_ne!(enc1.nonce, enc2.nonce);
    }

    #[test]
    fn test_invalid_key_length() {
        let short_key = vec![0u8; 16];
        let result = EncryptionKey::from_bytes(&short_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_batch_encryption() {
        let key = EncryptionKey::generate();
        let encryptor = LogEncryptor::new(&key).unwrap();

        let entries = vec![
            ("Log entry 1", "LOG-001"),
            ("Log entry 2", "LOG-002"),
            ("Log entry 3", "LOG-003"),
        ];

        let results = encryptor.encrypt_batch(&entries);
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|r| r.is_ok()));
    }

    #[test]
    fn test_encrypted_entry_serialization() {
        let key = EncryptionKey::generate();
        let encryptor = LogEncryptor::new(&key).unwrap();

        let encrypted = encryptor.encrypt("Test message", "LOG-001").unwrap();
        let json = serde_json::to_string(&encrypted).unwrap();
        let deserialized: EncryptedLogEntry = serde_json::from_str(&json).unwrap();

        let decrypted = encryptor.decrypt(&deserialized).unwrap();
        assert_eq!(decrypted, "Test message");
    }
}
