//! Log redaction module for PII protection v2.0
//!
//! Provides automatic redaction of sensitive data in log entries.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Redaction pattern types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum RedactionPattern {
    /// Social Security Number (XXX-XX-XXXX)
    SSN,
    /// Credit Card Number (16 digits)
    CreditCard,
    /// Email Address
    Email,
    /// Phone Number
    PhoneNumber,
    /// IP Address
    IpAddress,
    /// Bank Account Number
    BankAccount,
    /// API Key / Token
    ApiKey,
    /// Password field
    Password,
    /// Custom pattern
    Custom(String),
}

/// Redaction configuration
#[derive(Debug, Clone)]
pub struct RedactionConfig {
    pub enabled_patterns: Vec<RedactionPattern>,
    pub replacement_char: char,
    pub preserve_format: bool,
}

impl Default for RedactionConfig {
    fn default() -> Self {
        Self {
            enabled_patterns: vec![
                RedactionPattern::SSN,
                RedactionPattern::CreditCard,
                RedactionPattern::Email,
                RedactionPattern::PhoneNumber,
                RedactionPattern::Password,
                RedactionPattern::ApiKey,
            ],
            replacement_char: '*',
            preserve_format: true,
        }
    }
}

/// Compiled regex patterns for efficient redaction
struct CompiledPatterns {
    ssn: Regex,
    credit_card: Regex,
    email: Regex,
    phone: Regex,
    ip_address: Regex,
    bank_account: Regex,
    api_key: Regex,
    password: Regex,
}

impl CompiledPatterns {
    fn new() -> Self {
        Self {
            ssn: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
            credit_card: Regex::new(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b").unwrap(),
            email: Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").unwrap(),
            phone: Regex::new(r"\b(\+?1?[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b").unwrap(),
            ip_address: Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap(),
            bank_account: Regex::new(r"\b\d{8,17}\b").unwrap(),
            api_key: Regex::new(r"(?i)(api[_-]?key|token|secret|bearer)\s*[:=]\s*['\x22]?[A-Za-z0-9_-]{20,}['\x22]?").unwrap(),
            password: Regex::new(r"(?i)(password|passwd|pwd)\s*[:=]\s*['\x22]?[^\s'\x22]+['\x22]?").unwrap(),
        }
    }
}

/// Log redactor for automatic PII protection
pub struct LogRedactor {
    config: RedactionConfig,
    patterns: CompiledPatterns,
    custom_patterns: HashMap<String, Regex>,
}

impl Default for LogRedactor {
    fn default() -> Self {
        Self::new(RedactionConfig::default())
    }
}

impl LogRedactor {
    /// Create a new log redactor with custom configuration
    pub fn new(config: RedactionConfig) -> Self {
        Self {
            config,
            patterns: CompiledPatterns::new(),
            custom_patterns: HashMap::new(),
        }
    }

    /// Add a custom redaction pattern
    pub fn add_custom_pattern(&mut self, name: &str, pattern: &str) -> Result<(), regex::Error> {
        let regex = Regex::new(pattern)?;
        self.custom_patterns.insert(name.to_string(), regex);
        self.config.enabled_patterns.push(RedactionPattern::Custom(name.to_string()));
        Ok(())
    }

    /// Redact sensitive data from a string
    pub fn redact(&self, input: &str) -> String {
        let mut result = input.to_string();

        for pattern_type in &self.config.enabled_patterns {
            result = match pattern_type {
                RedactionPattern::SSN => self.redact_pattern(&result, &self.patterns.ssn, "***-**-****"),
                RedactionPattern::CreditCard => self.redact_credit_card(&result),
                RedactionPattern::Email => self.redact_email(&result),
                RedactionPattern::PhoneNumber => self.redact_pattern(&result, &self.patterns.phone, "***-***-****"),
                RedactionPattern::IpAddress => self.redact_pattern(&result, &self.patterns.ip_address, "***.***.***.***"),
                RedactionPattern::BankAccount => self.redact_pattern(&result, &self.patterns.bank_account, "********"),
                RedactionPattern::ApiKey => self.redact_api_key(&result),
                RedactionPattern::Password => self.redact_password(&result),
                RedactionPattern::Custom(name) => {
                    if let Some(regex) = self.custom_patterns.get(name) {
                        self.redact_pattern(&result, regex, "[REDACTED]")
                    } else {
                        result
                    }
                }
            };
        }

        result
    }

    /// Redact using a simple pattern replacement
    fn redact_pattern(&self, input: &str, pattern: &Regex, replacement: &str) -> String {
        pattern.replace_all(input, replacement).to_string()
    }

    /// Redact credit card numbers, preserving last 4 digits
    fn redact_credit_card(&self, input: &str) -> String {
        self.patterns.credit_card.replace_all(input, |caps: &regex::Captures| {
            let matched = caps.get(0).unwrap().as_str();
            let digits: String = matched.chars().filter(|c| c.is_ascii_digit()).collect();
            if digits.len() >= 4 {
                format!("****-****-****-{}", &digits[digits.len()-4..])
            } else {
                "****-****-****-****".to_string()
            }
        }).to_string()
    }

    /// Redact email addresses, preserving domain
    fn redact_email(&self, input: &str) -> String {
        self.patterns.email.replace_all(input, |caps: &regex::Captures| {
            let matched = caps.get(0).unwrap().as_str();
            if let Some(at_pos) = matched.find('@') {
                let domain = &matched[at_pos..];
                format!("****{}", domain)
            } else {
                "****@****.***".to_string()
            }
        }).to_string()
    }

    /// Redact API keys and tokens
    fn redact_api_key(&self, input: &str) -> String {
        self.patterns.api_key.replace_all(input, |caps: &regex::Captures| {
            let matched = caps.get(0).unwrap().as_str();
            if let Some(eq_pos) = matched.find([':', '=']) {
                let prefix = &matched[..=eq_pos];
                format!("{} [REDACTED]", prefix.trim_end_matches([':', '=', ' ']))
            } else {
                "[REDACTED API KEY]".to_string()
            }
        }).to_string()
    }

    /// Redact passwords
    fn redact_password(&self, input: &str) -> String {
        self.patterns.password.replace_all(input, |caps: &regex::Captures| {
            let matched = caps.get(0).unwrap().as_str();
            if let Some(eq_pos) = matched.find([':', '=']) {
                let prefix = &matched[..=eq_pos];
                format!("{} [REDACTED]", prefix.trim_end_matches([':', '=', ' ']))
            } else {
                "[REDACTED PASSWORD]".to_string()
            }
        }).to_string()
    }

    /// Check if a string contains sensitive data
    pub fn contains_sensitive_data(&self, input: &str) -> bool {
        for pattern_type in &self.config.enabled_patterns {
            let has_match = match pattern_type {
                RedactionPattern::SSN => self.patterns.ssn.is_match(input),
                RedactionPattern::CreditCard => self.patterns.credit_card.is_match(input),
                RedactionPattern::Email => self.patterns.email.is_match(input),
                RedactionPattern::PhoneNumber => self.patterns.phone.is_match(input),
                RedactionPattern::IpAddress => self.patterns.ip_address.is_match(input),
                RedactionPattern::BankAccount => self.patterns.bank_account.is_match(input),
                RedactionPattern::ApiKey => self.patterns.api_key.is_match(input),
                RedactionPattern::Password => self.patterns.password.is_match(input),
                RedactionPattern::Custom(name) => {
                    self.custom_patterns.get(name).map_or(false, |r| r.is_match(input))
                }
            };
            if has_match {
                return true;
            }
        }
        false
    }

    /// Get list of detected sensitive data types
    pub fn detect_sensitive_types(&self, input: &str) -> Vec<RedactionPattern> {
        let mut found = Vec::new();

        for pattern_type in &self.config.enabled_patterns {
            let has_match = match pattern_type {
                RedactionPattern::SSN => self.patterns.ssn.is_match(input),
                RedactionPattern::CreditCard => self.patterns.credit_card.is_match(input),
                RedactionPattern::Email => self.patterns.email.is_match(input),
                RedactionPattern::PhoneNumber => self.patterns.phone.is_match(input),
                RedactionPattern::IpAddress => self.patterns.ip_address.is_match(input),
                RedactionPattern::BankAccount => self.patterns.bank_account.is_match(input),
                RedactionPattern::ApiKey => self.patterns.api_key.is_match(input),
                RedactionPattern::Password => self.patterns.password.is_match(input),
                RedactionPattern::Custom(name) => {
                    self.custom_patterns.get(name).map_or(false, |r| r.is_match(input))
                }
            };
            if has_match {
                found.push(pattern_type.clone());
            }
        }

        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssn_redaction() {
        let redactor = LogRedactor::default();
        let input = "User SSN: 123-45-6789 was verified";
        let output = redactor.redact(input);
        assert!(output.contains("***-**-****"));
        assert!(!output.contains("123-45-6789"));
    }

    #[test]
    fn test_credit_card_redaction() {
        let redactor = LogRedactor::default();
        let input = "Card: 4111-1111-1111-1234 processed";
        let output = redactor.redact(input);
        assert!(output.contains("****-****-****-1234"));
        assert!(!output.contains("4111-1111-1111"));
    }

    #[test]
    fn test_email_redaction() {
        let redactor = LogRedactor::default();
        let input = "User email: john.doe@example.com logged in";
        let output = redactor.redact(input);
        assert!(output.contains("@example.com"));
        assert!(!output.contains("john.doe"));
    }

    #[test]
    fn test_password_redaction() {
        let redactor = LogRedactor::default();
        let input = "Login attempt with password=secretpass123";
        let output = redactor.redact(input);
        assert!(output.contains("[REDACTED]"));
        assert!(!output.contains("secretpass123"));
    }

    #[test]
    fn test_api_key_redaction() {
        let redactor = LogRedactor::default();
        let input = "Request with api_key: abcdef1234567890abcdef1234567890";
        let output = redactor.redact(input);
        assert!(output.contains("[REDACTED]"));
        assert!(!output.contains("abcdef1234567890"));
    }

    #[test]
    fn test_contains_sensitive_data() {
        let redactor = LogRedactor::default();
        assert!(redactor.contains_sensitive_data("SSN: 123-45-6789"));
        assert!(!redactor.contains_sensitive_data("Normal log message"));
    }

    #[test]
    fn test_detect_sensitive_types() {
        let redactor = LogRedactor::default();
        let input = "User john@example.com with SSN 123-45-6789";
        let types = redactor.detect_sensitive_types(input);
        assert!(types.contains(&RedactionPattern::Email));
        assert!(types.contains(&RedactionPattern::SSN));
    }

    #[test]
    fn test_multiple_redactions() {
        let redactor = LogRedactor::default();
        let input = "User 123-45-6789 email: test@example.com card: 4111111111111234";
        let output = redactor.redact(input);
        assert!(!output.contains("123-45-6789"));
        assert!(!output.contains("test@example.com"));
        assert!(output.contains("****-****-****-1234"));
    }

    #[test]
    fn test_custom_pattern() {
        let mut redactor = LogRedactor::default();
        redactor.add_custom_pattern("employee_id", r"EMP-\d{6}").unwrap();
        let input = "Employee EMP-123456 accessed system";
        let output = redactor.redact(input);
        assert!(output.contains("[REDACTED]"));
        assert!(!output.contains("EMP-123456"));
    }
}
