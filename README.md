# Rust Secure Logger

[![CI](https://github.com/guardsarm/rust-secure-logger/actions/workflows/ci.yml/badge.svg)](https://github.com/guardsarm/rust-secure-logger/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/rust-secure-logger.svg)](https://crates.io/crates/rust-secure-logger)
[![Documentation](https://docs.rs/rust-secure-logger/badge.svg)](https://docs.rs/rust-secure-logger)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A memory-safe, thread-safe logging library designed for financial systems and critical infrastructure where security and audit trails are essential.

## 🔒 Security-First Design

Built with Rust to eliminate memory safety vulnerabilities that cause 70% of security incidents in traditional C/C++ systems. Aligns with **2024 CISA/FBI guidance** recommending memory-safe languages for critical infrastructure.

## Features

- ✅ **Memory Safety** - Rust's ownership system prevents buffer overflows and use-after-free errors
- ✅ **Thread Safety** - Concurrent logging without data races
- ✅ **Tamper Detection** - Cryptographic hashing (SHA-256) of all log entries
- ✅ **Structured Logging** - JSON format for easy parsing and SIEM integration
- ✅ **Audit Trail** - Immutable log entries with timestamps and integrity verification
- ✅ **Financial Systems Ready** - Designed for regulatory compliance (SOX, GLBA, PCI-DSS)

## Use Cases

- Financial transaction logging
- Security event monitoring
- Compliance audit trails
- Critical infrastructure logging
- Tamper-evident record keeping

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
rust-secure-logger = "0.1.0"
```

## Quick Start

```rust
use rust_secure_logger::{SecureLogger, SecurityLevel};

fn main() {
    let logger = SecureLogger::new();

    // Log different security levels
    logger.info("Application started");
    logger.warning("High memory usage detected");

    // Log security events with metadata
    logger.security_event(
        "Failed login attempt",
        Some(serde_json::json!({
            "ip": "192.168.1.100",
            "username": "admin",
            "timestamp": "2024-11-06T00:00:00Z"
        }))
    );

    // Log audit trail for financial transactions
    logger.audit(
        "Wire transfer initiated",
        Some(serde_json::json!({
            "amount": 50000.00,
            "from_account": "****1234",
            "to_account": "****5678",
            "user_id": "12345"
        }))
    );

    // Verify integrity of all logs
    assert!(logger.verify_all_integrity());

    // Export logs as JSON
    let json = logger.export_json().unwrap();
    println!("{}", json);
}
```

## Security Features

### Cryptographic Integrity

Every log entry includes a SHA-256 hash of its content for tamper detection:

```rust
let entry = LogEntry::new(SecurityLevel::Audit, "Transaction processed".to_string(), None);
assert!(entry.verify_integrity()); // Verify entry hasn't been tampered with
```

### Thread Safety

Safe concurrent logging from multiple threads:

```rust
use std::thread;

let logger = SecureLogger::new();

let handles: Vec<_> = (0..10).map(|i| {
    let logger_clone = logger.clone();
    thread::spawn(move || {
        logger_clone.info(format!("Thread {} message", i));
    })
}).collect();

for handle in handles {
    handle.join().unwrap();
}

assert_eq!(logger.get_entries().len(), 10);
```

### Filtering and Queries

```rust
// Get all audit entries
let audit_logs = logger.get_entries_by_level(SecurityLevel::Audit);

// Count security events
let security_event_count = logger.count_by_level(SecurityLevel::SecurityEvent);

// Export filtered logs
let critical_logs = logger.get_entries_by_level(SecurityLevel::Critical);
```

## Security Levels

- `Info` - Informational messages
- `Warning` - Warnings that may require attention
- `SecurityEvent` - Security events requiring review
- `Critical` - Critical security incidents
- `Audit` - Audit trail entries (financial transactions, access control)

## Examples

See the `examples/` directory:

```bash
cargo run --example basic_usage
cargo run --example audit_trail
```

## Testing

```bash
cargo test
```

## Alignment with Federal Guidance

This library implements security best practices recommended by:

- **CISA/FBI Joint Guidance (2024)** - Memory-safe languages for critical infrastructure
- **Executive Order 14028 (2021)** - Improving the Nation's Cybersecurity
- **NSA Cybersecurity Information Sheet** - Software Memory Safety

By using Rust, this library eliminates entire classes of vulnerabilities:
- Buffer overflows
- Use-after-free errors
- Data races
- Null pointer dereferences

## Use in Financial Systems

Designed for financial institutions requiring:
- **SOX compliance** - Audit trail requirements
- **GLBA compliance** - Financial data protection
- **PCI-DSS compliance** - Payment card industry standards
- **Regulatory reporting** - Immutable audit trails
- **Incident response** - Security event logging

## Performance

- **Low overhead** - Minimal performance impact
- **Async-ready** - Compatible with tokio and async-std
- **Scalable** - Handles high-volume logging in production systems

## License

MIT License - See LICENSE file

## Author

Tony Chuks Awunor

- M.S. Computer Science (CGPA: 4.52/5.00)
- EC-Council Certified Ethical Hacker v13 AI (CEH v13 AI)
- EC-Council Certified SOC Analyst (CSA)
- Specialization: Memory-safe cryptographic systems and financial security infrastructure
- Research interests: Rust security implementations, threat detection, and vulnerability assessment
- Published crates: rust-crypto-utils, rust-secure-logger, rust-threat-detector, rust-transaction-validator, rust-network-scanner, rust-memory-safety-examples

## Contributing

Contributions welcome! Please open an issue or pull request.

## Related Projects

- [rust-crypto-utils](https://github.com/guardsarm/rust-crypto-utils) - Cryptographic utilities
- [rust-transaction-validator](https://github.com/guardsarm/rust-transaction-validator) - Financial transaction validation
- [rust-threat-detector](https://github.com/guardsarm/rust-threat-detector) - SIEM threat detection

## Citation

If you use this library in research or production systems, please cite:

```
Awunor, T.C. (2024). Rust Secure Logger: Memory-Safe Logging for Financial Systems.
https://github.com/guardsarm/rust-secure-logger
```

---

**Built for critical infrastructure. Designed for security. Implemented in Rust.**
