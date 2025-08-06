# Security Policy for PasswordsToGo

_Last updated: 2025-08-06_

## Supported Versions

We support and provide security updates for the latest official release of PasswordsToGo. Older versions may not receive patches for vulnerabilities.

| Version | Supported          |
|---------|--------------------|
| 1.0.x   | ✅ Yes             |
| < 1.0   | ❌ No (Beta only)  |

---

## Reporting a Vulnerability

If you discover a security vulnerability in PasswordsToGo, **please follow these steps**:

1. **Do not disclose vulnerabilities publicly.**  
   Please report issues privately to the maintainers.

2. **Contact:**  
   Send an email to [security@player52.dev](mailto:security@player52.dev) or open a **private security advisory** via GitHub (if available).

3. **Include details:**  
   - A description of the vulnerability.
   - Steps to reproduce.
   - Your environment (OS, Python version, PasswordsToGo version).
   - Potential impact.

We aim to respond to security reports within **72 hours**.

---

## Security Practices

PasswordsToGo uses the following security measures:

- **Master password-based encryption:**  
  All vault data is encrypted locally with a key derived from your master password via PBKDF2.

- **Per-entry encryption:**  
  Each password and note is encrypted individually.

- **Tamper detection:**  
  The vault file’s integrity is verified using cryptographic hashes.

- **In-memory encryption:**  
  Vault data is kept encrypted in memory and only decrypted as needed.

- **Password reveal re-authentication:**  
  Users must re-enter their master password to view or copy stored passwords.

- **Clipboard auto-clear:**  
  Passwords copied to the clipboard are automatically cleared after a short time.

- **Application signing:**  
  Official releases are signed for authenticity verification.

- **No telemetry:**  
  PasswordsToGo sends no usage or vault data anywhere.

---

## Third-party Dependencies

PasswordsToGo uses vetted, well-maintained third-party libraries (such as [cryptography](https://cryptography.io/), [pyperclip](https://github.com/asweigart/pyperclip), etc.).  
We monitor CVEs and update dependencies when security issues arise.

---

## Responsible Disclosure

We encourage responsible disclosure.  
Once a report is received, we will:

- Confirm the vulnerability.
- Work on a fix or mitigation.
- Release a patch and update documentation as quickly as possible.
- Credit reporters if desired.

---

## End-of-life & Unsupported Versions

Older, unsupported versions may lack security updates.  
**Always use the latest official release.**

---

Thank you for helping keep PasswordsToGo users safe!
