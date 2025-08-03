# Changelog

All notable changes to **PasswordsToGo** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [0.2.0]

### Added
- **Master Password:** Replaces the PIN system. Users now set a master password (minimum 8 characters) for unlocking the app, increasing security.
- **Password Strength Meter:** A visual indicator of password strength is shown when creating or generating passwords.
- **Export/Import Encrypted Vault:** Users can export their encrypted password vault to a file and import it later for backup and restore.
- **Autolock/Timeout:** The app automatically locks after a period of inactivity (default 120 seconds), requiring the master password to unlock.
- **Dark Mode / Theme Selector:** Users can switch between light and dark themes for better comfort.
- **Favorites / Most Used:** Mark password entries as favorites, and see your most frequently used passwords.
- **Password History:** Each password entry keeps a history of previous passwords.
- **Two-Factor Authentication (2FA) Storage:** Optionally store TOTP secrets or 2FA backup codes with each password entry.
- **Breach Check:** Integration with "Have I Been Pwned" public API to check if a password has appeared in known data breaches.
- **Customizable Password Generator:** Users can control password length, character sets, and exclude ambiguous characters.
- **Secure Notes:** Store arbitrary secure notes, encrypted in the vault.
- **Secure Clipboard Management:** Passwords copied to clipboard are automatically cleared after 15 seconds.
- **Biometric Unlock (Simplified/Stub):** On Windows, a prototype biometric unlock (Windows Hello) is available. Falls back to master password if not available.
- The implementation is **simplified for testing** and demonstration. For production, it should be modularized and thoroughly tested.

### Changed
- Major refactor to support new features; user interface reorganized for clarity and easy navigation.
- Improved error handling and informative messages throughout the app.
- Documentation and UI updated to reflect new features.

### Security
- All sensitive information remains encrypted; master password and key files are never transmitted.
- Vault export/import is always encrypted.
- Clipboard is cleared automatically.

### Documentation
- Updated README and CHANGELOG to reflect new features and usage.
- Added notes on feature simplification for testing purposes.

---

## [0.1.0] - 2025-08-03

- Initial proof of concept: basic Tkinter GUI, plain JSON storage, password adding/viewing/searching.
- No encryption or PIN protection.
