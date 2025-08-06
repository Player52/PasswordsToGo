<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/8a2bc7f6-ecdb-4dd2-b54e-91ee3be0838c" />

# PasswordsToGo User Guide

Welcome to **PasswordsToGo**, your secure, easy-to-use password manager and generator. This guide will walk you through installing, using, and customizing PasswordsToGo for your needs.

---

## Table of Contents

- [Getting Started](#getting-started)
- [Main Features](#main-features)
- [Using PasswordsToGo](#using-passwordstogo)
  - [Unlocking the App](#unlocking-the-app)
  - [Adding a New Password](#adding-a-new-password)
  - [Generating a Strong Password](#generating-a-strong-password)
  - [Viewing and Searching Passwords](#viewing-and-searching-passwords)
  - [Favourites and Most Used](#favourites-and-most-used)
  - [Password History](#password-history)
  - [Exporting/Importing Your Vault](#exportingimporting-your-vault)
  - [Secure Notes](#secure-notes)
  - [Theme (Dark/Light Mode)](#theme-darklight-mode)
  - [Two-Factor Authentication (2FA) Storage](#two-factor-authentication-2fa-storage)
  - [Breach Check](#breach-check)
  - [Clipboard and Auto-Clear](#clipboard-and-auto-clear)
  - [Biometric Unlock](#biometric-unlock)
- [Security](#security)
- [Troubleshooting](#troubleshooting)
- [Contributing & Getting Help](#contributing--getting-help)

---

## Getting Started

1. **Install Python** if you haven’t already (Python 3.7+ recommended).
2. **Download** or **clone** this repository.
3. **Run the app:**

   ```
   python passwordstogo.py
   ```

   The app will install any missing dependencies automatically.

4. **First Launch:**  
   - Set your **master password** (minimum 8 characters).
   - Remember this password! Losing it will lock you out of your vault.

---

## Main Features

- **Encrypted password vault:** All data is encrypted using strong cryptography.
- **Master password login:** Your passwords are protected by a master password.
- **Automatic password generator:** Create strong, customizable passwords.
- **Favorites & most used:** Quickly access your most important credentials.
- **Password history:** Track password changes for each entry.
- **Secure notes:** Store private notes securely alongside passwords.
- **2FA code storage:** Save backup codes or TOTP secrets (use with caution).
- **Export/Import:** Backup or move your encrypted vault.
- **Theme switcher:** Choose between dark and light modes.
- **Clipboard management:** Passwords are auto-cleared from your clipboard.
- **Breach check:** Check if a password has appeared in a public breach.
- **(Prototype) Biometric unlock:** Use Windows Hello, if available.

---

## Using PasswordsToGo

### Unlocking the App

- On launch, enter your **master password** to unlock the app.
- (On supported systems) You may be prompted to use biometric authentication (e.g., Windows Hello).

### Adding a New Password

1. Click **"Add / Generate Password"**.
2. Enter the site/app, username/email, and desired password.
3. Optionally:
   - Use the password generator.
   - Add a note or 2FA code.
   - Mark as favorite.
4. Click **Save**.  
   Your password is encrypted, stored, and copied to your clipboard.

### Generating a Strong Password

- Use the generator options to set length, symbols, and exclude ambiguous characters.
- The built-in strength meter helps you choose a secure password.

### Viewing and Searching Passwords

- Click **"View All Passwords"** to browse your entries.
- Use **"Search Passwords"** to find credentials by site or username.
- Click an entry to view details, copy, toggle favorite, or see password history.

### Favorites and Most Used

- Mark entries as favorites for quick access.
- View your most used passwords from the **"Favorites / Most Used"** section.

### Password History

- When you update a password, previous versions are kept in the entry’s history for reference.

### Exporting/Importing Your Vault

- Use **"Vault Export/Import"** to back up your encrypted vault or restore from a backup.
- Only import vaults you trust!

### Secure Notes

- Store encrypted notes (e.g., license keys, recovery codes) alongside your passwords.

### Theme (Dark/Light Mode)

- Switch between dark and light themes from the main menu or settings.

### Two-Factor Authentication (2FA) Storage

- You can store backup codes or TOTP secrets with any password entry.
- **Warning:** Never use a password manager as your only backup for 2FA codes.

### Breach Check

- Check if your chosen password appears in known data breaches by clicking **"Check Breach"** during password creation.

### Clipboard and Auto-Clear

- Passwords you copy are automatically removed from your clipboard after 15 seconds for security.

### Biometric Unlock

- On supported systems (currently Windows with Hello), you may unlock PasswordsToGo with biometrics (prototype).
- If unavailable or declined, use your master password.

---

## Security

- PasswordsToGo **never sends your data or master password anywhere**.
- All sensitive data is encrypted locally.
- Your master password is **never stored as plain text**.
- If you lose or forget your master password, your encrypted data cannot be recovered.

---

## Troubleshooting

- **Forgot your master password?**  
  You’ll need to delete both `masterpw.key` and `secret.key` and start over (your stored passwords will be lost).
- **Clipboard is not clearing:**  
  Some clipboard managers override this; try clearing it manually if needed.
- **Import/Export not working:**  
  Only import files created by PasswordsToGo with your version or newer.

---

## Contributing & Getting Help

- Found a bug or have a suggestion? [Open an issue on GitHub](https://github.com/Player52/PasswordsToGo/issues).
- Want to contribute code? See [CONTRIBUTING.md](CONTRIBUTING.md).
- See [README.md](README.md) for more project info.

---

**Stay safe!**  
PasswordsToGo Team
