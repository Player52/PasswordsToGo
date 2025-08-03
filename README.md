# PasswordsToGo

PasswordsToGo is your new secure password manager and password creator! We take your security seriously, so your passwords are always encrypted and never shared. Manage, store, and generate strong passwords with ease—right from your desktop.

---

## 🚀 Features
- **Sleek, modern GUI** — easy to use, no command line needed
- **All data is encrypted** with in-house security using strong encryption
- **PIN protection** — only you can access your passwords
- **Automatic password generator** — create strong, unique passwords instantly
- **Clipboard integration** — new passwords are copied to your clipboard for convenience

---

## 🔒 Security Notice

We put your security first:
- Passwords are **encrypted** on your device using modern cryptography (Fernet symmetric encryption).
- Your encryption key and PIN are **never transmitted** or stored outside your own computer.
- If you lose your `secret.key` or `pin.key` files, your passwords cannot be recovered — this is by design!

---

## 🛠️ Requirements

- Python 3.7 or newer is recommended.
- The script will auto-install any missing dependencies (like `cryptography` and `pyperclip`) the first time you run it.

---

## 🖥️ Usage

1. **Download or clone this repository** to your computer.
2. **Open a terminal** in the project folder.
3. **Run the script:**

   ```
   python passwordstogo.py
   ```

   Or, on some systems:
   ```
   python3 passwordstogo.py
   ```

4. **On first use:**  
   - Set a 4-digit PIN.  
   - Remember this PIN! If you lose it, you must delete both `pin.key` and `secret.key` (but this will erase all your stored passwords).
5. **Follow the on-screen instructions** to add, find, or manage passwords.

---

## 🤝 How to Contribute

We welcome contributions! To do this, please go to the GitHub page where you downloaded the Password manager. Then follow the instructions below!

1. **Fork this repository**.
2. **Create a new branch** for your changes.
3. **Make your improvements** and commit them with clear messages.
4. **Open a Pull Request** describing your changes.

Please make sure your code is clear and well-documented. For major changes, open an Issue first to discuss your ideas.

---

## 📃 License

PasswordsToGo is open source. See [LICENSE](LICENSE) for details.

---

**Questions or suggestions?**  
Open an [issue](https://github.com/Player52/PasswordsToGo/issues) or start a discussion!
