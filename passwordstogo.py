import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import json
import os
import security_utils
import random
import string
import time
import threading
import hashlib
import platform
import sys

# ---- VERSION ----
APP_VERSION = "1.0.0"
APP_NAME = "PasswordsToGo"
# ---- File Support ----
VAULT_FILE = "passwords.json"
SALT_FILE = "master_salt.bin"
HASH_FILE = "master_hash.bin"
HASH_VAULT_FILE = "vault.hash"
SIGNATURE_FILE = "release.sig"
PUBLIC_KEY_FILE = "public.pem"
THEME_FILE = "theme.pref"
AUTOLCK_TIMEOUT = 120  # seconds

class SecureClipboard:
    def __init__(self):
        self.timer = None

    def copy(self, text, clear_after=15):
        pyperclip.copy(text)
        if self.timer and self.timer.is_alive():
            self.timer.cancel()
        self.timer = threading.Timer(clear_after, self.clear_clipboard)
        self.timer.start()

    def clear_clipboard(self):
        pyperclip.copy("")

clipboard = SecureClipboard()

# --- Application Signing Verification ---
def verify_release():
    if not os.path.exists(SIGNATURE_FILE) or not os.path.exists(PUBLIC_KEY_FILE):
        return True  # skip if not set up
    return security_utils.verify_release(__file__, SIGNATURE_FILE, PUBLIC_KEY_FILE)

# --- PBKDF2 MASTER PASSWORD FUNCTIONALITY ---
def set_master_password(masterpw):
    key, salt = security_utils.derive_key(masterpw)
    with open(SALT_FILE, "wb") as f:
        f.write(salt)
    with open(HASH_FILE, "wb") as f:
        f.write(key)

def verify_master_password(masterpw):
    if not os.path.exists(HASH_FILE) or not os.path.exists(SALT_FILE):
        return False
    with open(SALT_FILE, "rb") as f:
        salt = f.read()
    with open(HASH_FILE, "rb") as f:
        stored_hash = f.read()
    return security_utils.re_authenticate(masterpw, stored_hash, salt)

def masterpw_is_set():
    return os.path.exists(HASH_FILE) and os.path.exists(SALT_FILE)

# --- IN-MEMORY VAULT ENCRYPTION & TAMPER DETECTION ---
class VaultWrapper:
    def __init__(self, key):
        self.memory_vault = security_utils.InMemoryVault(key)

    def load(self, encrypted_data):
        self.memory_vault.load(encrypted_data)
        return json.loads(self.memory_vault.get())

    def save(self, vault):
        encrypted_data = self.memory_vault.save(json.dumps(vault))
        vault_hash = security_utils.compute_vault_hash(encrypted_data)
        with open(VAULT_FILE, "w") as f:
            f.write(encrypted_data)
        with open(HASH_VAULT_FILE, "w") as f:
            f.write(vault_hash)

    def verify_and_load(self):
        if not os.path.exists(VAULT_FILE) or not os.path.exists(HASH_VAULT_FILE):
            return {"entries": [], "notes": []}
        with open(VAULT_FILE, "r") as f:
            encrypted_data = f.read()
        with open(HASH_VAULT_FILE, "r") as f:
            stored_hash = f.read()
        if not security_utils.verify_vault_hash(encrypted_data, stored_hash):
            messagebox.showerror("Error", "Vault file tampered or corrupted!")
            return {"entries": [], "notes": []}
        self.memory_vault.load(encrypted_data)
        return json.loads(self.memory_vault.get())

# --- PASSWORD GENERATION ---
def generate_password(length=16, use_upper=True, use_lower=True, use_digits=True, use_symbols=True, exclude_ambiguous=False):
    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    digits = string.digits
    symbols = string.punctuation
    ambiguous = "O0Il1|`'\";,.[]{}()"

    chars = ""
    if use_upper: chars += upper
    if use_lower: chars += lower
    if use_digits: chars += digits
    if use_symbols: chars += symbols
    if exclude_ambiguous:
        chars = "".join([c for c in chars if c not in ambiguous])
    if not chars:
        chars = lower
    return ''.join(random.choice(chars) for _ in range(length))

def password_strength(password):
    length = len(password)
    categories = [
        any(c.isupper() for c in password),
        any(c.islower() for c in password),
        any(c.isdigit() for c in password),
        any(c in string.punctuation for c in password)
    ]
    score = sum(categories) + (length >= 16) + (length >= 24)
    return score

def strength_text_color(score):
    return [
        ("Very Weak", "#c00"),
        ("Weak", "#f00"),
        ("Fair", "#e69500"),
        ("Good", "#1a8"),
        ("Strong", "#282"),
        ("Excellent", "#174")
    ][min(score, 5)]

# --- AUTOLCOK/TIMEOUT ---
class AutoLocker:
    def __init__(self, timeout, lock_callback):
        self.timeout = timeout
        self.lock_callback = lock_callback
        self.timer = None
        self.active = True

    def reset(self):
        if self.timer and self.timer.is_alive():
            self.timer.cancel()
        self.timer = threading.Timer(self.timeout, self.lock)
        self.timer.start()

    def lock(self):
        if self.active:
            self.lock_callback()

    def stop(self):
        self.active = False
        if self.timer and self.timer.is_alive():
            self.timer.cancel()

# --- THEME SUPPORT ---
def get_theme():
    return "dark" if os.path.exists(THEME_FILE) and open(THEME_FILE).read().strip() == "dark" else "light"

def set_theme(theme):
    with open(THEME_FILE, "w") as f:
        f.write(theme)

def apply_theme(root, theme):
    style = ttk.Style()
    if theme == "dark":
        style.theme_use("clam")
        style.configure(".", background="#252526", foreground="#e7e7e7")
        style.configure("TLabel", background="#252526", foreground="#e7e7e7")
        style.configure("TButton", background="#2d2d30", foreground="#e7e7e7")
        root.configure(bg="#252526")
    else:
        style.theme_use("default")
        style.configure(".", background="#f7f7f7", foreground="#222")
        style.configure("TLabel", background="#f7f7f7", foreground="#222")
        style.configure("TButton", background="#e7e7e7", foreground="#222")
        root.configure(bg="#f7f7f7")

# --- BIOMETRIC UNLOCK (Windows Hello stub, fallback to master password) ---
def biometric_available():
    return platform.system() == "Windows" and "win32com" in sys.modules

def try_biometric():
    if platform.system() == "Windows":
        try:
            shell = win32com.client.Dispatch("WScript.Shell")
            result = shell.Popup("Authenticate with Windows Hello\nClick OK to proceed.", 5, "Windows Hello", 0)
            return result == 1
        except Exception:
            return False
    return False

# --- BREACH CHECK (HIBP password hash API) ---
def check_breach(password):
    sha1pw = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix = sha1pw[:5]
    suffix = sha1pw[5:]
    try:
        r = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
        for line in r.text.splitlines():
            if line.startswith(suffix):
                return True
        return False
    except Exception:
        return None

class MasterPasswordDialog(simpledialog.Dialog):
    def __init__(self, parent, is_setting=False):
        self.is_setting = is_setting
        super().__init__(parent, "Set Master Password" if is_setting else "Enter Master Password")

    def body(self, frame):
        if self.is_setting:
            ttk.Label(frame, text="Set your master password (min 8 chars):").pack()
            self.pw_var = tk.StringVar()
            self.re_var = tk.StringVar()
            ttk.Entry(frame, textvariable=self.pw_var, show="*", width=30).pack()
            ttk.Label(frame, text="Re-enter master password:").pack()
            ttk.Entry(frame, textvariable=self.re_var, show="*", width=30).pack()
        else:
            ttk.Label(frame, text="Enter your master password:").pack()
            self.pw_var = tk.StringVar()
            ttk.Entry(frame, textvariable=self.pw_var, show="*", width=30).pack()
        return frame

    def validate(self):
        if self.is_setting:
            pw = self.pw_var.get()
            re = self.re_var.get()
            if len(pw) < 8:
                messagebox.showerror("Error", "Password must be at least 8 characters.")
                return False
            if pw != re:
                messagebox.showerror("Error", "Passwords do not match.")
                return False
            self.result = pw
            return True
        else:
            pw = self.pw_var.get()
            if not pw:
                messagebox.showerror("Error", "Enter your master password.")
                return False
            self.result = pw
            return True

class PasswordsToGoApp:
    def __init__(self, root):
        if not verify_release():
            messagebox.showerror("Security", "Application signature invalid! Exiting for safety.")
            sys.exit(1)
        self.root = root
        self.theme = get_theme()
        apply_theme(self.root, self.theme)
        self.autolocker = AutoLocker(AUTOLCK_TIMEOUT, self.lock_app)
        self.masterpw = None
        # Unlock logic will set up self.vault
        self.vault = None
        self.vault_wrapper = None
        self.init_login()

    def lock_app(self):
        self.unlocked = False
        for widget in self.root.winfo_children():
            widget.destroy()
        self.init_login()

    def unlock_app(self):
        self.unlocked = True
        for widget in self.root.winfo_children():
            widget.destroy()
        self.init_main()
        self.autolocker.reset()

    def init_login(self):
        self.root.title(f"{APP_NAME} {APP_VERSION} – Locked")
        f = ttk.Frame(self.root, padding=40)
        f.pack(fill="both", expand=True)
        ttk.Label(f, text=f"{APP_NAME}", font=("Segoe UI", 22, "bold"), foreground="#0078d7").pack(pady=(0,18))
        ttk.Label(f, text=f"Version {APP_VERSION}", font=("Segoe UI", 10)).pack(pady=(0,8))
        if not masterpw_is_set():
            dlg = MasterPasswordDialog(self.root, is_setting=True)
            if dlg.result is None:
                self.root.destroy()
                return
            set_master_password(dlg.result)
            messagebox.showinfo("Master Password Set", "Master password set! Please remember it.")
        if biometric_available():
            if try_biometric():
                self.masterpw = None
                self.unlock_app()
                return
        dlg = MasterPasswordDialog(self.root)
        if dlg.result is None:
            self.root.destroy()
            return
        if verify_master_password(dlg.result):
            self.masterpw = dlg.result
            # Derive the session key for vault encryption
            with open(SALT_FILE, "rb") as f:
                salt = f.read()
            vault_key, _ = security_utils.derive_key(self.masterpw, salt)
            self.vault_wrapper = VaultWrapper(vault_key)
            # Load and verify vault file
            self.vault = self.vault_wrapper.verify_and_load()
            self.unlock_app()
        else:
            messagebox.showerror("Error", "Incorrect master password.")
            self.root.destroy()

    def init_main(self):
        self.root.title(f"{APP_NAME} {APP_VERSION}")
        frame = ttk.Frame(self.root, padding=20)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text=f"{APP_NAME}", font=("Segoe UI", 19, "bold"), foreground="#0078d7").pack(pady=(0, 18))
        ttk.Label(frame, text=f"Version {APP_VERSION}", font=("Segoe UI", 10)).pack(pady=(0, 10))
        theme_btn = ttk.Button(frame, text="Dark Mode" if self.theme == "light" else "Light Mode",
                               command=self.toggle_theme)
        theme_btn.pack(pady=(0,10), anchor="ne")
        ttk.Button(frame, text="Add / Generate Password", command=self.add_password).pack(fill="x", pady=4)
        ttk.Button(frame, text="View All Passwords", command=self.view_passwords).pack(fill="x", pady=4)
        ttk.Button(frame, text="Search Passwords", command=self.search_passwords).pack(fill="x", pady=4)
        ttk.Button(frame, text="Favorites / Most Used", command=self.show_favorites).pack(fill="x", pady=4)
        ttk.Button(frame, text="Secure Notes", command=self.secure_notes).pack(fill="x", pady=4)
        ttk.Button(frame, text="Vault Export/Import", command=self.export_import).pack(fill="x", pady=4)
        ttk.Button(frame, text="Settings", command=self.settings_dialog).pack(fill="x", pady=4)
        ttk.Button(frame, text="Lock", command=self.lock_app).pack(fill="x", pady=12)

    def toggle_theme(self):
        self.theme = "dark" if self.theme == "light" else "light"
        set_theme(self.theme)
        apply_theme(self.root, self.theme)
        self.lock_app()

    def add_password(self):
        add_win = tk.Toplevel(self.root)
        add_win.title("Add / Generate Password")
        apply_theme(add_win, self.theme)
        frame = ttk.Frame(add_win, padding=16)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Add New Password", font=("Segoe UI", 13, "bold"), foreground="#0078d7").pack(pady=(0,10))

        site_var = tk.StringVar()
        user_var = tk.StringVar()
        pw_var = tk.StringVar()
        note_var = tk.StringVar()
        fav_var = tk.BooleanVar()
        twofa_var = tk.StringVar()

        gen_length = tk.IntVar(value=16)
        use_upper = tk.BooleanVar(value=True)
        use_lower = tk.BooleanVar(value=True)
        use_digits = tk.BooleanVar(value=True)
        use_symbols = tk.BooleanVar(value=True)
        exclude_amb = tk.BooleanVar(value=False)

        ttk.Label(frame, text="Site/App:").pack(anchor="w")
        ttk.Entry(frame, textvariable=site_var, width=34).pack()
        ttk.Label(frame, text="Username/Email:").pack(anchor="w", pady=(6,0))
        ttk.Entry(frame, textvariable=user_var, width=34).pack()
        ttk.Label(frame, text="Password:").pack(anchor="w", pady=(6,0))
        pwentry = ttk.Entry(frame, textvariable=pw_var, show="*", width=26)
        pwentry.pack(side="left")
        showbtn = ttk.Button(frame, text="Show", width=7, command=lambda: pwentry.config(show="" if pwentry.cget("show") == "*" else "*"))
        showbtn.pack(side="left", padx=4)

        strlabel = ttk.Label(frame, text="Strength: ")
        strlabel.pack(anchor="w")
        def update_strength(*_):
            score = password_strength(pw_var.get())
            txt, color = strength_text_color(score)
            strlabel.config(text=f"Strength: {txt}", foreground=color)
        pw_var.trace_add("write", update_strength)

        def breach_check():
            pw = pw_var.get()
            if not pw:
                messagebox.showwarning("Breach Check", "No password entered.")
                return
            result = check_breach(pw)
            if result is None:
                messagebox.showinfo("Breach Check", "Could not check breach status (no internet?).")
            elif result:
                messagebox.showwarning("Breach Check", "This password has appeared in a breach! Please use another.")
            else:
                messagebox.showinfo("Breach Check", "This password has not been found in known breaches.")

        ttk.Button(frame, text="Check Breach", command=breach_check).pack(anchor="w", pady=2)

        ttk.Label(frame, text="Generator Options:").pack(anchor="w", pady=(8,0))
        opts = ttk.Frame(frame)
        opts.pack(anchor="w")
        ttk.Checkbutton(opts, text="Uppercase", variable=use_upper).pack(side="left")
        ttk.Checkbutton(opts, text="Lowercase", variable=use_lower).pack(side="left")
        ttk.Checkbutton(opts, text="Digits", variable=use_digits).pack(side="left")
        ttk.Checkbutton(opts, text="Symbols", variable=use_symbols).pack(side="left")
        ttk.Checkbutton(opts, text="No ambiguous", variable=exclude_amb).pack(side="left")
        ttk.Label(frame, text="Length:").pack(anchor="w")
        ttk.Scale(frame, from_=8, to=64, orient="horizontal", variable=gen_length).pack(fill="x")
        ttk.Button(frame, text="Generate", command=lambda: pw_var.set(
            generate_password(
                length=gen_length.get(),
                use_upper=use_upper.get(),
                use_lower=use_lower.get(),
                use_digits=use_digits.get(),
                use_symbols=use_symbols.get(),
                exclude_ambiguous=exclude_amb.get()
            ))).pack(anchor="w", pady=4)

        ttk.Label(frame, text="2FA Backup Codes / TOTP:").pack(anchor="w", pady=(8,0))
        ttk.Entry(frame, textvariable=twofa_var, width=34).pack()
        ttk.Checkbutton(frame, text="Favorite", variable=fav_var).pack(anchor="w", pady=(2,0))
        ttk.Label(frame, text="Note:").pack(anchor="w")
        ttk.Entry(frame, textvariable=note_var, width=34).pack()

        def on_submit():
            site = site_var.get().strip()
            user = user_var.get().strip()
            pw = pw_var.get().strip()
            note = note_var.get().strip()
            fav = fav_var.get()
            twofa = twofa_var.get().strip()
            if not site or not user or not pw:
                messagebox.showerror("Error", "Site, Username, and Password are required.")
                return
            timestamp = int(time.time())
            # Encrypt entries using per-session vault key
            encrypted_pw = security_utils.encrypt_entry(pw, self.vault_wrapper.memory_vault.fernet._signing_key + self.vault_wrapper.memory_vault.fernet._encryption_key)
            encrypted_note = security_utils.encrypt_entry(note, self.vault_wrapper.memory_vault.fernet._signing_key + self.vault_wrapper.memory_vault.fernet._encryption_key)
            encrypted_twofa = security_utils.encrypt_entry(twofa, self.vault_wrapper.memory_vault.fernet._signing_key + self.vault_wrapper.memory_vault.fernet._encryption_key)
            history = [{"pw": encrypted_pw, "changed": timestamp}]
            entry = {
                "site": site,
                "user": user,
                "password": encrypted_pw,
                "note": encrypted_note,
                "favorite": fav,
                "twofa": encrypted_twofa,
                "history": history,
                "used": 0,
                "created": timestamp
            }
            self.vault["entries"].append(entry)
            self.vault_wrapper.save(self.vault)
            clipboard.copy(pw)
            security_utils.clear_clipboard()
            messagebox.showinfo("Saved", "Password saved and copied to clipboard!")
            add_win.destroy()

        ttk.Button(frame, text="Save", command=on_submit).pack(pady=12)

    def view_passwords(self):
        vwin = tk.Toplevel(self.root)
        vwin.title("All Passwords")
        apply_theme(vwin, self.theme)
        frame = ttk.Frame(vwin, padding=10)
        frame.pack(fill="both", expand=True)
        lb = tk.Listbox(frame, width=56, height=16)
        lb.pack(side="left", fill="y")
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=lb.yview)
        scrollbar.pack(side="left", fill="y")
        lb.config(yscrollcommand=scrollbar.set)
        entries = self.vault["entries"]
        for idx, entry in enumerate(entries):
            mark = "★ " if entry.get("favorite") else ""
            lb.insert("end", f'{mark}{entry["site"]} | {entry["user"]}')
        def show_selected(_=None):
            idx = lb.curselection()
            if not idx:
                return
            entry = entries[idx[0]]
            details = tk.Toplevel(vwin)
            details.title("Entry Details")
            apply_theme(details, self.theme)
            dframe = ttk.Frame(details, padding=14)
            dframe.pack(fill="both", expand=True)
            ttk.Label(dframe, text=f'Site: {entry["site"]}', font=("Segoe UI", 12, "bold")).pack(anchor="w")
            ttk.Label(dframe, text=f'User: {entry["user"]}', font=("Segoe UI", 11)).pack(anchor="w")
            # Re-authenticate before revealing password
            def toggle_pw():
                dlg = MasterPasswordDialog(self.root)
                if dlg.result is None:
                    return
                with open(SALT_FILE, "rb") as f:
                    salt = f.read()
                with open(HASH_FILE, "rb") as f:
                    stored_hash = f.read()
                if not security_utils.re_authenticate(dlg.result, stored_hash, salt):
                    messagebox.showerror("Auth Failed", "Incorrect password.")
                    return
                pw_entry.config(show="" if pw_entry.cget("show") == "*" else "*")
                security_utils.warn_screenshot()
            pw_val = security_utils.decrypt_entry(entry["password"], self.vault_wrapper.memory_vault.fernet._signing_key + self.vault_wrapper.memory_vault.fernet._encryption_key)
            pw_var = tk.StringVar(value=pw_val)
            ttk.Label(dframe, text="Password:").pack(anchor="w")
            pw_entry = ttk.Entry(dframe, textvariable=pw_var, width=34, show="*")
            pw_entry.pack(anchor="w")
            ttk.Button(dframe, text="Show/Hide", width=9, command=toggle_pw).pack(anchor="w")
            ttk.Button(dframe, text="Copy Password", command=lambda: [clipboard.copy(pw_var.get()), security_utils.clear_clipboard(), messagebox.showinfo("Copied", "Copied to clipboard!")]).pack(anchor="w", pady=3)
            ttk.Label(dframe, text="2FA/TOTP:").pack(anchor="w")
            totp_val = security_utils.decrypt_entry(entry.get("twofa", ""), self.vault_wrapper.memory_vault.fernet._signing_key + self.vault_wrapper.memory_vault.fernet._encryption_key)
            totp_var = tk.StringVar(value=totp_val)
            ttk.Entry(dframe, textvariable=totp_var, width=34).pack(anchor="w")
            ttk.Label(dframe, text="Note:").pack(anchor="w")
            note_val = security_utils.decrypt_entry(entry.get("note", ""), self.vault_wrapper.memory_vault.fernet._signing_key + self.vault_wrapper.memory_vault.fernet._encryption_key)
            ttk.Label(dframe, text=note_val, font=("Segoe UI", 9)).pack(anchor="w")
            fav = entry.get("favorite", False)
            def toggle_fav():
                entry["favorite"] = not entry.get("favorite", False)
                self.vault_wrapper.save(self.vault)
                details.destroy()
            ttk.Button(dframe, text="Unfavorite" if fav else "Favorite", command=toggle_fav).pack(anchor="w", pady=3)
            ttk.Label(dframe, text="Password History:", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=3)
            for hist in entry.get("history", []):
                hist_pw = security_utils.decrypt_entry(hist["pw"], self.vault_wrapper.memory_vault.fernet._signing_key + self.vault_wrapper.memory_vault.fernet._encryption_key)
                changed = time.strftime("%Y-%m-%d %H:%M", time.localtime(hist["changed"]))
                ttk.Label(dframe, text=f"{changed}: {hist_pw[:3]}... ({len(hist_pw)} chars)").pack(anchor="w")
            entry["used"] = entry.get("used", 0) + 1
            self.vault_wrapper.save(self.vault)
        lb.bind("<<ListboxSelect>>", show_selected)

    def search_passwords(self):
        q = simpledialog.askstring("Search", "Enter site or username:")
        if not q: return
        q = q.lower()
        results = [e for e in self.vault["entries"] if q in e["site"].lower() or q in e["user"].lower()]
        if not results:
            messagebox.showinfo("No Results", "No matching passwords found.")
            return
        self.show_entries_list(results, title="Search Results")

    def show_favorites(self):
        favs = [e for e in self.vault["entries"] if e.get("favorite")]
        used = sorted(self.vault["entries"], key=lambda e: e.get("used", 0), reverse=True)[:10]
        win = tk.Toplevel(self.root)
        win.title("Favorites / Most Used")
        apply_theme(win, self.theme)
        f = ttk.Frame(win, padding=10)
        f.pack(fill="both", expand=True)
        ttk.Label(f, text="Favorites", font=("Segoe UI", 11, "bold")).pack()
        for entry in favs:
            ttk.Label(f, text=f'{entry["site"]} | {entry["user"]}').pack(anchor="w")
        ttk.Label(f, text="Most Used", font=("Segoe UI", 11, "bold")).pack(pady=(10,0))
        for entry in used:
            ttk.Label(f, text=f'{entry["site"]} | {entry["user"]} (used {entry.get("used",0)}x)').pack(anchor="w")

    def secure_notes(self):
        notes_win = tk.Toplevel(self.root)
        notes_win.title("Secure Notes")
        apply_theme(notes_win, self.theme)
        frame = ttk.Frame(notes_win, padding=10)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Secure Notes", font=("Segoe UI", 13, "bold")).pack()
        notes = self.vault.get("notes", [])
        lb = tk.Listbox(frame, width=54, height=10)
        lb.pack(side="left", fill="y")
        for note in notes:
            title = security_utils.decrypt_entry(note["title"], self.vault_wrapper.memory_vault.fernet._signing_key + self.vault_wrapper.memory_vault.fernet._encryption_key)
            lb.insert("end", title)
        def show_note():
            idx = lb.curselection()
            if not idx: return
            note = notes[idx[0]]
            title = security_utils.decrypt_entry(note["title"], self.vault_wrapper.memory_vault.fernet._signing_key + self.vault_wrapper.memory_vault.fernet._encryption_key)
            body = security_utils.decrypt_entry(note["body"], self.vault_wrapper.memory_vault.fernet._signing_key + self.vault_wrapper.memory_vault.fernet._encryption_key)
            nw = tk.Toplevel(notes_win)
            nw.title(title)
            apply_theme(nw, self.theme)
            f = ttk.Frame(nw, padding=10)
            f.pack(fill="both", expand=True)
            ttk.Label(f, text=title, font=("Segoe UI", 13, "bold")).pack()
            txt = tk.Text(f, height=12, width=40, wrap="word")
            txt.pack()
            txt.insert("end", body)
            txt.config(state="disabled")
        lb.bind("<<ListboxSelect>>", lambda e: show_note())
        def add_note():
            title = simpledialog.askstring("Note Title", "Title:")
            body = simpledialog.askstring("Note Body", "Body:")
            if title and body:
                encrypted_title = security_utils.encrypt_entry(title, self.vault_wrapper.memory_vault.fernet._signing_key + self.vault_wrapper.memory_vault.fernet._encryption_key)
                encrypted_body = security_utils.encrypt_entry(body, self.vault_wrapper.memory_vault.fernet._signing_key + self.vault_wrapper.memory_vault.fernet._encryption_key)
                notes.append({"title": encrypted_title, "body": encrypted_body})
                self.vault_wrapper.save(self.vault)
                lb.insert("end", title)
        ttk.Button(frame, text="Add Note", command=add_note).pack()

    def export_import(self):
        win = tk.Toplevel(self.root)
        win.title("Export/Import Vault")
        apply_theme(win, self.theme)
        f = ttk.Frame(win, padding=10)
        f.pack(fill="both", expand=True)
        ttk.Label(f, text="Export/Import Vault", font=("Segoe UI", 13, "bold")).pack()
        ttk.Button(f, text="Export Vault", command=lambda: self.export_vault_dialog()).pack(pady=5)
        ttk.Button(f, text="Import Vault", command=lambda: self.import_vault_dialog()).pack(pady=5)

    def export_vault_dialog(self):
        path = filedialog.asksaveasfilename(title="Export Vault", defaultextension=".ptg", filetypes=[("PasswordsToGo Vault", "*.ptg")])
        if not path: return
        # Export encrypted vault file
        with open(VAULT_FILE, "r") as f:
            encrypted_data = f.read()
        with open(path, "w") as f:
            f.write(encrypted_data)
        messagebox.showinfo("Export", "Vault exported successfully.")

    def import_vault_dialog(self):
        path = filedialog.askopenfilename(title="Import Vault", filetypes=[("PasswordsToGo Vault", "*.ptg")])
        if not path: return
        with open(path, "r") as f:
            encrypted_data = f.read()
        with open(VAULT_FILE, "w") as f:
            f.write(encrypted_data)
        # (Recompute hash after import)
        vault_hash = security_utils.compute_vault_hash(encrypted_data)
        with open(HASH_VAULT_FILE, "w") as f:
            f.write(vault_hash)
        self.vault = self.vault_wrapper.verify_and_load()
        messagebox.showinfo("Import", "Vault imported successfully.")
        self.lock_app()

    def settings_dialog(self):
        win = tk.Toplevel(self.root)
        win.title("Settings")
        apply_theme(win, self.theme)
        f = ttk.Frame(win, padding=10)
        f.pack(fill="both", expand=True)
        ttk.Label(f, text="Settings", font=("Segoe UI", 13, "bold")).pack()
        ttk.Label(f, text="Auto-lock Timeout (seconds):").pack(anchor="w")
        timeout_var = tk.IntVar(value=AUTOLCK_TIMEOUT)
        ttk.Entry(f, textvariable=timeout_var, width=8).pack(anchor="w")
        def save_settings():
            global AUTOLCK_TIMEOUT
            AUTOLCK_TIMEOUT = timeout_var.get()
            self.autolocker.timeout = AUTOLCK_TIMEOUT
            messagebox.showinfo("Saved", "Settings saved.")
            win.destroy()
        ttk.Button(f, text="Save", command=save_settings).pack()

    def show_entries_list(self, entries, title="Entries"):
        win = tk.Toplevel(self.root)
        win.title(title)
        apply_theme(win, self.theme)
        frame = ttk.Frame(win, padding=10)
        frame.pack(fill="both", expand=True)
        lb = tk.Listbox(frame, width=56, height=16)
        lb.pack(side="left", fill="y")
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=lb.yview)
        scrollbar.pack(side="left", fill="y")
        lb.config(yscrollcommand=scrollbar.set)
        for entry in entries:
            mark = "★ " if entry.get("favorite") else ""
            lb.insert("end", f'{mark}{entry["site"]} | {entry["user"]}')
        def show_selected(_=None):
            idx = lb.curselection()
            if not idx:
                return
            entry = entries[idx[0]]
            details = tk.Toplevel(win)
            details.title("Entry Details")
            apply_theme(details, self.theme)
            dframe = ttk.Frame(details, padding=14)
            dframe.pack(fill="both", expand=True)
            ttk.Label(dframe, text=f'Site: {entry["site"]}', font=("Segoe UI", 12, "bold")).pack(anchor="w")
            ttk.Label(dframe, text=f'User: {entry["user"]}', font=("Segoe UI", 11)).pack(anchor="w")
            pw_val = security_utils.decrypt_entry(entry["password"], self.vault_wrapper.memory_vault.fernet._signing_key + self.vault_wrapper.memory_vault.fernet._encryption_key)
            pw_var = tk.StringVar(value=pw_val)
            ttk.Label(dframe, text="Password:").pack(anchor="w")
            pw_entry = ttk.Entry(dframe, textvariable=pw_var, width=34, show="*")
            pw_entry.pack(anchor="w")
            def toggle_pw():
                dlg = MasterPasswordDialog(self.root)
                if dlg.result is None:
                    return
                with open(SALT_FILE, "rb") as f:
                    salt = f.read()
                with open(HASH_FILE, "rb") as f:
                    stored_hash = f.read()
                if not security_utils.re_authenticate(dlg.result, stored_hash, salt):
                    messagebox.showerror("Auth Failed", "Incorrect password.")
                    return
                pw_entry.config(show="" if pw_entry.cget("show") == "*" else "*")
                security_utils.warn_screenshot()
            ttk.Button(dframe, text="Show/Hide", width=9, command=toggle_pw).pack(anchor="w")
            ttk.Button(dframe, text="Copy Password", command=lambda: [clipboard.copy(pw_var.get()), security_utils.clear_clipboard(), messagebox.showinfo("Copied", "Copied to clipboard!")]).pack(anchor="w", pady=3)
        lb.bind("<<ListboxSelect>>", show_selected)

if __name__ == "__main__":
    import pyperclip
    import requests
    root = tk.Tk()
    root.geometry("480x600")
    app = PasswordsToGoApp(root)
    if getattr(app, "unlocked", True):
        root.mainloop()
