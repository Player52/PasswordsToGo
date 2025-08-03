import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import json
import os
import random
import string

# Ensure cryptography and pyperclip are installed
try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:
    import subprocess
    subprocess.check_call(["python", "-m", "pip", "install", "cryptography"])
    from cryptography.fernet import Fernet, InvalidToken

try:
    import pyperclip
except ImportError:
    import subprocess
    subprocess.check_call(["python", "-m", "pip", "install", "pyperclip"])
    import pyperclip

PASSWORDS_FILE = "passwords.json"
KEY_FILE = "secret.key"
PIN_FILE = "pin.key"

# --- ENCRYPTION SETUP ---

def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)
    return key

def load_key():
    if not os.path.exists(KEY_FILE):
        return generate_key()
    with open(KEY_FILE, "rb") as key_file:
        return key_file.read()

fernet = Fernet(load_key())

def encrypt(text):
    return fernet.encrypt(text.encode()).decode()

def decrypt(token):
    try:
        return fernet.decrypt(token.encode()).decode()
    except InvalidToken:
        return "<Decryption Failed>"

# --- PIN SETUP ---

def set_pin(pin):
    # Use Fernet to encrypt the pin with the main key
    with open(PIN_FILE, "wb") as f:
        f.write(fernet.encrypt(pin.encode()))

def verify_pin(pin):
    if not os.path.exists(PIN_FILE):
        return False
    with open(PIN_FILE, "rb") as f:
        encrypted_pin = f.read()
    try:
        stored_pin = fernet.decrypt(encrypted_pin).decode()
        return pin == stored_pin
    except InvalidToken:
        return False

def pin_is_set():
    return os.path.exists(PIN_FILE)

# --- PASSWORD STORAGE ---

def load_passwords():
    if not os.path.exists(PASSWORDS_FILE):
        return {}
    with open(PASSWORDS_FILE, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}

def save_passwords(passwords):
    with open(PASSWORDS_FILE, "w") as f:
        json.dump(passwords, f, indent=2)

def generate_password(length=16):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

# --- MODERN GUI ---

class PinDialog(simpledialog.Dialog):
    def __init__(self, parent, title, is_setting=False):
        self.is_setting = is_setting
        super().__init__(parent, title)
    def body(self, frame):
        ttk.Label(frame, text="Enter your 4-digit PIN:" if not self.is_setting else "Set a new 4-digit PIN:",
                  font=("Segoe UI", 12)).pack(pady=8)
        self.pin_var = tk.StringVar()
        self.pin_entry = ttk.Entry(frame, textvariable=self.pin_var, show="*", font=("Segoe UI", 14), width=12, justify="center")
        self.pin_entry.pack(pady=4)
        self.pin_entry.focus()
        if self.is_setting:
            ttk.Label(frame, text="Do not forget this PIN!\nIf forgotten, delete pin.key and secret.key to reset.\n(You will lose your passwords)",
                      font=("Segoe UI", 8), foreground="gray").pack(pady=4)
        return self.pin_entry
    def validate(self):
        pin = self.pin_var.get()
        if len(pin) == 4 and pin.isdigit():
            self.result = pin
            return True
        messagebox.showerror("PIN Error", "PIN must be exactly 4 digits.")
        return False

class PasswordManagerGUI:
    def __init__(self, master):
        self.master = master
        self.master.withdraw()  # Hide main until PIN passed

        # Modern theme
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TButton", font=("Segoe UI", 11), padding=8)
        style.configure("Accent.TButton", font=("Segoe UI", 11, "bold"), padding=8, foreground="#fff", background="#0078d7")
        style.map("Accent.TButton", background=[("active", "#005a9e")])
        style.configure("TLabel", font=("Segoe UI", 11))
        style.configure("Header.TLabel", font=("Segoe UI", 17, "bold"))

        # Authentication
        self.authenticate()
        if not getattr(self, "authenticated", False):
            self.master.destroy()
            return

        self.passwords = load_passwords()
        self.init_gui()

    def authenticate(self):
        # Set PIN if not set
        if not pin_is_set():
            pin = PinDialog(self.master, "Set PIN", is_setting=True).result
            if pin is None:
                return
            set_pin(pin)
            messagebox.showinfo("PIN Set", "PIN set! Please remember it. You’ll be asked for it when you open PasswordsToGo.")
        # Enter PIN
        for _ in range(3):
            pin = PinDialog(self.master, "Enter PIN").result
            if pin is None:
                return
            if verify_pin(pin):
                self.authenticated = True
                self.master.deiconify()
                return
            else:
                messagebox.showerror("PIN Error", "Incorrect PIN. Try again.")
        messagebox.showwarning("Too Many Attempts", "Too many incorrect PIN attempts.\nExiting app.")
        self.authenticated = False

    def init_gui(self):
        self.master.title("🔒 PasswordsToGo")
        self.master.geometry("420x340")
        self.master.configure(bg="#f7f7f7")
        self.master.resizable(False, False)
        frame = ttk.Frame(self.master, padding=20)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="PasswordsToGo", style="Header.TLabel", foreground="#0078d7").pack(pady=(0, 18))

        ttk.Button(frame, text="Add New Password", style="Accent.TButton", width=38, command=self.add_password).pack(pady=7)
        ttk.Button(frame, text="View Passwords", width=38, command=self.view_passwords).pack(pady=7)
        ttk.Button(frame, text="Search Password", width=38, command=self.search_password).pack(pady=7)
        ttk.Button(frame, text="Change PIN", width=38, command=self.change_pin).pack(pady=7)
        ttk.Button(frame, text="Exit", width=38, command=self.master.quit).pack(pady=(20, 0))

    def add_password(self):
        def on_submit():
            site = site_var.get().strip()
            user = user_var.get().strip()
            pw = pw_var.get().strip()
            if not site or not user:
                messagebox.showerror("Missing Info", "Site and Username/Email are required.")
                return
            if not pw:
                pw = generate_password()
                pw_var.set(pw)
            encrypted_pw = encrypt(pw)
            if site not in self.passwords:
                self.passwords[site] = []
            self.passwords[site].append({"user": user, "password": encrypted_pw})
            save_passwords(self.passwords)
            pyperclip.copy(pw)
            messagebox.showinfo("Password Saved", "Password saved and copied to clipboard!")
            add_win.destroy()

        add_win = tk.Toplevel(self.master)
        add_win.title("Add New Password")
        add_win.geometry("370x260")
        add_win.resizable(False, False)
        frame = ttk.Frame(add_win, padding=20)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Add a New Password", style="Header.TLabel", foreground="#0078d7").pack(pady=(0, 10))
        site_var = tk.StringVar()
        user_var = tk.StringVar()
        pw_var = tk.StringVar()

        ttk.Label(frame, text="Site/App:").pack(anchor="w", pady=(10, 0))
        ttk.Entry(frame, textvariable=site_var, width=34).pack()
        ttk.Label(frame, text="Username/Email:").pack(anchor="w", pady=(10, 0))
        ttk.Entry(frame, textvariable=user_var, width=34).pack()
        ttk.Label(frame, text="Password (leave blank to generate):").pack(anchor="w", pady=(10, 0))
        pw_entry = ttk.Entry(frame, textvariable=pw_var, width=34, show="*")
        pw_entry.pack()
        ttk.Button(frame, text="Show/Hide", width=10,
                   command=lambda: pw_entry.config(show="" if pw_entry.cget("show") == "*" else "*")).pack(pady=2)
        ttk.Button(frame, text="Save", style="Accent.TButton", width=18, command=on_submit).pack(pady=(18, 0))

    def view_passwords(self):
        top = tk.Toplevel(self.master)
        top.title("Stored Passwords")
        top.geometry("420x330")
        frame = ttk.Frame(top, padding=12)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Stored Passwords", style="Header.TLabel", foreground="#0078d7").pack(pady=(0, 7))
        lb_frame = ttk.Frame(frame)
        lb_frame.pack(fill="both", expand=True)
        scrollbar = ttk.Scrollbar(lb_frame)
        scrollbar.pack(side="right", fill="y")
        listbox = tk.Listbox(lb_frame, width=54, height=10, yscrollcommand=scrollbar.set, font=("Segoe UI", 10))
        for site, entries in self.passwords.items():
            for entry in entries:
                listbox.insert("end", f"{site} | {entry['user']}")
        listbox.pack(side="left", fill="both", expand=True)
        scrollbar.config(command=listbox.yview)

        def show_selected():
            idx = listbox.curselection()
            if not idx:
                return
            selected = listbox.get(idx)
            site, user = selected.split(" | ")
            entry = next(e for e in self.passwords[site] if e['user'] == user)
            pw = decrypt(entry["password"])
            pwtop = tk.Toplevel(top)
            pwtop.title("Password Details")
            pwtop.geometry("350x220")
            frame2 = ttk.Frame(pwtop, padding=16)
            frame2.pack(fill="both", expand=True)
            ttk.Label(frame2, text=f"Site: {site}", font=("Segoe UI", 11, "bold")).pack(anchor="w")
            ttk.Label(frame2, text=f"User: {user}", font=("Segoe UI", 11)).pack(anchor="w", pady=(0,5))
            ttk.Label(frame2, text="Password:", font=("Segoe UI", 11)).pack(anchor="w")
            pw_var = tk.StringVar(value=pw)
            pwentry = ttk.Entry(frame2, textvariable=pw_var, width=28, show="*")
            pwentry.pack(anchor="w")
            def toggle():
                pwentry.config(show="" if pwentry.cget("show") == "*" else "*")
            ttk.Button(frame2, text="Show/Hide", width=10, command=toggle).pack(anchor="w", pady=3)
            ttk.Button(frame2, text="Copy to Clipboard", style="Accent.TButton", width=18,
                       command=lambda: [pyperclip.copy(pw_var.get()), messagebox.showinfo("Copied", "Password copied to clipboard!")]).pack(pady=5)

        ttk.Button(frame, text="Show Details", style="Accent.TButton", width=20, command=show_selected).pack(pady=8)

    def search_password(self):
        query = simpledialog.askstring("Search", "Enter site or username to search for:")
        if not query:
            return
        results = []
        for site, entries in self.passwords.items():
            if query.lower() in site.lower():
                for entry in entries:
                    results.append((site, entry["user"]))
            else:
                for entry in entries:
                    if query.lower() in entry["user"].lower():
                        results.append((site, entry["user"]))
        if not results:
            messagebox.showinfo("No Results", "No matching passwords found.")
            return
        top = tk.Toplevel(self.master)
        top.title("Search Results")
        top.geometry("420x240")
        frame = ttk.Frame(top, padding=10)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Search Results", style="Header.TLabel", foreground="#0078d7").pack(pady=(0, 7))
        listbox = tk.Listbox(frame, width=54, height=7, font=("Segoe UI", 10))
        for site, user in results:
            listbox.insert("end", f"{site} | {user}")
        listbox.pack(fill="both", expand=True)
        def show_selected():
            idx = listbox.curselection()
            if not idx:
                return
            selected = listbox.get(idx)
            site, user = selected.split(" | ")
            entry = next(e for e in self.passwords[site] if e['user'] == user)
            pw = decrypt(entry["password"])
            pwtop = tk.Toplevel(top)
            pwtop.title("Password Details")
            pwtop.geometry("350x220")
            frame2 = ttk.Frame(pwtop, padding=16)
            frame2.pack(fill="both", expand=True)
            ttk.Label(frame2, text=f"Site: {site}", font=("Segoe UI", 11, "bold")).pack(anchor="w")
            ttk.Label(frame2, text=f"User: {user}", font=("Segoe UI", 11)).pack(anchor="w", pady=(0,5))
            ttk.Label(frame2, text="Password:", font=("Segoe UI", 11)).pack(anchor="w")
            pw_var = tk.StringVar(value=pw)
            pwentry = ttk.Entry(frame2, textvariable=pw_var, width=28, show="*")
            pwentry.pack(anchor="w")
            def toggle():
                pwentry.config(show="" if pwentry.cget("show") == "*" else "*")
            ttk.Button(frame2, text="Show/Hide", width=10, command=toggle).pack(anchor="w", pady=3)
            ttk.Button(frame2, text="Copy to Clipboard", style="Accent.TButton", width=18,
                       command=lambda: [pyperclip.copy(pw_var.get()), messagebox.showinfo("Copied", "Password copied to clipboard!")]).pack(pady=5)
        ttk.Button(frame, text="Show Details", style="Accent.TButton", width=20, command=show_selected).pack(pady=8)

    def change_pin(self):
        # Only allow if they enter the current PIN
        pin = PinDialog(self.master, "Enter Old PIN").result
        if pin is None or not verify_pin(pin):
            messagebox.showerror("PIN Error", "Incorrect current PIN.")
            return
        new_pin = PinDialog(self.master, "Set New PIN", is_setting=True).result
        if new_pin is None:
            return
        set_pin(new_pin)
        messagebox.showinfo("PIN Changed", "PIN changed successfully.")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    if getattr(app, "authenticated", True):
        root.mainloop()
