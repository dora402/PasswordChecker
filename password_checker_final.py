import tkinter as tk
from tkinter import messagebox, simpledialog
from tkinter import ttk
import re
import hashlib
import random
import string
import json
import time
import os
import base64
from math import log2

# cryptography imports
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# --- Config / Vault ----------------------------------------------------------------
VAULT_FILE = "vault.dat"
VAULT_META = "vault.meta"
KDF_ITERATIONS = 390000
HASH_ITERATIONS = 200000
backend = default_backend()

def derive_fernet_key(password: str, salt: bytes, iterations: int = KDF_ITERATIONS) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations, backend=backend)
    key = kdf.derive(password.encode())
    return base64.urlsafe_b64encode(key)

def create_vault(master_password: str):
    salt = os.urandom(16)
    key = derive_fernet_key(master_password, salt)
    f = Fernet(key)
    empty = json.dumps([]).encode()
    token = f.encrypt(empty)
    with open(VAULT_FILE, "wb") as wf:
        wf.write(token)
    meta = {"salt": base64.b64encode(salt).decode(), "kdf_iterations": KDF_ITERATIONS}
    with open(VAULT_META, "w") as mf:
        json.dump(meta, mf)
    return key, []

def load_vault(master_password: str):
    if not os.path.exists(VAULT_META) or not os.path.exists(VAULT_FILE):
        raise FileNotFoundError("Vault files missing")
    with open(VAULT_META, "r") as mf:
        meta = json.load(mf)
    salt = base64.b64decode(meta["salt"])
    iterations = meta.get("kdf_iterations", KDF_ITERATIONS)
    key = derive_fernet_key(master_password, salt, iterations)
    f = Fernet(key)
    with open(VAULT_FILE, "rb") as rf:
        token = rf.read()
    data = f.decrypt(token)
    history = json.loads(data.decode())
    return key, history

def save_vault(key: bytes, history: list):
    f = Fernet(key)
    data = json.dumps(history).encode()
    token = f.encrypt(data)
    with open(VAULT_FILE, "wb") as wf:
        wf.write(token)

# --- Utilities ---------------------------------------------------------------------
def estimate_entropy(password: str) -> float:
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        pool += 32
    if pool == 0:
        return 0.0
    return round(len(password) * log2(pool), 2)

def pbkdf2_hash_password(password: str, salt: bytes = None, iterations: int = HASH_ITERATIONS):
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return salt.hex(), dk.hex()

# --- Main App ----------------------------------------------------------------------
class PasswordCheckerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Strength Checker — Secure Edition")
        self.root.geometry("820x720")
        self.root.resizable(False, False)

        self.key = None
        self.history = []

        # Vault setup
        self.setup_vault()

        # Build UI
        self.build_ui()

    def setup_vault(self):
        if not os.path.exists(VAULT_META) or not os.path.exists(VAULT_FILE):
            messagebox.showinfo("Vault Setup", "No vault found. Create a master password to encrypt your history.")
            while True:
                mp1 = simpledialog.askstring("Create Master Password", "Enter a master password to encrypt your vault:", show='*')
                if mp1 is None:
                    messagebox.showerror("Exit", "Master password required. Exiting.")
                    self.root.destroy()
                    return
                mp2 = simpledialog.askstring("Confirm Master Password", "Confirm master password:", show='*')
                if mp2 is None:
                    messagebox.showerror("Exit", "Master password required. Exiting.")
                    self.root.destroy()
                    return
                if mp1 != mp2:
                    messagebox.showwarning("Mismatch", "Passwords do not match. Try again.")
                    continue
                self.key, self.history = create_vault(mp1)
                messagebox.showinfo("Vault Created", "Vault created and encrypted locally. Remember your master password!")
                break
        else:
            tries = 3
            while tries > 0:
                mp = simpledialog.askstring("Unlock Vault", "Enter your master password to unlock the vault:", show='*')
                if mp is None:
                    messagebox.showerror("Exit", "Master password required. Exiting.")
                    self.root.destroy()
                    return
                try:
                    self.key, self.history = load_vault(mp)
                    break
                except Exception:
                    tries -= 1
                    messagebox.showwarning("Incorrect", f"Master password incorrect. {tries} tries left.")
            if tries == 0 and self.key is None:
                messagebox.showerror("Locked", "Failed to unlock vault. Exiting.")
                self.root.destroy()
                return

    def build_ui(self):
        style = ttk.Style()
        style.theme_use('clam')

        header = ttk.Frame(self.root, padding=(12,8))
        header.pack(fill='x')
        ttk.Label(header, text="Password Strength Checker — Secure Edition", font=("Segoe UI", 16, "bold")).pack(anchor='center')

        main = ttk.Frame(self.root, padding=(12,10))
        main.pack(fill='both', expand=True)

        # Left: Input & generator
        left = ttk.Frame(main)
        left.grid(row=0, column=0, sticky='n', padx=(0,10))

        # Input area
        input_box = ttk.LabelFrame(left, text="Password Input", padding=(10,8))
        input_box.pack(fill='x', pady=(0,10))

        self.entry_var = tk.StringVar()
        self.entry = ttk.Entry(input_box, width=40, textvariable=self.entry_var, show="*")
        self.entry.grid(row=0, column=0, padx=6, pady=6, sticky='w')

        self.show_var = tk.IntVar()
        show_cb = ttk.Checkbutton(input_box, text="Show", variable=self.show_var, command=self.toggle_show)
        show_cb.grid(row=0, column=1, padx=6)

        check_btn = ttk.Button(input_box, text="Check Password", command=self.check_password)
        check_btn.grid(row=1, column=0, pady=8, sticky='w')

        copy_btn = ttk.Button(input_box, text="Copy Input", command=self.copy_input)
        copy_btn.grid(row=1, column=1, padx=6, pady=8)

        # Generator area
        gen_box = ttk.LabelFrame(left, text="Password Generator", padding=(10,8))
        gen_box.pack(fill='x')

        ttk.Label(gen_box, text="Length:").grid(row=0, column=0, sticky='w')
        self.gen_length = tk.IntVar(value=14)
        length_slider = ttk.Scale(gen_box, from_=8, to=32, orient='horizontal', variable=self.gen_length)
        length_slider.grid(row=0, column=1, sticky='we', padx=6)
        self.gen_length_label = ttk.Label(gen_box, text=str(self.gen_length.get()))
        self.gen_length_label.grid(row=0, column=2, padx=6)
        # update label when slider moves
        def update_len_label(*_):
            self.gen_length_label.config(text=str(int(self.gen_length.get())))
        self.gen_length.trace_add('write', lambda *a: update_len_label())

        # character class checkboxes
        self.use_upper = tk.IntVar(value=1)
        self.use_lower = tk.IntVar(value=1)
        self.use_digits = tk.IntVar(value=1)
        self.use_symbols = tk.IntVar(value=1)
        ttk.Checkbutton(gen_box, text="Uppercase", variable=self.use_upper).grid(row=1, column=0, sticky='w')
        ttk.Checkbutton(gen_box, text="Lowercase", variable=self.use_lower).grid(row=1, column=1, sticky='w')
        ttk.Checkbutton(gen_box, text="Digits", variable=self.use_digits).grid(row=1, column=2, sticky='w')
        ttk.Checkbutton(gen_box, text="Symbols", variable=self.use_symbols).grid(row=1, column=3, sticky='w')

        gen_btn = ttk.Button(gen_box, text="Generate", command=self.generate_password)
        gen_btn.grid(row=2, column=0, pady=8, sticky='w')

        copy_gen_btn = ttk.Button(gen_box, text="Copy Generated", command=self.copy_input)
        copy_gen_btn.grid(row=2, column=1, pady=8, padx=6, sticky='w')

        # Right: Results & history
        right = ttk.Frame(main)
        right.grid(row=0, column=1, sticky='n', padx=(10,0))

        res_box = ttk.LabelFrame(right, text="Analysis", padding=(10,8))
        res_box.pack(fill='both', expand=True)

        # Strength bar + label
        self.strength_var = tk.StringVar(value="—")
        ttk.Label(res_box, text="Strength:").grid(row=0, column=0, sticky='w')
        self.str_label = ttk.Label(res_box, textvariable=self.strength_var, font=("Segoe UI", 12, "bold"))
        self.str_label.grid(row=0, column=1, sticky='w', padx=6)

        self.pbar = ttk.Progressbar(res_box, length=360, mode='determinate', maximum=100)
        self.pbar.grid(row=1, column=0, columnspan=3, pady=(6,10))

        # Suggestions & hash box
        self.suggestions_text = tk.Text(res_box, height=14, width=60, wrap='word', font=("Segoe UI", 10))
        self.suggestions_text.grid(row=2, column=0, columnspan=3, pady=(6,6))
        self.suggestions_text.tag_configure("header", font=("Segoe UI", 10, "bold"))
        self.suggestions_text.tag_configure("common", foreground="red")
        self.suggestions_text.tag_configure("suggestion", foreground="#0d6efd")
        self.suggestions_text.tag_configure("hash", foreground="#198754")
        self.suggestions_text.config(state='disabled')

        # Buttons for history/export
        btns = ttk.Frame(right)
        btns.pack(pady=(8,0))
        ttk.Button(btns, text="Show History", command=self.show_history).pack(side='left', padx=6)
        ttk.Button(btns, text="Export Encrypted Vault", command=self.export_vault).pack(side='left', padx=6)

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status = ttk.Label(self.root, textvariable=self.status_var, relief='sunken', anchor='w')
        status.pack(fill='x', side='bottom')

    # --- UI helpers ---
    def toggle_show(self):
        if self.show_var.get():
            self.entry.config(show="")
        else:
            self.entry.config(show="*")

    def copy_input(self):
        val = self.entry.get()
        if not val:
            messagebox.showinfo("Copy", "No password to copy.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(val)
        self.status_var.set("Copied to clipboard")
        self.root.after(2000, lambda: self.status_var.set("Ready"))

    # --- Core features ---
    def check_password(self):
        password = self.entry.get()
        if not password:
            messagebox.showwarning("Input Error", "Please enter a password!")
            return

        length_rule = len(password) >= 8
        uppercase_rule = re.search(r"[A-Z]", password) is not None
        lowercase_rule = re.search(r"[a-z]", password) is not None
        number_rule = re.search(r"[0-9]", password) is not None
        special_rule = re.search(r"[!@#$%^&*(),.?\":{}|<>]", password) is not None

        score = sum([length_rule, uppercase_rule, lowercase_rule, number_rule, special_rule])
        if score <= 2:
            strength = "Weak"
            color = "#dc3545"  # red
        elif score <= 4:
            strength = "Medium"
            color = "#fd7e14"  # orange
        else:
            strength = "Strong"
            color = "#198754"  # green

        entropy = estimate_entropy(password)
        # Normalize progress bar: combine score (0-5) and entropy (cap at ~80 bits)
        norm_entropy = min(entropy, 80) / 80  # 0..1
        norm_score = score / 5  # 0..1
        bar_value = int((0.6 * norm_score + 0.4 * norm_entropy) * 100)
        self.pbar['value'] = bar_value
        self.strength_var.set(f"{strength} ({bar_value}%)")
        self.str_label.config(foreground=color)

        suggestions = []
        if not length_rule:
            suggestions.append("- Make your password at least 8 characters long")
        if not uppercase_rule:
            suggestions.append("- Add at least one uppercase letter (A-Z)")
        if not lowercase_rule:
            suggestions.append("- Add at least one lowercase letter (a-z)")
        if not number_rule:
            suggestions.append("- Add at least one number (0-9)")
        if not special_rule:
            suggestions.append("- Add at least one special character (!@#$%^&* etc.)")

        common_passwords = ["123456", "password", "12345678", "qwerty", "abc123",
                            "111111", "letmein", "1234", "12345", "123456789"]
        common_warning = ""
        common_flag = False
        if password.lower() in common_passwords:
            common_warning = "Warning: This password is very common!"
            common_flag = True

        salt_hex, hash_hex = pbkdf2_hash_password(password)
        entry = {
            "timestamp": int(time.time()),
            "strength": strength,
            "entropy_bits": entropy,
            "salt": salt_hex,
            "hash": hash_hex,
            "common": common_flag,
            "generated": False,
        }
        self.history.append(entry)
        save_vault(self.key, self.history)

        # Update suggestions text
        self.suggestions_text.config(state='normal')
        self.suggestions_text.delete("1.0", tk.END)
        if common_warning:
            self.suggestions_text.insert(tk.END, common_warning + "\n\n", "common")
        if suggestions:
            self.suggestions_text.insert(tk.END, "Suggestions:\n", "header")
            for s in suggestions:
                self.suggestions_text.insert(tk.END, s + "\n", "suggestion")
        self.suggestions_text.insert(tk.END, f"\nEstimated entropy: {entropy} bits\n", "hash")
        self.suggestions_text.insert(tk.END, f"\nStored (PBKDF2) hash (hex):\n{hash_hex}\n", "hash")
        self.suggestions_text.config(state='disabled')

        self.status_var.set("Password analyzed")
        self.root.after(2000, lambda: self.status_var.set("Ready"))

    def generate_password(self):
        length = int(self.gen_length.get())
        chars = ""
        if self.use_lower.get():
            chars += string.ascii_lowercase
        if self.use_upper.get():
            chars += string.ascii_uppercase
        if self.use_digits.get():
            chars += string.digits
        if self.use_symbols.get():
            chars += "!@#$%^&*(),.?\":{}|<>"
        if not chars:
            messagebox.showwarning("Generator Error", "Select at least one character class for generator.")
            return
        new_password = ''.join(random.choice(chars) for _ in range(length))
        self.entry_var.set(new_password)

        # store metadata (no plaintext on disk), then analyze
        salt_hex, hash_hex = pbkdf2_hash_password(new_password)
        entropy = estimate_entropy(new_password)
        entry = {
            "timestamp": int(time.time()),
            "strength": "Strong" if entropy >= 60 else "Medium",
            "entropy_bits": entropy,
            "salt": salt_hex,
            "hash": hash_hex,
            "common": False,
            "generated": True,
        }
        self.history.append(entry)
        save_vault(self.key, self.history)

        self.check_password()
        self.status_var.set("Generated a strong password")

    def show_history(self):
        history_window = tk.Toplevel(self.root)
        history_window.title("Password History (encrypted on disk)")
        history_window.geometry("760x520")
        history_window.resizable(False, False)

        label = ttk.Label(history_window, text="Stored Entries (NO plaintext) — timestamp, strength, entropy, salt, PBKDF2-hash, flags", font=("Segoe UI", 10, "bold"))
        label.pack(pady=8)

        text = tk.Text(history_window, width=92, height=26, font=("Courier", 10))
        text.pack(pady=6)
        sb = ttk.Scrollbar(history_window, command=text.yview)
        sb.pack(side='right', fill='y')
        text.config(yscrollcommand=sb.set)

        if not self.history:
            text.insert(tk.END, "No stored entries yet.\n")
        for idx, e in enumerate(self.history, 1):
            ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(e['timestamp']))
            text.insert(tk.END, f"{idx}. {ts} | Strength: {e['strength']} | Entropy: {e['entropy_bits']} bits | Generated: {e['generated']} | Common: {e['common']}\n")
            text.insert(tk.END, f"    salt: {e['salt']}\n    hash: {e['hash']}\n\n")
        text.config(state='disabled')

    def export_vault(self):
        save_as = simpledialog.askstring("Export Vault", "Enter filename to export the encrypted vault (e.g. backup_vault.dat):")
        if not save_as:
            return
        try:
            with open(VAULT_FILE, 'rb') as rf, open(save_as, 'wb') as wf:
                wf.write(rf.read())
            messagebox.showinfo("Exported", f"Encrypted vault exported to {save_as}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export: {e}")

# --- Entrypoint -------------------------------------------------------------------
def main():
    root = tk.Tk()
    app = PasswordCheckerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()