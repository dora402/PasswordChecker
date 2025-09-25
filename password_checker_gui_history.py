import tkinter as tk
from tkinter import messagebox
import re
import hashlib
import random
import string

# Store password history
password_history = []

# Function to check password strength
def check_password():
    password = entry.get()
    if not password:
        messagebox.showwarning("Input Error", "Please enter a password!")
        return

    # Rules
    length_rule = len(password) >= 8
    uppercase_rule = re.search(r"[A-Z]", password) is not None
    lowercase_rule = re.search(r"[a-z]", password) is not None
    number_rule = re.search(r"[0-9]", password) is not None
    special_rule = re.search(r"[!@#$%^&*(),.?\":{}|<>]", password) is not None

    # Overall strength
    score = sum([length_rule, uppercase_rule, lowercase_rule, number_rule, special_rule])
    if score <= 2:
        strength = "Weak"
        color = "red"
    elif score <= 4:
        strength = "Medium"
        color = "orange"
    else:
        strength = "Strong"
        color = "green"

    # Suggestions
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

    # Common password check
    common_passwords = ["123456", "password", "12345678", "qwerty", "abc123", "111111", "letmein", "1234", "12345", "123456789"]
    common_warning = ""
    if password.lower() in common_passwords:
        common_warning = "Warning: This password is very common!\n"

    # Hash
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    # Store in history
    password_history.append((password, hashed_password))

    # Display results
    result_label.config(text="", fg="black")
    result_label.config(text=f"Password Strength: {strength}", fg=color)
    suggestions_text.config(state="normal")
    suggestions_text.delete("1.0", tk.END)
    if common_warning:
        suggestions_text.insert(tk.END, common_warning + "\n", "common")
    if suggestions:
        suggestions_text.insert(tk.END, "Suggestions:\n", "header")
        for sug in suggestions:
            suggestions_text.insert(tk.END, sug + "\n", "suggestion")
    suggestions_text.insert(tk.END, f"\nSHA-256 hash:\n{hashed_password}", "hash")
    suggestions_text.config(state="disabled")

# Function to generate a strong password
def generate_password():
    length = 12
    characters = string.ascii_letters + string.digits + "!@#$%^&*(),.?\":{}|<>"
    new_password = ''.join(random.choice(characters) for _ in range(length))
    entry.delete(0, tk.END)
    entry.insert(0, new_password)
    check_password()

# Function to show password history
def show_history():
    history_window = tk.Toplevel(root)
    history_window.title("Password History")
    history_window.geometry("500x400")
    history_window.resizable(False, False)

    history_label = tk.Label(history_window, text="Password History (Plain + SHA-256 Hash):", font=("Arial", 12, "bold"))
    history_label.pack(pady=10)

    history_text = tk.Text(history_window, width=60, height=20, font=("Arial", 11))
    history_text.pack(pady=10)
    scrollbar = tk.Scrollbar(history_window, command=history_text.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    history_text.config(yscrollcommand=scrollbar.set)

    for idx, (pwd, hsh) in enumerate(password_history, 1):
        history_text.insert(tk.END, f"{idx}. Password: {pwd}\n   SHA-256: {hsh}\n\n")

    history_text.config(state="disabled")

# GUI setup
root = tk.Tk()
root.title("Password Strength Checker")
root.geometry("600x600")
root.resizable(False, False)

# Instruction frame
instr_frame = tk.Frame(root)
instr_frame.pack(pady=10)
instr_label = tk.Label(instr_frame, text="Enter your password below:", font=("Arial", 14))
instr_label.pack()

# Entry frame
entry_frame = tk.Frame(root)
entry_frame.pack(pady=10)
entry = tk.Entry(entry_frame, width=30, show="*", font=("Arial", 12))
entry.pack()

# Button frame
button_frame = tk.Frame(root)
button_frame.pack(pady=10)
check_button = tk.Button(button_frame, text="Check Password", command=check_password, font=("Arial", 12), bg="blue", fg="white", width=18)
check_button.pack(side=tk.LEFT, padx=5)
generate_button = tk.Button(button_frame, text="Generate Strong Password", command=generate_password, font=("Arial", 12), bg="green", fg="white", width=22)
generate_button.pack(side=tk.LEFT, padx=5)
history_button = tk.Button(button_frame, text="Show History", command=show_history, font=("Arial", 12), bg="purple", fg="white", width=12)
history_button.pack(side=tk.LEFT, padx=5)

# Result frame
result_frame = tk.Frame(root)
result_frame.pack(pady=15)
result_label = tk.Label(result_frame, text="", font=("Arial", 14), justify="left")
result_label.pack()

# Suggestions text box with scrollbar
suggestions_frame = tk.Frame(root)
suggestions_frame.pack(pady=10)
suggestions_text = tk.Text(suggestions_frame, height=15, width=70, font=("Arial", 11), wrap="word")
suggestions_text.pack(side=tk.LEFT)
scrollbar = tk.Scrollbar(suggestions_frame, command=suggestions_text.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
suggestions_text.config(yscrollcommand=scrollbar.set)
suggestions_text.tag_configure("header", font=("Arial", 12, "bold"))
suggestions_text.tag_configure("suggestion", foreground="blue")
suggestions_text.tag_configure("common", foreground="red", font=("Arial", 12, "bold"))
suggestions_text.tag_configure("hash", foreground="green")

suggestions_text.config(state="disabled")

# Run GUI
root.mainloop()
