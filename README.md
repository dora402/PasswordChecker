Password Strength Checker (Secure Edition)

A secure password strength checker with GUI, hashing, encryption, and a local password vault. Designed to help users create strong passwords and securely manage them.

## Features

- **GUI Interface:** User-friendly interface built with Tkinter.
- **Password Strength Analysis:**
  - Minimum 8 characters
  - At least one uppercase letter
  - At least one lowercase letter
  - At least one number
  - At least one special character
- **Color-coded feedback** on password strength.
- **Improvement suggestions** for weak passwords.
- **SHA-256 hashing** of passwords.
- **AES encryption** for secure local storage (password vault).
- **Password History Viewer** to track stored passwords.

## Installation

1. Clone the repository:
```bash
git clone https://github.com/dora402/PasswordChecker.git
Navigate to the project folder:

bash
Copy code
cd PasswordChecker
Install required dependencies:

bash
Copy code
pip install -r requirements.txt
Run the application:

bash
Copy code
python password_checker_final.py
Usage
Open the application GUI.

Enter a password to check its strength.

View suggestions and strengthen your password.

Save passwords securely in the local vault.

Access the history viewer to see stored passwords.

Screenshots
Main GUI

Password Analysis Result

Password Generator

History Viewer

Folder Structure
markdown
Copy code
PasswordChecker/
│── password_checker_final.py
│── password_checker_gui_history.py
│── README.md
│── requirements.txt
│── .gitignore
│── LICENSE
│── screenshots/
     ├── main_gui.png
     ├── analysis_result.png
     ├── generator.png
     └── history_viewer.png
.gitignore
Excludes sensitive files and caches:

markdown
Copy code
vault.dat
vault.meta
__pycache__/
*.pyc
License
This project is licensed under the MIT License.

Author
Name: Suhani Chaturvedi

GitHub: dora402

Focus: Cybersecurity & Python projects
