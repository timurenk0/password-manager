# Password Manager App

This is a lightweight, secure password manager built with Python and Flask. It allows users to register, log in, securely store encrypted passwords, and retrieve them using RSA-based encryption and decryption — all through a clean and responsive web interface.

---

## How to Run

### 1. Clone the repo
```
git clone https://github.com/timurenk0/password-manager.git
cd password-manager
```

### 2. Create and Activate venv
```
python -m venv venv

# On Windows:
venv\Scripts\activate

#on macOs/Linux:
source venv/bin/activate
```

### 3. Install Dependencies
```
pip install -r requirements.txt
```

### 4. Run the Application
```
cd backend
python app.py
```


## 🚀 Features

- 🔐 **User Registration & Authentication**  
  Secure sign-up/login system with hashed passwords (bcrypt).

- 🧠 **Password Encryption**  
  Passwords are encrypted using asymmetric encryption (public/private RSA key pair).

- 🗂️ **Personal Vault Dashboard**  
  Users can view, add, and decrypt stored passwords.

- 🔑 **Private Key Handling**  
  Upon registration, users receive a private key required for decryption (never stored).

- 🎨 **Modern Web UI**  
  Responsive interface using HTML + custom CSS.

---

## 📁 Project Structure
```
password-manager/
├── backend/
│ ├── app.py                    # Main Flask app
│ ├── auth.py                   # Authentication logic
│ ├── database.py               # Database initialization
│ └── password_generator.py     # RSA encryption/decryption logic
│ └── database.db               # SQLite database file
├── frontend/
│ ├── register.html
│ ├── login.html
│ ├── dashboard.html
│ └── add_password.html
├── static/
│ └── auth_styles.css           # CSS styling for UI
├── requirements.txt            # Project dependencies
└── README.md                   
```