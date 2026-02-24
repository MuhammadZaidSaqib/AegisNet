🔐 AegisNet – Secure Encrypted Multi-Client Chat System

A cyberpunk-styled, end-to-end encrypted multi-client chat application built with Python, Diffie-Hellman key exchange, and AES-GCM authenticated encryption.


<img width="1450" height="865" alt="Screenshot 2026-02-24 172852" src="https://github.com/user-attachments/assets/b3907cd0-724d-4044-a8a1-1d7e82f18c22" />

<img width="1019" height="686" alt="Screenshot 2026-02-24 173153" src="https://github.com/user-attachments/assets/04c37a71-a07f-47d4-95d2-ea6aa9a59153" />







🚀 Overview

AegisNet is a secure, multi-client chat system designed for:

🎓 University projects

💼 Internship portfolios

🔐 Cybersecurity demonstrations

🛡 Secure communication experiments

It combines:

Diffie-Hellman key exchange

AES-256-GCM encryption

Secure authentication

Private messaging

Online user discovery

Rate limiting

Logging

Modern PyQt GUI (Cyberpunk Mode 😎)

🛡 Security Architecture
🔐 Key Exchange

Each client performs:

Diffie-Hellman key exchange with server

Unique session key per connection

No hardcoded encryption keys

🔒 Encryption

AES-256-GCM (Authenticated Encryption)

Integrity + Confidentiality

All payloads encrypted (including auth)

🔑 Authentication

Register / Login system

Password hashing (bcrypt)

Encrypted credential exchange

💬 Features
👤 User System

Register new accounts

Login with existing credentials

Online user list

Join / Leave system notifications

💬 Messaging

Public chat

Private messaging (/pm username message)

Online users list (/users)

Timestamps

Error handling

Rate limiting (anti-spam)

🖥 GUI

PyQt-based desktop interface

Cyberpunk hacker theme

Secure channel indicator

Message bubbles

Real-time updates

🛡 Defensive Features

Rate limiting (max 5 messages / 5 seconds)

Server logging

Thread-safe multi-client handling

Encrypted protocol routing

🏗 Project Structure
AegisNet/
│
├── server/
│   ├── server.py
│   ├── auth.py
│   ├── encryption.py
│   ├── key_exchange.py
│   └── ...
│
├── client/
│   ├── network.py
│   ├── gui_login.py
│   ├── gui_chat.py
│   ├── encryption.py
│   ├── key_exchange.py
│   └── ...
│
├── logs/
│   └── server.log
│
├── run_server.py
├── run_client.py
├── requirements.txt
└── README.md
📦 Requirements
🐍 Python Version

Python 3.9+

📚 Required Packages

Install using:

pip install -r requirements.txt

Or manually:

pip install pyqt5 cryptography bcrypt
Example requirements.txt
PyQt5
cryptography
bcrypt
⚙️ How To Run
1️⃣ Clone Repository
git clone https://github.com/YOUR_USERNAME/AegisNet.git
cd AegisNet
2️⃣ Create Virtual Environment (Recommended)

Windows:

python -m venv venv
venv\Scripts\activate

Mac/Linux:

python3 -m venv venv
source venv/bin/activate
3️⃣ Install Dependencies
pip install -r requirements.txt
4️⃣ Run Server
python run_server.py

Server will start on:

127.0.0.1:5555
5️⃣ Run Client (GUI)

Open another terminal:

python run_client.py

Login/Register and start chatting securely.

🧪 How To Use
Public Message

Just type message normally.

Private Message
/pm username message

Example:

/pm ali hello bro
Show Online Users
/users
📜 Logging

Server logs stored in:

logs/server.log

Includes:

User authentication events

Public messages

Private messages

Disconnect events

🔥 Cyberpunk Mode UI

The GUI includes:

Neon green terminal style

Secure channel indicator

Encrypted messaging header

Dark hacker aesthetic

Scrollable encrypted feed

🎓 Educational Value

This project demonstrates:

Secure socket programming

Authenticated encryption

Key exchange protocols

Multi-threaded server design

Secure message routing

Rate limiting implementation

Secure authentication systems

⚠️ Disclaimer

This project is for:

Educational use

Research

Learning secure systems

It is not production-ready secure messaging software.

👨‍💻 Author

Muhammad Zaid Saqib
Cybersecurity & Software Engineering Student

🚀 Future Improvements

End-to-End encryption without server decryption

File transfer (encrypted)

Safety fingerprint verification

Self-destructing messages

Message persistence

Cloud deployment

Docker containerization

Web-based version (FastAPI + React)

🛡 Why AegisNet?

"Aegis" means shield.

AegisNet represents a secure communication shield built from the ground up.
