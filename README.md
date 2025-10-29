# Secure Password Manager (Python)

A minimal, secure password manager written in Python. It uses cryptography.Fernet for robust, authenticated encryption. A master password is required to access the vault. Entries can be added, retrieved, updated, deleted, and listed. Plain-text secrets are never stored on disk or logged.

## Features
- Master password authentication with strong key derivation (PBKDF2-HMAC-SHA256)
- Authenticated encryption with Fernet (AES-128-CBC + HMAC-SHA256)
- Encrypted vault file; no plain-text passwords are stored
- CRUD operations: add, get, update, delete, list
- No secrets in logs; optional `--show` flag to print a password intentionally
- Default vault location: `vault/` directory (git-ignored)

## Quick start
1. Ensure Python 3.9+ is installed.
2. Create a virtualenv and install dependencies:
   - Windows PowerShell:
     ```powershell
     python -m venv .venv
     .\.venv\Scripts\python.exe -m pip install -U pip
     .\.venv\Scripts\python.exe -m pip install -r requirements.txt
     ```
3. Initialize a new vault:
   ```powershell
   .\.venv\Scripts\python.exe .\main.py init
   ```
4. Add an entry:
   ```powershell
   .\.venv\Scripts\python.exe .\main.py add --name github --username alice
   # You'll be prompted for the entry password securely.
   ```
5. Retrieve an entry (without showing the secret):
   ```powershell
   .\.venv\Scripts\python.exe .\main.py get --name github
   # Use --show to print the password if you accept the risk of shoulder-surfing.
   ```

## Commands
- `init` — create a new vault; prompts for a master password
- `add` — add a credential (prompts for secret)
- `get` — fetch credential; prints username and either hides the password or prints it with `--show`
- `update` — update existing credential
- `delete` — remove credential
- `list` — list entry names only
- `change-master` — rotate master password and re-encrypt vault

Run `python main.py -h` for details.

## Security notes and best practices
- The master password is never stored; a random salt and a key-check token are stored in `vault/config.json`.
- Keys are derived with PBKDF2HMAC-SHA256 with a high iteration count (configurable, default 390k).
- The vault file (`vault/vault.dat`) holds only ciphertext; JSON is encrypted as one blob to minimize metadata leakage.
- No secrets are logged. Be cautious using `--show` which prints a password to stdout by your explicit request.
- Back up `vault/` securely; losing it (or the master password) makes recovery impossible.
- Prefer long, high-entropy master passwords. Consider a password manager-generated passphrase.
- Vault integrity and confidentiality rely on OS security for the `vault/` directory permissions.

## Disclaimer
This is an educational reference implementation. Review and test thoroughly before using for high-risk scenarios.
