# Bastion: CLI password manager

## Overview
Bastion is a terminal-based password manager written in Python that runs entirely from the command line and stores all password entries in a single encrypted binary file on your local machine. Access is gated by a master password, which is used both to verify your identity and to derive the encryption key that protects your data. No third-party vaults, no internet connection required.

---

## Features

- AES-256 encryption via Fernet (from the `cryptography` library)
- Master password verification using SHA-256
- Encryption key derivation using PBKDF2 with 480,000 iterations and a random salt
- Add, view, edit, and delete password entries
- Change master password with automatic re-encryption of all data
- No network access — everything stays local
- Color-coded terminal interface via `colorama`

---

## Security Model

Understanding how Bastion protects your data:

**Master password verification** — when you set a master password, its SHA-256 hash is stored in `master.hash`. On login, the hash of the input is compared against the stored hash. The plaintext password is never written to disk.

**Encryption key derivation** — your master password is not used directly as an encryption key. Instead, it is passed through PBKDF2-HMAC-SHA256 with a randomly generated 16-byte salt and 480,000 iterations to produce a 256-bit key. This makes brute-force attacks significantly slower. The salt is stored in `passwords.salt`.

**Data encryption** — all password entries are encrypted with Fernet (AES-128-CBC + HMAC-SHA256) using the derived key and written to `passwords.enc` as a binary file. Without the correct master password, the file is unreadable.

**Master password change** — when you change the master password, Bastion decrypts all entries with the old key, generates a new salt, derives a new key from the new password, and re-encrypts everything. The old salt is deleted. No data is left encrypted with the old key.

---

## Requirements

- Python 3.10 or higher
- The following Python packages:

| Package | Purpose |
|---------|---------|
| `cryptography` | AES encryption and PBKDF2 key derivation |
| `colorama` | Colored terminal output |

---

## Installation

**1. Clone or download the repository**

```bash
git clone https://github.com/your-username/bastion.git
cd bastion
```

**2. Install dependencies**

```bash
pip install cryptography colorama
```

**3. Run the program**

```bash
python passwords.py
```

On first launch, you will be prompted to create a master password. This generates `master.hash` and prepares the encryption salt for subsequent use.

---

## File Structure

```
bastion/
├── passwords.py      # Main program
├── master.hash       # SHA-256 hash of the master password (created on first run)
├── passwords.enc     # Encrypted password entries (created on first save)
└── passwords.salt    # Random salt for key derivation (created on first save)
```

> All three data files are generated automatically. Do not manually edit or delete `passwords.salt` — doing so will make your encrypted entries permanently unrecoverable.

---

## Usage

After launching, you will see the main menu:

```
  +------ MAIN MENU ------+
  | 1. Add entry          |
  | 2. View entries       |
  | 3. Edit entry         |
  | 4. Delete entry       |
  | 5. Change master pass |
  | 6. Exit               |
  +-----------------------+
```

### 1. Add entry

Prompts for a service name, username or email, and password. The entry is appended to the encrypted file. Type `0` at any prompt to cancel and return to the menu.

### 2. View entries

Displays a numbered list of saved service names. Select a number to reveal the full entry (service, username, and password). Type `0` to go back.

### 3. Edit entry

Displays the list of entries. Select one to edit its fields. Each field shows the current value in brackets — press Enter to keep it unchanged, or type a new value to replace it.

```
Service name   [github]: 
Username/email [user@example.com]: new@example.com
Password       [oldpass123]: 
```

### 4. Delete entry

Displays the list of entries. Select a number to permanently delete that entry. The remaining entries are re-encrypted and saved immediately.

### 5. Change master password

Asks for the current master password, then a new one. All entries are decrypted and re-encrypted with a freshly derived key. The old salt is discarded and a new one is generated.

### 6. Exit

Closes the program. No data is held in memory after exit.

---

## Changing the Master Password

When you change the master password, the program:

1. Verifies the current password against `master.hash`
2. Decrypts all entries from `passwords.enc` using the old key
3. Updates `master.hash` with the hash of the new password
4. Deletes `passwords.salt` and generates a new random salt
5. Derives a new encryption key from the new password and the new salt
6. Re-encrypts all entries and writes them to `passwords.enc`

This process ensures no data remains accessible with the old password after the change.
