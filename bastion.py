import os
import base64
import hashlib
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from colorama import init, Fore, Style

init()

HASH_FILE = "master.hash"
DATA_FILE  = "passwords.enc"
SALT_FILE  = "passwords.salt"

PBKDF2_ITERATIONS = 480_000


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def load_salt() -> bytes:
    if os.path.exists(SALT_FILE):
        with open(SALT_FILE, "rb") as f:
            return f.read()
    salt = os.urandom(16)
    with open(SALT_FILE, "wb") as f:
        f.write(salt)
    return salt


def set_master_password():
    password = input(Fore.YELLOW + "Create a master password: " + Style.RESET_ALL)
    with open(HASH_FILE, "w") as f:
        f.write(hash_password(password))
    return password


def verify_master_password():
    if not os.path.exists(HASH_FILE):
        print(Fore.CYAN + "No master password configured." + Style.RESET_ALL)
        return set_master_password()

    while True:
        password = input(Fore.YELLOW + "Master password (or 'exit'): " + Style.RESET_ALL)

        if password.lower() == "exit":
            print(Fore.MAGENTA + "\nGoodbye." + Style.RESET_ALL)
            exit()

        with open(HASH_FILE, "r") as f:
            stored_hash = f.read().strip()

        if hash_password(password) == stored_hash:
            return password

        print(Fore.RED + "Wrong password. Try again.\n" + Style.RESET_ALL)


def parse_entry(entry):
    parts    = entry.split(" | ")
    service  = parts[0].replace("service:",  "").strip() if len(parts) > 0 else ""
    username = parts[1].replace("username:", "").strip() if len(parts) > 1 else ""
    password = parts[2].replace("password:", "").strip() if len(parts) > 2 else ""
    return service, username, password


def format_entry(service, username, password):
    return f"service: {service} | username: {username} | password: {password}"


def load_entries(master_password: str) -> list[str]:
    if not os.path.exists(DATA_FILE):
        return []
    salt    = load_salt()
    key     = derive_key(master_password, salt)
    fernet  = Fernet(key)
    with open(DATA_FILE, "rb") as f:
        encrypted = f.read()
    try:
        decrypted = fernet.decrypt(encrypted).decode()
    except InvalidToken:
        print(Fore.RED + "Error: could not decrypt data file." + Style.RESET_ALL)
        return []
    return [line for line in decrypted.splitlines() if line.strip()]


def save_entries(entries: list[str], master_password: str):
    salt      = load_salt()
    key       = derive_key(master_password, salt)
    fernet    = Fernet(key)
    plaintext = "\n".join(entries).encode()
    encrypted = fernet.encrypt(plaintext)
    with open(DATA_FILE, "wb") as f:
        f.write(encrypted)


def add_entry(master_password: str):
    print(Fore.CYAN + "\nAdding new entry (type 0 to go back)..." + Style.RESET_ALL)

    service = input("Service name: ")
    if service == "0":
        return

    username = input("Username / email: ")
    if username == "0":
        return

    password = input("Password: ")
    if password == "0":
        return

    entries = load_entries(master_password)
    entries.append(format_entry(service, username, password))
    save_entries(entries, master_password)
    print(Fore.GREEN + "Entry saved." + Style.RESET_ALL)


def view_entries(master_password: str):
    entries = load_entries(master_password)
    if not entries:
        print(Fore.YELLOW + "No entries saved." + Style.RESET_ALL)
        return

    while True:
        print(Fore.GREEN + "\nSaved entries:" + Style.RESET_ALL)
        for i, entry in enumerate(entries, start=1):
            service, _, _ = parse_entry(entry)
            print(f"  {i}. {service}")
        print("  0. Back")

        choice = input("Select an entry: ").strip()
        if choice == "0":
            return

        if not choice.isdigit():
            print("Invalid input.")
            continue

        idx = int(choice) - 1
        if 0 <= idx < len(entries):
            service, username, pwd = parse_entry(entries[idx])
            print(Fore.MAGENTA + f"\n  Service:  {service}" + Style.RESET_ALL)
            print(Fore.MAGENTA + f"  Username: {username}" + Style.RESET_ALL)
            print(Fore.MAGENTA + f"  Password: {pwd}" + Style.RESET_ALL)
        else:
            print("Invalid selection.")


def delete_entry(master_password: str):
    entries = load_entries(master_password)
    if not entries:
        print("No entries saved.")
        return

    while True:
        print("\nEntries available for deletion:")
        for i, entry in enumerate(entries, start=1):
            service, _, _ = parse_entry(entry)
            print(f"  {i}. {service}")
        print("  0. Back")

        choice = input("Select an entry to delete: ").strip()
        if choice == "0":
            return

        if not choice.isdigit():
            print("Invalid input.")
            continue

        idx = int(choice) - 1
        if 0 <= idx < len(entries):
            del entries[idx]
            save_entries(entries, master_password)
            print(Fore.RED + "Entry deleted." + Style.RESET_ALL)
            return
        else:
            print("Invalid selection.")


def edit_entry(master_password: str):
    entries = load_entries(master_password)
    if not entries:
        print("No entries saved.")
        return

    while True:
        print("\nEntries available for editing:")
        for i, entry in enumerate(entries, start=1):
            service, _, _ = parse_entry(entry)
            print(f"  {i}. {service}")
        print("  0. Back")

        choice = input("Select an entry to edit: ").strip()
        if choice == "0":
            return

        if not choice.isdigit():
            print("Invalid input.")
            continue

        idx = int(choice) - 1
        if 0 <= idx < len(entries):
            old_service, old_username, old_password = parse_entry(entries[idx])

            new_service  = input(f"Service name   [{old_service}]: ").strip()  or old_service
            new_username = input(f"Username/email [{old_username}]: ").strip() or old_username
            new_password = input(f"Password       [{old_password}]: ").strip() or old_password

            entries[idx] = format_entry(new_service, new_username, new_password)
            save_entries(entries, master_password)
            print(Fore.GREEN + "Entry updated." + Style.RESET_ALL)
            return
        else:
            print("Invalid selection.")


def change_master_password(master_password: str) -> str:
    print(Fore.YELLOW + "\nChange master password (type 0 to go back)" + Style.RESET_ALL)

    current = input("Current master password: ")
    if current == "0":
        return master_password

    with open(HASH_FILE, "r") as f:
        stored_hash = f.read().strip()

    if hash_password(current) != stored_hash:
        print(Fore.RED + "Wrong password." + Style.RESET_ALL)
        return master_password

    new_password = input("New master password: ")
    if new_password == "0":
        return master_password

    entries = load_entries(master_password)

    with open(HASH_FILE, "w") as f:
        f.write(hash_password(new_password))

    if os.path.exists(SALT_FILE):
        os.remove(SALT_FILE)

    save_entries(entries, new_password)
    print(Fore.CYAN + "Master password updated." + Style.RESET_ALL)
    return new_password


def print_banner():
    print(Fore.CYAN + Style.BRIGHT)
    print("  ██████╗  █████╗ ███████╗████████╗██╗ ██████╗ ███╗   ██╗")
    print("  ██╔══██╗██╔══██╗██╔════╝╚══██╔══╝██║██╔═══██╗████╗  ██║")
    print("  ██████╔╝███████║███████╗   ██║   ██║██║   ██║██╔██╗ ██║")
    print("  ██╔══██╗██╔══██║╚════██║   ██║   ██║██║   ██║██║╚██╗██║")
    print("  ██████╔╝██║  ██║███████║   ██║   ██║╚██████╔╝██║ ╚████║")
    print("  ╚═════╝ ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝")
    print(Style.RESET_ALL)


def main():
    print_banner()
    master_password = verify_master_password()

    while True:
        print(Fore.YELLOW + "\n  +------ MAIN MENU ------+" + Style.RESET_ALL)
        print("  | 1. Add entry          |")
        print("  | 2. View entries       |")
        print("  | 3. Edit entry         |")
        print("  | 4. Delete entry       |")
        print("  | 5. Change master pass |")
        print("  | 6. Exit               |")
        print(Fore.YELLOW + "  +-----------------------+" + Style.RESET_ALL)

        choice = input("  Option: ").strip()

        if choice == "1":
            add_entry(master_password)
        elif choice == "2":
            view_entries(master_password)
        elif choice == "3":
            edit_entry(master_password)
        elif choice == "4":
            delete_entry(master_password)
        elif choice == "5":
            master_password = change_master_password(master_password)
        elif choice == "6":
            print(Fore.MAGENTA + "\nGoodbye." + Style.RESET_ALL)
            break
        else:
            print("Invalid option.")


if __name__ == "__main__":
    main()
