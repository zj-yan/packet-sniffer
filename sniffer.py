import argparse
import os

import getpass
import bcrypt
# using bcrypt library instead of the simple SHA-256 hash

from core import PacketSniffer
from output import OutputToScreen


# Using a more secure password hashing algorithm: bcrypt, instead of a simple hash function.
# Bcrypt is designed to be slow and computationally intensive,
# making it more resistant to brute-force attacks.
def hash_password(password):
    # Implement a salt when hashing passwords.
    # This adds an extra layer of security by ensuring that even if two users have the same password,
    # their hashed passwords will be different.
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed.decode()

def verify_password(stored_password_hash, provided_password):
    return bcrypt.checkpw(provided_password.encode(), stored_password_hash.encode())

# Hashed password for admin 
admin_password_hash = hash_password('admin')


parser = argparse.ArgumentParser(description="Network packet sniffer")
parser.add_argument(
    "-i", "--interface",
    type=str,
    default=None,
    help="Interface from which Ethernet frames will be captured (monitors "
         "all available interfaces by default)."
)
parser.add_argument(
    "-d", "--data",
    action="store_true",
    help="Output packet data during capture."
)

parser.add_argument(
    "-r", "--role",
    type=str,
    default='end-user',
    choices=['admin', 'end-user', 'developer'],
    help="Role of the user running the sniffer."
)




_args = parser.parse_args()

if os.getuid() != 0:
    raise SystemExit("Error: Permission denied. This application requires "
                    "administrator privileges to run.")


password = None
if _args.role == 'admin':
    entered_password = getpass.getpass("Enter admin password: ")
    if verify_password(admin_password_hash, entered_password):
        password = entered_password
    else:
        raise SystemExit("Invalid password. Exiting.")


sniffer = PacketSniffer()
output_screen = OutputToScreen(
    subject=sniffer,
    display_data=_args.data,
    user_role=_args.role
)

try:
    for _ in sniffer.listen(_args.interface):
        pass
except KeyboardInterrupt:
    raise SystemExit("[!] Aborting packet capture...")

