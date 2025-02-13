"""This contains the coding challenge for 02/12/25 - The ultimate logic gauntlet"""
from string import printable
import base64
import sys
from cryptography.fernet import Fernet

KEY = "sQax5USVW0d1JQIChNfyJRBqL1JLVffOtRAAQuWYBeU="
PASSWORD = "DecryptPassword"
cypher_suite = Fernet(KEY)

def caesar_cypher(to_encode: str, shift: int = 3) -> str:
    table = str.maketrans(printable, printable[shift:] + printable[:shift])
    return to_encode.translate(table)

def caesar_decypher(to_encode: str, shift: int = 3) -> str:
    table = str.maketrans(printable, printable[-shift:] + printable[:-shift])
    return to_encode.translate(table)

def custom_encryption(to_encode: str) -> str:
    return "".join(chr(255 - ord(c)) for c in to_encode)

def custom_decryption(to_encode: str) -> str:
    return "".join(chr(255 - ord(c)) for c in to_encode)

def encrypt(to_encode: str) -> str:
    step1 = caesar_cypher(to_encode)
    step2 = base64.b64encode(step1.encode()).decode()
    step3 = custom_encryption(step2)
    step4 = cypher_suite.encrypt(step3.encode()).decode()
    return step4

def decrypt(to_encode: str) -> str:
    user_password = input("Enter decryption password: ")
    if user_password != PASSWORD:
        print("Wrong password")
        sys.exit(1)
    step1 = cypher_suite.decrypt(to_encode.encode()).decode()
    step2 = custom_decryption(step1)
    step3 = base64.b64decode(step2).decode()
    step4 = caesar_decypher(step3)
    return step4

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: challenge.py <encode|decode> text_to_encode")
        sys.exit(1)

    action = sys.argv[1]
    text = sys.argv[2]

    if action == "encode":
        print(f"Encrypted text: {encrypt(text)}")
    elif action == "decode":
        print(f"Decrypted text: {decrypt(text)}")
    else:
        print("Usage: challenge.py <encode|decode> text_to_encode")