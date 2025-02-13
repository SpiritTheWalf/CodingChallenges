"""This contains the coding challenge for 02/12/25 - The ultimate logic gauntlet"""
from cryptography.fernet import Fernet
import base64
import sys

# Generate a key
KEY = "sQax5USVW0d1JQIChNfyJRBqL1JLVffOtRAAQuWYBeU="
cypher_suite = Fernet(KEY)

def caesar_cypher(to_encode: str, shift: int = 3) -> str:
    return "".join(chr((ord(c) - 32 + shift) % 95 + 32) if 32 <= ord(c) <= 126 else c for c in to_encode)

def caesar_decypher(to_encode: str, shift: int = 3) -> str:
    return caesar_cypher(to_encode, -shift)

def encrypt(to_encode: str) -> str:
    step1 = caesar_cypher(to_encode)
    step2 = base64.b64encode(step1.encode()).decode()
    step3 = cypher_suite.encrypt(step2.encode()).decode()
    return step3

def decrypt(to_encode: str) -> str:
    step1 = cypher_suite.decrypt(to_encode.encode()).decode()
    step2 = base64.b64decode(step1).decode()
    step3 = caesar_decypher(step2)
    return step3

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