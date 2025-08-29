#!/usr/bin/env python3
"""
Custom Password Cracker

This script performs a simple dictionary attack against a hashed password.
Given a target hash and a wordlist, it attempts to find the plaintext
password by hashing each word from the list and comparing it to the target.

Usage:
    python password_cracker.py <hash> <algorithm> <wordlist_file>

- <hash>: The target hashed password (e.g., obtained from a shadow file).
- <algorithm>: The hashing algorithm used (md5 or sha256).
- <wordlist_file>: Path to a file containing potential passwords, one per line.

Note: This tool is for educational purposes. Only use it against systems you
have permission to test.
"""
import hashlib
import sys


def crack_password(hash_value: str, algorithm: str, wordlist_path: str) -> str | None:
    """Attempt to crack the given hash using the specified algorithm and wordlist.

    Args:
        hash_value (str): The target hash to crack.
        algorithm (str): Hash algorithm ("md5" or "sha256").
        wordlist_path (str): Path to the wordlist file.

    Returns:
        str | None: The cracked password if found, otherwise None.
    """
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as wordlist:
            for word in wordlist:
                word = word.strip()
                if not word:
                    continue
                # Compute the hash of the current word using the specified algorithm
                if algorithm.lower() == "md5":
                    hashed = hashlib.md5(word.encode()).hexdigest()
                elif algorithm.lower() == "sha256":
                    hashed = hashlib.sha256(word.encode()).hexdigest()
                else:
                    raise ValueError("Unsupported algorithm. Use md5 or sha256.")

                # Compare the computed hash to the target hash
                if hashed == hash_value.lower():
                    return word
    except FileNotFoundError:
        print(f"Wordlist file not found: {wordlist_path}")
    except Exception as exc:
        print(f"Error occurred: {exc}")
    return None


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python password_cracker.py <hash> <algorithm> <wordlist_file>")
        sys.exit(1)

    target_hash = sys.argv[1]
    algorithm = sys.argv[2]
    wordlist_file = sys.argv[3]

    print(f"[*] Starting dictionary attack using {algorithm.upper()}...")
    result = crack_password(target_hash, algorithm, wordlist_file)

    if result:
        print(f"[+] Password found: {result}")
    else:
        print("[-] Password not found in the provided wordlist.")
