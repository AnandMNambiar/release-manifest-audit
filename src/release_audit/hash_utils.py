import hashlib
from pathlib import Path


def calculate_sha3_512(file_path: Path) -> str:
    """Calculate the SHA3-512 hash of a file."""

    sha3 = hashlib.sha3_512()

    with file_path.open("rb") as file:
        while chunk := file.read(8192):
            sha3.update(chunk)

    return sha3.hexdigest()


def verify_sha3_512(file_path: Path, expected_hash: str) -> bool:
    """Return True when the file's SHA3-512 hash matches the expected hash."""

    actual_hash = calculate_sha3_512(file_path)

    return actual_hash.lower() == expected_hash.lower()