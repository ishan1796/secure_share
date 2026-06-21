import random
import string
import re

def generate_secureshare_id() -> str:
    """Generate a random SecureShare ID like 'SS-A1B2C3D4'."""
    # Format: SS- followed by 8 characters of uppercase letters and digits
    chars = string.ascii_uppercase + string.digits
    random_part = "".join(random.choices(chars, k=8))
    return f"SS-{random_part}"

def is_valid_email(email: str) -> bool:
    """Validate email format using standard regex."""
    email_regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return bool(re.match(email_regex, email))

def is_valid_secureshare_id(secure_id: str) -> bool:
    """Validate SecureShare ID format (SS- followed by 8 alphanumeric uppercase chars)."""
    id_regex = r"^SS-[A-Z0-9]{8}$"
    return bool(re.match(id_regex, secure_id))

def format_size(size_in_bytes: int) -> str:
    """Format file size in bytes to a human-readable string (KB, MB, etc.)."""
    if size_in_bytes < 1024:
        return f"{size_in_bytes} B"
    elif size_in_bytes < 1024 * 1024:
        return f"{size_in_bytes / 1024:.2f} KB"
    elif size_in_bytes < 1024 * 1024 * 1024:
        return f"{size_in_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{size_in_bytes / (1024 * 1024 * 1024):.2f} GB"
