"""Sample application with compliance violations."""

# Hardcoded secret (violation)
API_KEY = "sk_live_1234567890abcdef"
DATABASE_PASSWORD = "super_secret_password_123"

# Configuration
DEBUG = True
HOST = "0.0.0.0"  # Insecure binding

def connect_database():
    """Connect to database."""
    # Another hardcoded secret
    password = "admin123"
    return f"postgresql://user:{password}@localhost/db"

if __name__ == "__main__":
    print("App running")
