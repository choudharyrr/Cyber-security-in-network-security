import hashlib

def hash_password(password):
    # Hash the password using SHA-256 algorithm
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return hashed_password

def authenticate_user(username, password, stored_password):
    # Check if the username exists and compare the hashed passwords
    if username in users and hash_password(password) == stored_password:
        print("Authentication successful!")
    else:
        print("Authentication failed.")

# Example usage
users = {
    "alice": hash_password("password123"),
    "bob": hash_password("qwerty456"),
    # Add more users and hashed passwords here
}

# Simulate user authentication
username = input("Enter username: ")
password = input("Enter password: ")

if username in users:
    stored_password = users[username]
    authenticate_user(username, password, stored_password)
else:
    print("User not found.")
