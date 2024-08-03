import hashlib
import base64
import pyperclip

# Generate a strong password from a given input string
def generate_password(input_string):
    # Length of the password
    password_length = 20

    # Use SHA-256 hash of the input string as the basis for the password
    hashed_input = hashlib.sha256(input_string.encode()).digest()

    # Use the first 20 bytes of the hash as the password
    password_bytes = hashed_input[:password_length]

    # Convert the bytes to a base64-encoded string
    password = base64.b64encode(password_bytes).decode()

    return password

# Generate output using a hashed password
def generate_output(input_string):
    # Generate a strong password from the input
    password = generate_password(input_string)

    # Copy the password to the clipboard
    pyperclip.copy(password)

    return password

# Main function to interact with the user
def main():
    while True:
        user_input = input("Enter your input (or type 'exit' to quit): ")
        if user_input.lower() == "exit":
            print("Exiting the program.")
            break
        output = generate_output(user_input)
        print("Password:", output)
        print("Password copied to clipboard. You can now paste it.")

if __name__ == "__main__":
    main()