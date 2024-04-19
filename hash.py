import hashlib
import base64
import pyperclip

def generate_output(input_string):
    # Convert input string to bytes
    input_bytes = input_string.encode()

    # List of hashing algorithms to use
    algorithms = [
        hashlib.sha256, 
        hashlib.sha512, 
        hashlib.sha3_256, 
        hashlib.blake2b,
        hashlib.sha1,
        hashlib.sha224,
        hashlib.sha384,
        hashlib.md5
    ]

    # Concatenate multiple hash outputs
    concatenated_hash = b""
    for algorithm in algorithms:
        hash_output = algorithm(input_bytes).digest()
        concatenated_hash += hash_output

    # Encode the concatenated hash output using base64
    encoded_output = base64.b64encode(concatenated_hash)

    # Decode the encoded output to a string
    output = encoded_output.decode()

    # Copy the output to the clipboard
    pyperclip.copy(output)

    # Return the output
    return output

def main():
    while True:
        # Prompt user for input
        user_input = input("Enter your input (or type 'exit' to quit): ")

        # Check if the user wants to exit
        if user_input.lower() == "exit":
            print("Exiting the program.")
            break

        # Generate the output based on the input
        output = generate_output(user_input)

        # Print the output
        print("Output:", output)
        print("Output copied to clipboard. You can now paste it.")

if __name__ == "__main__":
    main()
