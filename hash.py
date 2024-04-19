import hashlib
import base64
import pyperclip

def generate_output(input_string):
    try:
        input_bytes = input_string.encode()
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
        concatenated_hash = b""
        for algorithm in algorithms:
            hash_output = algorithm(input_bytes).digest()
            concatenated_hash += hash_output
        encoded_output = base64.b64encode(concatenated_hash)
        output = encoded_output.decode()
        pyperclip.copy(output)
        return output
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def main():
    while True:
        try:
            user_input = input("Enter your input (or type 'exit' to quit): ")
            if user_input.lower() == "exit":
                print("Exiting the program.")
                break
            output = generate_output(user_input)
            if output:
                print("Output:", output)
                print("Output copied to clipboard. You can now paste it.")
            else:
                print("Failed to generate output.")
        except KeyboardInterrupt:
            print("\nExiting the program.")
            break

if __name__ == "__main__":
    main()
