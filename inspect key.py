from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import os

def inspect_encryption_key():
    try:
        # Ensure the encrypted AES key file exists
        if not os.path.exists('encrypted_aes_key.bin'):
            raise FileNotFoundError("The encrypted AES key file ('encrypted_aes_key.bin') was not found.")

        # Load the encrypted AES key from the file
        with open('encrypted_aes_key.bin', 'rb') as f:
            encrypted_aes_key = f.read()

        # Load the RSA private key
        with open('private.pem', 'rb') as priv_file:
            private_key = RSA.import_key(priv_file.read())

        # Decrypt the AES key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        aes_key = cipher_rsa.decrypt(encrypted_aes_key)

        # Display the decrypted AES key
        print(f"Decrypted AES Key: {base64.b64encode(aes_key).decode('utf-8')}")

        return aes_key
    except FileNotFoundError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

inspect_encryption_key()
