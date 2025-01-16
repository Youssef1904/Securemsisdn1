from Crypto.PublicKey import RSA
import os

# Print the current working directory
print("Current Working Directory:", os.getcwd())

# Paths for key files
private_key_path = 'private.pem'
public_key_path = 'public.pem'

# Check if keys already exist
if os.path.exists(private_key_path) and os.path.exists(public_key_path):
    print("Keys already exist. Skipping key generation.")
else:
    # Generate RSA keys
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    # Save the keys to files
    with open(private_key_path, 'wb') as f:
        f.write(private_key)

    with open(public_key_path, 'wb') as f:
        f.write(public_key)

    print("New RSA key pair generated and saved.")

    
