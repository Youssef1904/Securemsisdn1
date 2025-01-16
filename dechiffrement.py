from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import base64
import pandas as pd

# Lire la clé privée RSA
with open('private.pem', 'rb') as f:
    private_key = RSA.import_key(f.read())

# Lire la clé AES chiffrée
with open('encrypted_aes_key.bin', 'rb') as f:
    encrypted_aes_key = f.read()

# Déchiffrer la clé AES avec la clé privée RSA
cipher_rsa = PKCS1_OAEP.new(private_key)
aes_key = cipher_rsa.decrypt(encrypted_aes_key)

# Lire les MSISDN chiffrés depuis le fichier Excel
df = pd.read_excel('encrypted_msisdn_data.xlsx')
encrypted_msisdn_list = df['MSISDN'].tolist()

# Fonction pour déchiffrer chaque MSISDN avec AES
def decrypt_msisdn(msisdn, aes_key):
    data = base64.b64decode(msisdn)
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    msisdn = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return msisdn.decode('utf-8')

# Déchiffrer tous les MSISDN
df['decrypted_MSISDN'] = df['MSISDN'].apply(lambda enc: decrypt_msisdn(enc, aes_key))

# Sauvegarder les MSISDN déchiffrés dans un nouveau fichier Excel
df.drop(columns=['MSISDN'], inplace=True)
df.to_excel('decrypted_msisdn_data.xlsx', index=False)
