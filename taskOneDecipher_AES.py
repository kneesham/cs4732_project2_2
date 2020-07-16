from Crypto.Cipher import AES

# AES EXAMPLE
# used for the decryption of taskOneCipher_AES.py

aes_key = b'dogsaregood12345'

file_in = open('./encrypted_messages/aes_cipher.bin', 'rb')
nonce = file_in.read(16)
tag = file_in.read(16)
ciphered_data = file_in.read()
file_in.close()

# Decrypt and verify
cipher = AES.new(aes_key, AES.MODE_EAX, nonce)
plaintext = cipher.decrypt_and_verify(ciphered_data, tag) # Decrypt and verify with the tag

print("plaintext is: " + plaintext)
