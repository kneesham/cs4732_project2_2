from Crypto.Cipher import AES

# AES EXAMPLE
# The purpose of this file is just to demonstrate that the pycryptodome is working.
# This file will simply encrypt some text and store that in a file.


aes_key = b'dogsaregood12345'

cipher = AES.new(aes_key, AES.MODE_EAX)
data_to_encrypt = 'Nullum magnum ingenium sine mixture dementia fuit.'


nonce = cipher.nonce
ciphertext, tag = cipher.encrypt_and_digest(data_to_encrypt)

print("Your encrypted message was: " + ciphertext)

w_file = open('./encrypted_messages/aes_cipher.bin', 'wb')
w_file.write(nonce)  # Write the nonce to the output file (will be required for decryption - fixed size)
w_file.write(tag)
w_file.write(ciphertext)
w_file.close()

