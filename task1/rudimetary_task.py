from Crypto.Hash import SHA256
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# The purpose of this file is just to demonstrate that the pycryptodome is working.

print("SHA-256")

# SHA-256

h = SHA256.new()
message = b'attack the code at dawn'

h.update(message)
print("your original message is: " + message)

hashedtext = h.hexdigest()
print ("your hashed text is: " + hashedtext)

w_file = open('./sha256_enc.txt', 'wb')
w_file.write(hashedtext)
w_file.close()

# AES
print("AES:")  # for spacing purposes.

aes_key = b'dogsaregood12345'

cipher = AES.new(aes_key, AES.MODE_EAX)
data_to_encrypt = 'Nullum magnum ingenium sine mixture dementia fuit.'
print("Your original message: " + data_to_encrypt)

nonce = cipher.nonce
ciphertext, tag = cipher.encrypt_and_digest(data_to_encrypt)

print("Your encrypted message was: " + ciphertext)

w_file = open('./aes_cipher.bin', 'wb')
w_file.write(nonce)  # Write the nonce to the output file (will be required for decryption - fixed size)
w_file.write(tag)
w_file.write(ciphertext)
w_file.close()


#RSA

print("RSA:")

# Generating the key pair.
key = RSA.generate(1024)
private_key = key.export_key()
file_out = open("./my_private_key.pem", "wb")
file_out.write(private_key)
file_out.close()
print(private_key)

public_key = key.publickey().export_key()
file_out = open("./my_receiver.pem", "wb")
file_out.write(public_key)
file_out.close()
print(public_key)


data = "Attack At Dawn".encode("utf-8")
file_out = open("./encrypted_rsa.bin", "wb")

recipient_key = RSA.import_key(open("./my_receiver.pem").read())
session_key = get_random_bytes(16)

# Encrypt the session key with the public RSA key
cipher_rsa = PKCS1_OAEP.new(recipient_key)
enc_session_key = cipher_rsa.encrypt(session_key)

# Encrypt the data with the AES session key
cipher_aes = AES.new(session_key, AES.MODE_EAX)
ciphertext, tag = cipher_aes.encrypt_and_digest(data)
[ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
file_out.close()
