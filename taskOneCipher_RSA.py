from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

# Generating the key pair.
key = RSA.generate(2048)
private_key = key.export_key()
file_out = open("./encrypted_messages/my_private_key.pem", "wb")
file_out.write(private_key)
file_out.close()
print(private_key)

public_key = key.publickey().export_key()
file_out = open("./encrypted_messages/my_receiver.pem", "wb")
file_out.write(public_key)
file_out.close()
print(public_key)


data = "Attack At Dawn".encode("utf-8")
file_out = open("./encrypted_messages/encrypted_rsa.bin", "wb")

recipient_key = RSA.import_key(open("./encrypted_messages/my_receiver.pem").read())
session_key = get_random_bytes(16)

# Encrypt the session key with the public RSA key
cipher_rsa = PKCS1_OAEP.new(recipient_key)
enc_session_key = cipher_rsa.encrypt(session_key)

# Encrypt the data with the AES session key
cipher_aes = AES.new(session_key, AES.MODE_EAX)
ciphertext, tag = cipher_aes.encrypt_and_digest(data)
[ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
file_out.close()
