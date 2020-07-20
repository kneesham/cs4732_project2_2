from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

print("\nENCRYPTING FILE LESS THAN 128-BITS USING A 128-BIT KEY: ")

aes_key_256 = get_random_bytes(16)  # will be a new 128 bit key.

cipher = AES.new(aes_key_256, AES.MODE_EAX)

data_from_file_lt128 = open('./message128.txt').read()  # lt128 = 'less than 128 bits.'
nonce = cipher.nonce
ciphertext, tag = cipher.encrypt_and_digest(data_from_file_lt128)

print("Your encrypted message " + ciphertext)

w_file = open('./task2_128_lt128.bin', 'wb')
w_file.write(nonce)
w_file.write(tag)
w_file.write(ciphertext)
w_file.close()

file_in = open('./task2_128_lt128.bin', 'rb')
nonce = file_in.read(16)
tag = file_in.read(16)
ciphered_data = file_in.read()
file_in.close()

# Decrypt and verify
cipher = AES.new(aes_key_256, AES.MODE_EAX, nonce)
plaintext = cipher.decrypt_and_verify(ciphered_data, tag)  # Decrypt and verify with the tag

print("plaintext is: " + plaintext)
print("")
print("ENCRYPTING FILE LESS THAN 128-BITS USING A 256-BIT KEY: ")

aes_key_256 = get_random_bytes(32)  # will be a new 128 bit key.

cipher = AES.new(aes_key_256, AES.MODE_EAX)

data_from_file_lt128 = open('./message128.txt').read()  # lt128 = 'less than 128 bits.'
nonce = cipher.nonce
ciphertext, tag = cipher.encrypt_and_digest(data_from_file_lt128)

print("Your encrypted message " + ciphertext)

w_file = open('./task2_128_lt128.bin', 'wb')
w_file.write(nonce)
w_file.write(tag)
w_file.write(ciphertext)
w_file.close()

file_in = open('./task2_128_lt128.bin', 'rb')
nonce = file_in.read(16)
tag = file_in.read(16)
ciphered_data = file_in.read()
file_in.close()

# Decrypt and verify
cipher = AES.new(aes_key_256, AES.MODE_EAX, nonce)
plaintext = cipher.decrypt_and_verify(ciphered_data, tag)  # Decrypt and verify with the tag

print("plaintext is: " + plaintext)

# DOING THE EXACT SAME TASK BUT WITH THE LARGER 1MB FILE

print("\nENCRYPTING FILE GREATER THAN 1MB USING A 128-BIT KEY: ")

aes_key_256 = get_random_bytes(16)  # will be a new 128 bit key.

cipher = AES.new(aes_key_256, AES.MODE_EAX)

data_from_file_1mb = open('./shakespere1mb.txt').read()
nonce = cipher.nonce
ciphertext, tag = cipher.encrypt_and_digest(data_from_file_1mb)

do_want_display = raw_input("The amount of encrypted text is quite large, would you like to display it? (y/n)")

if do_want_display.lower() == "y":
    print("Your encrypted message " + ciphertext)

w_file = open('./task2_128_1mb.bin', 'wb')
w_file.write(nonce)
w_file.write(tag)
w_file.write(ciphertext)
w_file.close()

file_in = open('./task2_128_1mb.bin', 'rb')
nonce = file_in.read(16)
tag = file_in.read(16)
ciphered_data = file_in.read()
file_in.close()

# Decrypt and verify
cipher = AES.new(aes_key_256, AES.MODE_EAX, nonce)
plaintext = cipher.decrypt_and_verify(ciphered_data, tag)  # Decrypt and verify with the tag


do_want_display = raw_input("The amount of plaintext is quite large, would you like to display it? (y/n)")

if do_want_display.lower() == "y":
    print("plaintext is: " + plaintext)

print("")
print("ENCRYPTING FILE GREATER THAN 1MB USING A 256-BIT KEY: ")

aes_key_256 = get_random_bytes(32)  # will be a new 128 bit key.

cipher = AES.new(aes_key_256, AES.MODE_EAX)

data_from_file_1mb = open('./shakespere1mb.txt').read()  # lt128 = 'less than 128 bits.'
nonce = cipher.nonce
ciphertext, tag = cipher.encrypt_and_digest(data_from_file_1mb)

do_want_display = raw_input("The amount of encrypted text is quite large, would you like to display it? (y/n)")

if do_want_display.lower() == "y":
    print("Your encrypted message " + ciphertext)

w_file = open('./task2_256_1mb.bin', 'wb')
w_file.write(nonce)
w_file.write(tag)
w_file.write(ciphertext)
w_file.close()

file_in = open('./task2_256_1mb.bin', 'rb')
nonce = file_in.read(16)
tag = file_in.read(16)
ciphered_data = file_in.read()
file_in.close()

# Decrypt and verify
cipher = AES.new(aes_key_256, AES.MODE_EAX, nonce)
plaintext = cipher.decrypt_and_verify(ciphered_data, tag)  # Decrypt and verify with the tag

do_want_display = raw_input("The amount of plaintext is quite large, would you like to display it? (y/n)")

if do_want_display.lower() == "y":
    print("plaintext is: " + plaintext)

print("END OF STEP 1")
