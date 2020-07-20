from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from time import time
import os
from Crypto.Util.Padding import pad, unpad

total_seconds = 1
number_of_iterations = 0

aes_key = get_random_bytes(16)  # will be a new 128 bit key.

cipher = AES.new(aes_key, AES.MODE_EAX)

data_from_file_lt128 = open('./shakespere1mb.txt').read()
nonce = cipher.nonce
ciphertext, tag = cipher.encrypt_and_digest(data_from_file_lt128)

w_file = open('./task2_128_lt1mb.bin', 'wb')
w_file.write(nonce)
w_file.write(tag)
w_file.write(ciphertext)
w_file.close()

aprox_size_mb = round(os.path.getsize('./task2_128_lt1mb.bin') / 1000000.0, 5)

start_time = time()  # Adding a start time to get the difference.

while True:
    now = time()
    elapsed_time = now - start_time

    if not elapsed_time >= total_seconds:
        #  perform another encryption and decryption if elapsed time is less than 1 second.
        number_of_iterations += 1
        r_file = open('./task2_128_lt1mb.bin', 'rb')
        nonce = r_file.read(16)
        tag = r_file.read(16)
        ciphered_data = r_file.read()
        r_file.close()

        # Decrypt and verify
        cipher = AES.new(aes_key, AES.MODE_EAX, nonce)
        plaintext = cipher.decrypt_and_verify(ciphered_data, tag)  # Decrypt and verify with the tag
    else:
        break


print("\n (AES MODE: EAX, KEYSIZE: 128-bit) The max file size that could be decrypted in 1 second on this computer is: " + str(number_of_iterations * aprox_size_mb) + "MB")

number_of_iterations = 0

aes_key = get_random_bytes(16)  # will be a new 128 bit key.

cipher = AES.new(aes_key, AES.MODE_CFB)

data_from_file_lt128 = open('./shakespere1mb.txt').read()
ciphertext = cipher.encrypt(data_from_file_lt128)

w_file = open('./task2_128_lt1mb.bin', 'wb')
w_file.write(ciphertext)
w_file.close()

aprox_size_mb = round(os.path.getsize('./task2_128_lt1mb.bin') / 1000000.0, 5)

start_time = time()  # Adding a start time to get the difference.

while True:
    now = time()
    elapsed_time = now - start_time

    if not elapsed_time >= total_seconds:
        #  perform another encryption and decryption if elapsed time is less than 1 second.
        number_of_iterations += 1
        r_file = open('./task2_128_lt1mb.bin', 'rb')
        ciphered_data = r_file.read()
        r_file.close()

        # Decrypt and verify
        cipher = AES.new(aes_key, AES.MODE_CFB)
        plaintext = cipher.decrypt(ciphered_data)  # Decrypt and verify with the tag
    else:
        break


print("\n (AES MODE: CFB, KEYSIZE: 128-bit) The max file size that could be decrypted in 1 second on this computer is: " + str(number_of_iterations * aprox_size_mb) + "MB")


# CBC
number_of_iterations = 0


data = data_from_file_lt128 = open('./shakespere1mb.txt').read()

aes_key = get_random_bytes(16)
cipher = AES.new(aes_key, AES.MODE_CBC)
ciphertext = cipher.encrypt(pad(data, AES.block_size))


iv = cipher.iv

w_file = open('./task2_128_lt1mb.bin', 'wb')
w_file.write(ciphertext)
w_file.close()

try:
    aprox_size_mb = round(os.path.getsize('./task2_128_lt1mb.bin') / 1000000.0, 5)

    start_time = time()  # Adding a start time to get the difference.

    while True:
        now = time()
        elapsed_time = now - start_time

        if not elapsed_time >= total_seconds:
            #  perform another encryption and decryption if elapsed time is less than 1 second.
            number_of_iterations += 1
            r_file = open('./task2_128_lt1mb.bin', 'rb')
            ciphered_data = r_file.read()
            r_file.close()

            # Decrypt
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphered_data), AES.block_size)
        else:
            break
    print("\n (AES MODE: CBC, KEYSIZE: 128-bit) The max file size that could be decrypted in 1 second on this computer is: " + str(number_of_iterations * aprox_size_mb) + "MB")

except ValueError, KeyError:
    print("Incorrect decryption")
