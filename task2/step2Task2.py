from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from time import time
import os

total_seconds = 1
number_of_iterations = 0
exact_size_bytes = os.path.getsize('./message128.txt')

start_time = time()  # Adding a start time to get the difference.

while True:
    now = time()
    elapsed_time = now - start_time

    if not elapsed_time >= total_seconds:
        #  perform another encryption and decryption if elapsed time is less than 1 second.
        number_of_iterations += 1
        aes_key = get_random_bytes(16)  # will be a new 128 bit key.

        cipher = AES.new(aes_key, AES.MODE_EAX)

        data_from_file_lt128 = open('./message128.txt').read()  # lt128 = 'less than 128 bits.'
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(data_from_file_lt128)

        w_file = open('./task2_128_lt128.bin', 'wb')
        w_file.write(nonce)
        w_file.write(tag)
        w_file.write(ciphertext)
        w_file.close()

        r_file = open('./task2_128_lt128.bin', 'rb')
        nonce = r_file.read(16)
        tag = r_file.read(16)
        ciphered_data = r_file.read()
        r_file.close()

        # Decrypt and verify
        cipher = AES.new(aes_key, AES.MODE_EAX, nonce)
        plaintext = cipher.decrypt_and_verify(ciphered_data, tag)  # Decrypt and verify with the tag
    else:
        break

print("\nThe total number of encryptions/decryptions using (AES.MODE_EAX) in a single second is: " + str(number_of_iterations))
