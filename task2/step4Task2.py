import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import math
import decimal
# For this since it would take way too long to crack AES, I am going to do some estimation.


def encrypt_file():
    aes_key_256 = get_random_bytes(32)  # will be a new 256 bit key.

    cipher = AES.new(aes_key_256, AES.MODE_EAX)

    data_from_file_lt128 = open('./message128.txt').read()  # lt128 = 'file less than 128 bits.'
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data_from_file_lt128)

    w_file = open('./task2_128_lt128.bin', 'wb')
    w_file.write(nonce)
    w_file.write(tag)
    w_file.write(ciphertext)
    w_file.close()


def get_process_time():
    # I am assuming that we know the nonce, and the tag are the first 32 bits.
    file_in = open('./task2_128_lt128.bin', 'rb')
    nonce = file_in.read(16)
    tag = file_in.read(16)
    ciphered_data = file_in.read()
    file_in.close()

    # Try a random incorrect key to get how long the processor took (processor time)
    try:
        time.clock()
        random_aes_key = get_random_bytes(32)
        cipher = AES.new(random_aes_key, AES.MODE_EAX, nonce)
        plaintext = cipher.decrypt_and_verify(ciphered_data, tag)  # try decrypting and verify with the tag
    except ValueError:
        pass  # Pass the value error because we don't care about if the MAC ins't correct.

    return time.clock()


encrypt_file()
single_eval = get_process_time()

total_time_bf = single_eval * math.pow(2.0, 255.0)
# This is the total number of keys to try multiplied by the time taken in seconds for a single evaluation.

time_in_years = total_time_bf * (3.1709791983765 * math.pow(10, -8.0))
# estimated time in years to brute force.

print("\nTotal time taken (in seconds) to try a single evaluation is: " + str(single_eval))
print("Total seconds to brute force: " + str(decimal.Decimal(total_time_bf)))
print("Total time in years: " + str(decimal.Decimal(time_in_years)))

