from Crypto.Hash import SHA256

h = SHA256.new()
h.update(b'attack the code')

hashedtext = h.hexdigest()
print (hashedtext)

w_file = open('./encrypted_messages/sha256_enc.txt')
w_file.write(hashedtext)
w_file.close()

