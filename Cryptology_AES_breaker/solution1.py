import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from aesLongKeyGen24 import *
import math
# Open the file containing ciphertexts in read mode
with open("aesCiphertexts.txt", "r") as ciphers_file:
    cipher = ciphers_file.read().split('\n')

# Open the file containing plaintexts in read mode
with open("aesPlaintexts.txt", "r") as reader:
    messages = reader.read().split('\n')


# Extract the fifth ciphertext and convert it to bytes
cipher_text_5 = cipher[4]
byte_cipher_text = bytes.fromhex(cipher_text_5)
# An IV (iv) is set to a 16-byte zero block. This is used in CBC (Cipher Block Chaining) mode.
iv = b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0'

start_time = time.time()

# Encrypt the message using AES in CBC mode
def AES_enc(key, message):
    cipher_instance = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher_instance.encryptor()
    ciphertext = encryptor.update(message.encode('UTF-8')) + encryptor.finalize()
    return ciphertext

# Decrypt the ciphertext using AES in CBC mode
def AES_dec(key, cipher_text):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plain = decryptor.update(cipher_text)+decryptor.finalize()
    return plain

byte_combinations = []

# Generate all possible combinations of three bytes
for byte1 in range(256):
    for byte2 in range(256):
        for byte3 in range(16):
            byte_combinations.append(bytes([byte1, byte2, byte3<<4]))
            

print("\nTake deep breaths\nProgramme is running....\n")

# Iterate through generated combinations starting from index 
for j in range(0, len(byte_combinations)):
    shortKey = bytearray(byte_combinations[j])
    # Expand the short key to obtain the long key
    key = expandKey(shortKey)

    match_found = True
    # Iterate through the first four messages and check if the encryption matches the stored ciphertexts
    for i in range(4):
        ciphertext = AES_enc(key, messages[i])
        if ciphertext.hex() != cipher[i]:
            match_found = False
            break
        else:
            print(f"Checked for Message : {messages[i]}\n")


     # If all four matches are found, print information and break out of the loop
    if match_found:
        print(f"Match found!!!\n")
        print(f"Short-Key in hex : {shortKey.hex()}")
        break
    

print("Decrypting secret message...")

# Use the found short key to expand and decrypt the 5th message
key=expandKey(shortKey)
plain_text = AES_dec(key, byte_cipher_text)
print("The Secret message is :  " + str(plain_text.decode()))

end_time = time.time()
# Write the decrypted 5th message to a file
with open("aesSecretMessage.txt", "w") as secret_file:
        secret_file.write(str(plain_text.decode()))
        print("Written Secret message in aesSecretMessage.txt\n")

running_time = end_time - start_time
print(f"Running time : {running_time}")
