************************************ Overview ************************************* 
This Python script aims to recover the AES key used for encryption and subsequently decrypt a specific ciphertext.
The recovery process involves systematically exploring the key space and verifying matches between encrypted and expected ciphertexts.

************************************ File Structure ************************************ 
-> solution2.py: Main Python script.
-> aesSecretMessage.txt: Pyhton file used as module to expand the keys
-> 2aesPlaintexts.txt: File containing plaintexts.
-> 2aesCiphertexts.txt: File containing corresponding ciphertexts.
-> 2aesSecretMessage.txt: File where the decrypted message is saved.

************************************ Run the script ************************************ 
python solution.py

************************************ Working ************************************ 
-> Read plaintexts and ciphertexts from files.
-> Sets and dictionaries to store unique cipher representations after encryption and map them to short keys.
-> Generate all possible combinations of two bytes (0 to 255). Store it in list.
-> Encrypt the first message using short keys and store results in sets and dictionaries.
-> Decrypt the first cipher using the same short keys and store results in sets and dictionaries.
-> Iterate through sets of cipher representations obtained from encryption and decryption.
-> Check if there are matches and print short keys.
-> Check if other messages match with the given short keys.
-> Decrypt the last ciphertext using the second long key.
-> Decrypt the result using the first long key to obtain the original message.
-> Write the decrypted message to a file.
-> Print the running time.

************************************ View the result ************************************ 
The script outputs information during execution.
The recovered key and decrypted message are saved in 2aesSecretMessage.txt.
