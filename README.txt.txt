KARMVIR SINGH DHALIWAL 
30025474
CPSC 418 A1 Q8

I am submitting the file encrypt_modify.py, a python program that has 12 functions; namely 
	- string_to_bytes, which takes in a string and returns the byte encoding of that string in utf-8, this was a helper function that was implemented for us.
	- hash_bytes, which takes as input bytes, and returns the hash of the bytes using the SHA-224 hashing algorithm.
	- create_iv, which takes in an int value, and creates a cryptographically secure iv to be used in encryption algorithms.
	- derive_key, which takes in a string, hashes it and returns the first 16 bytes to be used as a key in encryption algorithms.
	- pad_bytes, which takes in bytes as input, and pads them to the desired length, as required by encryption algorithms.
	- encrypt_bytes, which takes in an input, key and iv and uses the key and iv to encrypt the input using AES-128-CBC encryption.
	- hash_pad_then_encrypt, takes in an input, string and iv, uses the string to create a key, then uses the key and iv to encrypt the input in a specific way.
	- check_tag, which takes in an input, and checks if the tag, which is appended to the input, is the same as the input hashed using sha 224. 
	- decrypt_unpad_check, which takes in an input and a string and decrypts the input, creating a key from the string. it then checks if the tag is correct.
	- generate_passwords, which takes in an int value for year, month, and day and generates all dates from the given date until today.
	- determine_password, which takes in an input and attempts to brute force the password that was used to encrypt it.
	- attempt_substitute, which takes in an input, codeword, target, and substitute and attempts to bruteforce the encryption, checks if a codeword is present in the plaintext, checks if a target word is present in the plaintext, and substitutes the target word with the substitute word.


The problem is partially solved.

The functions as listed above that are correctly implemented to the best of my knowledge are string_to_bytes, hash_bytes, create_iv, derive_key, pad_bytes, encrypt_bytes, hash_pad_then_encrypt, check_tag, decrypt_unpad_check, determine_password, attempt_substitute.

The function that is not implemented correctly is generate_passwords. I have not used a generator before and could not figure out how to correctly use it. I have implemented it using a list instead of a generator, and by using the list the remaining functions that call this, namely determine_password and attempt_substitution work correctly

Apart from generate_passwords, there are no known bugs in the code.