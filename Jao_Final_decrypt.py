#  ====================
#  Sherly R. Jao
#  BSCS - 3
#  Final Output of CS 3101N
#  ====================

import os
import sys
import hashlib as hl
import json

#  ===== INPUT =====
print("\n> Accept Filename")
input_file = input("Enter name of text file to be decrypted: ")

encyrpted_folder = "encrypted"
encrypted_filename = f"encrypted_{input_file}"

key_folder = "keys"
key_filename = f"keys_{input_file}"

encrypted_file = os.path.join(encyrpted_folder, encrypted_filename)
key_file = os.path.join(key_folder, key_filename)


#  Check if the file exist
if os.path.exists(encrypted_file) and os.path.exists(key_file):
    with open(encrypted_file, 'r') as file:
        content = file.read()
        ciphertext = [int(item.strip()) for item in content.split(', ')]

    with open(key_file, 'r') as file:
        key_contents = json.load(file)
else:
    print(f"\n!! Files: '{encrypted_file}' and '{key_file}' does not exist. Make sure your filename is correct. Exiting....")
    sys.exit(1)

#  distribute key contents
otp = key_contents["otp"]
decryption_key = key_contents["decryption_key"]
loop_num = key_contents["loop_num"]

while True:
    caesar_key = input("Enter Caesar Cipher Key: ")
    #  check if key is a digit
    if not caesar_key.isdigit():
        print("\n!! Caesar Cipher Key MUST be a digit. Enter new key.\n")
    else:
        caesar_key = int(caesar_key)
        break

while True:
    transposition_key = input("Enter Transposition Cipher Key: ")
    #  check if the transposition key has same letters
    if any(transposition_key.count(letter) > 1 for letter in transposition_key):
        print("\n!! Transposition Cipher Key must NOT have duplicate letters. Enter new key.\n")
    else:
        break

vigenere_key = input("Enter Vigenère Cipher Key: ")


#  ===== LOGIC =====
def rsa_decrypt(text, key):
    d, n = key
    decrypted_text = [chr(pow(char, d, n)) for char in text]
    return ''.join(decrypted_text)


def vernam_decrypt(text, key):
    decrypted_text = ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(text, key))
    return decrypted_text


def vigenere_decrypt(text, key):
    decrypted_text = ""
    len_key = len(key)

    for i, char in enumerate(text):
        if char.isalpha():
            is_upper = char.isupper()
            key_char = key[i % len_key].upper()
            shifted_char = chr((ord(char) - ord(key_char) + 26) % 26 + ord('A' if is_upper else 'a'))
            decrypted_text += shifted_char
        else:
            #  retain char if not alphabet
            decrypted_text += char

    return decrypted_text


def caesar_encrypt(text, key):
    ciphertext = ''

    for char in text:
        if char.isalpha():
            is_upper = char.isupper()
            shifted_char = chr((ord(char) - ord('A' if is_upper else 'a') + key) % 26 + ord('A' if is_upper else 'a'))
            ciphertext += shifted_char
        else:
            #  retain char if not alphabet
            ciphertext += char

    return ciphertext


def caesar_decrypt(text, key):
    return caesar_encrypt(text, -key)


def transposition_decrypt(text, key):
    sorted_key = ''.join(sorted(key))

    num_columns = len(sorted_key)
    num_rows = (len(text) + num_columns - 1) // num_columns
    grid = [[' ' for _ in range(num_columns)] for _ in range(num_rows)]
    char_index = 0

    for col_char in sorted_key:
        col_index = key.index(col_char)
        for row in range(num_rows):
            grid[row][col_index] = text[char_index]
            char_index += 1

    decrypted_key = ''.join(''.join(grid[row]) for row in range(num_rows))

    return decrypted_key


#  ===== DECRYPTION =====
rsa_decrypted_text = rsa_decrypt(ciphertext, decryption_key)
vernam_decrypted_text = vernam_decrypt(rsa_decrypted_text, otp)
vigenere_decrypted_text = vigenere_decrypt(vernam_decrypted_text, vigenere_key)
caesar_decrypted_text = caesar_decrypt(vigenere_decrypted_text, caesar_key)
text = caesar_decrypted_text


for i in range(loop_num):
    transposition_decrypted_text = transposition_decrypt(text, transposition_key)
    text = transposition_decrypted_text

decrypted_text = transposition_decrypted_text.strip()

#  decryption checker
# print(rsa_decrypted_text)
# print(vernam_decrypted_text)
# print(vigenere_decrypted_text)
# print(caesar_decrypted_text)
# print(decrypted_text)

#  ===== OUTPUT ======
def decrypted_text_to_file(output_folder, filename, content):
    name = os.path.join(output_folder, f"decrypted_{filename}")
    with open(name, 'w') as file:
        file.write(content)


decrypted_text_to_file("decrypted", input_file, decrypted_text)

#  ===== HASH CHECKING =====
print("\n> Hash Checking")
path = "plaintext"
original_file = os.path.join(path, input_file)


def get_hash(content):
    binary_data = content.encode("utf-8")
    md5 = hl.md5(binary_data).hexdigest()
    sha1 = hl.sha1(binary_data).hexdigest()

    return binary_data, md5, sha1


with open(original_file, 'r') as file:
    content = file.read()

original_binary_data, original_md5, original_sha1 = get_hash(content)
decrypted_binary_data, decrypted_md5, decrypted_sha1 = get_hash(decrypted_text)

are_identical = original_binary_data == decrypted_binary_data and original_md5 == decrypted_md5 and original_sha1 == decrypted_sha1

if are_identical:
    print("\n\n!! DECRYPTION SUCCESS !!")
    print(f"\nOriginal File: {original_file}")
    print(f"\tBinary Data: {original_binary_data}")
    print(f"\tMD5: {original_md5}")
    print(f"\tSHA1 Data: {original_sha1}")
    print(f"\nDecrypted File: decrypted_{original_file}")
    print(f"\tBinary Data: {decrypted_binary_data}")
    print(f"\tMD5: {decrypted_md5}")
    print(f"\tSHA1 Data: {decrypted_sha1}")
else:
    print("\n!! DECRYPTION UNSUCCESSFUL. There was a problem in your decryption !!")