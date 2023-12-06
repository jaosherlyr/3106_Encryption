#  ====================
#  Sherly R. Jao
#  BSCS - 3
#  Final Output of CS 3101N
#  ====================

import os
import sys
import random
import math
import json

#  ===== INPUT =====
print("\n> Accept Filename")
filename = input("Enter name of text file: ")
path = "plaintext"

file = os.path.join(path, filename)

#  Check if the file exist
if os.path.exists(file):
    with open(file, 'r') as file:
        plaintext = file.read()
else:
    print(f"\n!! File: '{file}' does not exist. Make sure your filename is correct. Exiting....")
    sys.exit(1)

print("\n> Accept Keys")

while True:
    caesar_key = input("Enter Caesar Cipher Key: ")
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


#  ===== GENERATE RSA KEYS =====
def is_prime(num):
    for i in range(2, int(math.sqrt(num)) + 1):
        if (num % i) == 0:
            return False
    return True


def get_prime(bits):
    while True:
        p_num = random.getrandbits(bits)
        if is_prime(p_num):
            return p_num


def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, x, y = extended_gcd(b % a, a)
        return g, y - (b // a) * x, x


def modular_inverse(integer, modulo):
    g, x, _ = extended_gcd(integer, modulo)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % modulo


def generate_rsa_keys(bits):
    p = get_prime(bits)

    while True:
        q = get_prime(bits)
        if p != q:
            break

    n = p * q
    phi = (p - 1) * (q - 1)

    while True:
        #  generate am e that is greater than 1 and less than phi
        e = random.randint(2, phi - 1)
        if math.gcd(e, phi) == 1:
            break

    #  generate d which is the modular inverse of e
    d = modular_inverse(e, phi)

    encrypt_key = (e, n)
    decrypt_key = (d, n)

    return encrypt_key, decrypt_key


#  ===== LOGIC =====
def transposition_encrypt(text, key):
    sorted_key = ''.join(sorted(key))

    num_columns = len(sorted_key)
    num_rows = (len(text) + (num_columns - 1)) // num_columns
    grid = [[' ' for _ in range(num_columns)] for _ in range(num_rows)]

    for i, char in enumerate(text):
        row = i // num_columns
        columns = i % num_columns
        grid[row][columns] = char

    ciphertext = ''
    for char_column in sorted_key:
        index = key.index(char_column)
        column = [grid[row][index] for row in range(num_rows)]
        ciphertext += ''.join(column)

    return ciphertext


def get_loop(num):
    factor = num

    for i in range(2, int(num ** 0.5) + 1):
        if num % i == 0:
            factor = i

    #  return 5 if the factor is greater than 5 otherwise return the smallest
    return factor if factor < 5 else 5


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


def vigenere_encrypt(text, key):
    ciphertext = ''
    len_key = len(key)

    for i, char in enumerate(text):
        if char.isalpha():
            is_upper = char.isupper()
            key_char = key[i % len_key].upper()
            shifted_char = chr((ord(char) + ord(key_char) - 2 * ord('A' if is_upper else 'a')) % 26 + ord('A' if is_upper else 'a'))
            ciphertext += shifted_char
        else:
            #  retain char if not alphabet
            ciphertext += char

    return ciphertext


def get_otp(len_text):
    return ''.join(random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ') for _ in range(len_text))


def vernam_encrypt(text, key):
    ciphertext = ''.join(chr(ord(p) ^ ord(k)) for p, k in zip(text, key))
    return ciphertext


bits = 8
encryption_key, decryption_key = generate_rsa_keys(bits)


def rsa_encrypt(text, key):
    e, n = key
    ciphertext = [pow(ord(char), e, n) for char in text]
    return ciphertext


#  ==== ENCRYPTION =====
transposition_ciphertext = plaintext
loop_num = get_loop(len(plaintext))

for i in range(loop_num):
    transposition_ciphertext = transposition_encrypt(transposition_ciphertext, transposition_key)

caesar_ciphertext = caesar_encrypt(transposition_ciphertext, caesar_key)
vigenere_ciphertext = vigenere_encrypt(caesar_ciphertext, vigenere_key)
otp = get_otp(len(vigenere_ciphertext))
vernam_ciphertext = vernam_encrypt(vigenere_ciphertext, otp)
rsa_ciphertext = rsa_encrypt(vernam_ciphertext, encryption_key)

# encryption checker
# print(rsa_ciphertext)
# print(vernam_ciphertext)
# print(vigenere_ciphertext)
# print(caesar_ciphertext)
# print(transposition_ciphertext)

#  ===== OUTPUT =====
def encrypted_text_to_file(output_folder, filename, content):
    name = os.path.join(output_folder, f"encrypted_{filename}")
    with open(name, 'w') as file:
        file.write(', '.join(str(item) for item in content))


def keys_to_file(output_folder, filename, otp, decryption_key, loop_num):
    content = {
        "otp": otp,
        "decryption_key": decryption_key,
        "loop_num": loop_num
    }

    name = os.path.join(output_folder, f"keys_{filename}")
    with open(name, 'w') as file:
        json.dump(content, file)


encrypted_text_to_file("encrypted", filename, rsa_ciphertext)
keys_to_file("keys", filename, otp, decryption_key, loop_num)

print("\n!! ENCRYPTION SUCCESS !!\n")
