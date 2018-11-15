#!/usr/bin/env python

from binascii import hexlify, unhexlify
from Crypto.Cipher import AES
from hashlib import md5


def pad(data):
    length = 16 - (len(data) % 16)
    data += chr(length)*length
    return data


def unpad(data):
    return data[0:-ord(data[-1])]


def make_md5(workingKey, encoding='utf-8'):
    return md5(workingKey.encode(encoding)).digest()


def encrypt(plainText, workingKey):
    iv = '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
    plainText = pad(plainText)
    encDigest = make_md5(workingKey)
    enc_cipher = AES.new(encDigest, AES.MODE_CBC, iv)
    encryptedText = hexlify(enc_cipher.encrypt(plainText)).decode('utf-8')
    return encryptedText


def decrypt(cipherText, workingKey):
    iv = '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
    decDigest = make_md5(workingKey)
    encryptedText = unhexlify(cipherText)
    dec_cipher = AES.new(decDigest, AES.MODE_CBC, iv)
    decryptedText = unpad(dec_cipher.decrypt(encryptedText).decode('utf-8'))
    return decryptedText
