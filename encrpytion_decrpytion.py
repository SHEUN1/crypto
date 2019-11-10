import os
import base64
import argparse
from Crypto.Cipher import AES

class Crypto:

    @classmethod
    def encrpyt(cls, cipher, msg):
        padding = 0
        if len(msg)%16:
            padding = (int(len(msg)/16) + 2)*16
        cipher_ready_msg = (msg.rjust(padding)).encode('utf-8')
        encrypted = base64.b64encode(cipher.encrypt(cipher_ready_msg))
        print (encrypted)
    
    @classmethod
    def decrpyt(cls, cipher, encoded_msg):
        decrypted = str(cipher.decrypt(base64.b64decode(encoded_msg)))
        decrypted = (decrypted.split(' ', 1)[1]).lstrip()
        print (decrypted)

parser = argparse.ArgumentParser()
parser.add_argument('--encrypt',    dest='to_encrypt', default=None)
parser.add_argument('--decrypt',    dest='to_decrypt', default=None)
parser.add_argument('--secret_key', dest='secret_key', default=None, required=True)

args = parser.parse_args()

secret_key = base64.b32encode(str.encode(args.secret_key))
cipher = AES.new(secret_key,AES.MODE_CBC, os.urandom(16))

if args.to_encrypt:
    Crypto.encrpyt(cipher, args.to_encrypt)
elif args.to_decrypt:
    Crypto.decrpyt(cipher, args.to_decrypt)