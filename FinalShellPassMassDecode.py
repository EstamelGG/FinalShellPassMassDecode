import argparse
import base64
import hashlib
import struct
from Crypto.Cipher import DES
import re
import os
import json


def remove_non_printable_chars(input_string):
    cleaned_string = re.sub(r'[\x00-\x1F\x7F-\x9F]', '', input_string)
    return cleaned_string


class Random:
    def __init__(self, seed=None):
        if seed is None:
            seed = (int((id(self) + id(seed)) * 997) & ((1 << 48) - 1))
        self.seed = (seed ^ 0x5DEECE66D) & ((1 << 48) - 1)

    def next(self, bits):
        self.seed = (self.seed * 0x5DEECE66D + 0xB) & ((1 << 48) - 1)
        value = self.seed >> (48 - bits)
        return value if value < (1 << (bits - 1)) else value - (1 << bits)

    def next_int(self):
        return self.next(32)

    def next_long(self):
        return (self.next(32) << 32) + self.next(32)

    def next_float(self):
        return self.next(24) / (1 << 24)

    def next_double(self):
        return ((self.next(26) << 27) + self.next(27)) * (1.0 / (1 << 53))


def des_decode(data, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.decrypt(data)


def random_key(head):
    ilist = [24, 54, 89, 120, 19, 49, 85, 115, 14, 44, 80, 110, 9, 40, 75, 106, 43, 73, 109, 12, 38, 68, 104, 7, 33, 64,
             99, 3, 28, 59, 94, 125, 112, 16, 51, 82, 107, 11, 46, 77, 103, 6, 41, 72, 98, 1, 37, 67, 4, 35, 70, 101, 0,
             30, 65, 96, 122, 25, 61, 91, 117, 20, 56, 86, 74, 104, 13, 43, 69, 99, 8, 38, 64, 95, 3, 34, 59, 90, 125,
             29, 93, 123, 32, 62, 88, 119, 27, 58, 83, 114, 22, 53, 79, 109, 17, 48, 35, 66, 101, 5, 31, 61, 96, 0, 26,
             56, 92, 122, 21, 51, 87, 117, 55, 85, 120, 24, 50, 80, 116, 19, 45, 75, 111, 14, 40, 71, 106, 10, 50, 81,
             116, 20, 45, 76, 111, 15, 41, 71, 106, 10, 36, 66, 102, 5, 69, 100, 8, 39, 65, 95, 3, 34, 60, 90, 126, 29,
             55, 85, 121, 24, 12, 42, 78, 108, 7, 37, 73, 103, 2, 33, 68, 99, 124, 28, 63, 94, 31, 61, 97, 0, 26, 57,
             92, 123, 21, 52, 87, 118, 17, 47, 82, 113, 100, 4, 39, 70, 96, 126, 34, 65, 91, 121, 30, 60, 86, 116, 25,
             55, 120, 23, 58, 89, 115, 18, 54, 84, 110, 13, 49, 79, 105, 9, 44, 75, 62, 92, 1, 31, 57, 88, 123, 27, 52,
             83, 118, 22, 48, 78, 113, 17, 81, 112, 20, 51, 76, 107, 15, 46, 72, 102, 10, 41, 67, 97, 6, 36]
    i = ilist[head[5]]
    ks = 3680984568597093857 // i
    random = Random(ks)
    t = head[0]
    for _ in range(t):
        random.next_long()
    n = random.next_long()
    r2 = Random(n)
    ld = [head[4], r2.next_long(), head[7], head[3], r2.next_long(), head[1], random.next_long(), head[2]]
    byte_stream = bytearray()
    for l in ld:
        byte_stream.extend(struct.pack('!Q', l & ((1 << 64) - 1)))
    key_data = md5(byte_stream)[:8]
    return key_data


def md5(data):
    return hashlib.md5(data).digest()


def decode_pass(data):
    if data is None:
        return None
    rs = ""
    buf = base64.b64decode(data)
    head = buf[:8]
    d = buf[8:]
    key = random_key(head)
    bt = des_decode(d, key)
    rs = bt.decode('utf-8')
    return remove_non_printable_chars(rs)

def getUserAndPass(file_path):
    with open(file_path, 'r') as file:
        json_data = json.load(file)
        try:
            password = json_data.get('password')
            username = json_data.get('user_name')
            host = json_data.get('host')
        except:
            host = False
            password = False
            username = False
    return host, username, password

def decode_json_files(src_path):
    src_path = str(src_path)
    print("Decode from path : %s" % src_path)
    if os.path.isfile(src_path) and src_path.endswith(".json"):
        host, username, password = getUserAndPass(src_path)
        if username and password:
            print("[+] %s:%s:%s" % (host, username, decode_pass(password)))
    elif os.path.isdir(src_path):
        for filename in os.listdir(src_path):
            if filename.endswith('.json'):
                # print("JSON File:", filename)
                file_path = os.path.join(src_path, filename)
                host, username, password = getUserAndPass(file_path)
                if username and password:
                    print("[+] %s:%s:%s" % (host, username, decode_pass(password)))


parser = argparse.ArgumentParser(description='Final Shell Decode')
parser.add_argument('-s', '--src_path', default="./", help='src file or directory path')
args = parser.parse_args()
target = args.src_path
decode_json_files(target)