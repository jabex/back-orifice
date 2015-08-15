# Packets fields:
# Mnemonic Size in bytes
# MAGIC    8
# LEN      4
# ID       4
# T        1
# DATA     variable

import binascii
import copy
 
def boseed(s):
    X = 0
    Y = len(s)
    Z = 0
    while X < Y:
        Z = Z + ord(s[X])
        X = X + 1
        
    X = 0
    while X < Y:
        if (X % 2)!=0:
            Z = Z - (ord(s[X]) * (Y - X + 1))            
        else:
            Z = Z + (ord(s[X]) * (Y - X + 1))
    
        Z = Z % 0x7fffffff
        X = X + 1

    Z = (Z * Y) % 0x7fffffff
    return Z

def borand(seed):
    return (seed*214013)+2531011


def crypter(seed, p, L):
    X = 0
    Z = seed
    while X<L:
        Z=borand(Z)
        p[X] = p[X]^((Z>>16) & 0xff)
        X = X +1
    return p


plain = bytearray(8)
# MAGIC "*!*QWTY?"
plain[0] =  bytes('*')
plain[1] =  bytes('!')
plain[2] =  bytes('*')
plain[3] =  bytes('Q')
plain[4] =  bytes('W')
plain[5] =  bytes('T')
plain[6] =  bytes('Y')
plain[7] =  bytes('?')

# LEN  The value of this field cannot be less than 19 
# import struct
# aux = tuple(struct.pack("<I", 18))
# plain[8]  = aux[0] #0x12
# plain[9]  = aux[1] #0x00
# plain[10] = aux[2] #0x00
# plain[11] = aux[3] #0x00

# Cipher text
hex_string = "ce63d1d216e713cf39a5a5864d8ab466aa32"
hex_data = hex_string.decode("hex")
cipher = bytearray(hex_data)

# Brute force seed
# Known Plaintext Attack
first_pkt_id = 0
last_pkt_id  = 7

minval = 0
maxval = pow(2, 32)
seeds = list()

# plain[i] ^ cipher[i] = plain[i] ^ (plain[i] ^ ((z>>16) & 0xff)) = (z>>16) & 0xff)
xored = bytearray(8)
for i in xrange(first_pkt_id, last_pkt_id+1):
    xored[i] = plain[i]^cipher[i]

for seed in xrange(minval, maxval+1):
    aux = 0 
    z=borand(seed)
    for k in xrange(first_pkt_id, last_pkt_id+1):
        if xored[k]!=(z>>16) & 0xff:
            break
        z=borand(z)
        aux = k
        
    if aux==last_pkt_id:
        seeds.append(seed)
        print "Seed Hit: ", seed
    

for i in xrange(0, len(seeds)):
    aux = copy.copy(cipher)
    print "\n"
    print "SEED : ", seeds[i]
    print "ASCII: ", crypter(seeds[i], aux,18)
    print "HEX  : ", binascii.b2a_hex(aux)
            