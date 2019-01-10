# -*- coding: utf-8 -*-
"""
Created on Thu Nov 15 23:42:21 2018

@author: amitks
"""

from Crypto.Cipher import AES
from Crypto import Random
import random
key = "ABCDEF0123456789"#Random.new().read(AES.block_size)
iv = Random.new().read(AES.block_size)
print(key,iv)

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def multiplicative_inverse(e, phi):
    d = 0
    x1 = 0
    x2 = 1
    y1 = 1
    temp_phi = phi

    while e > 0:
        temp1 = int(temp_phi/e)
        temp2 = int(temp_phi - temp1 * e)
        temp_phi = e
        e = temp2
        x = x2- temp1* x1
        y = d - temp1 * y1
        x2 = x1
        x1 = x
        d = y1
        y1 = y
    if temp_phi == 1:
        return d + phi

def is_prime(num):
    if num == 2:
        return True
    if num < 2 or num % 2 == 0:
        return False
    for n in range(3, int(num**0.5)+2, 2):
        if num % n == 0:
            return False
    return True

def generate_keypair(p, q):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError('Both numbers must be prime.')
    elif p == q:
        raise ValueError('p and q cannot be equal')
    n = p * q
    phi = (p-1) * (q-1)
    e = random.randrange(1, phi)
    g = gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = gcd(e, phi)
    d = multiplicative_inverse(e, phi)
    return ((e, n), (d, n))

def rsa_key_gen():
    print ("RSA Encrypter/ Decrypter")
    p = 89#int(input("Enter a prime number (17, 19, 23, etc): "))
    q = 97#int(input("Enter another prime number (Not one you entered above): "))
    public, private = generate_keypair(p, q)
    print ("Your public key is ", public ," and your private key is ", private)
    return public,private

def aes_keys():
    key=Random.new().read(AES.block_size)
    iv=Random.new().read(AES.block_size)
    print (iv)

def otp_key_gen(path):
     file=open(path,'r')
     data=file.read()
     file.close()
     length=len(data)

     otp_data=''
     x=list(i for i in range(48,58)) +list(i for i in range(97,123))+list(i for i in range(65,91))
     for i in range(0,length):
          otp_data+=chr(x[random.randint(0,len(x)-1)])

     file=open('otp/otp_table.txt','w')
     file.write(otp_data)
     file.close()

rsa_public_key=0,0
rsa_private_key=0,0
rsa_public_key,rsa_private_key=rsa_key_gen()
print ("Main",rsa_public_key,rsa_private_key)
aes_keys()
otp_key_gen("secure_server.py")