# -*- coding: utf-8 -*-
"""
Created on Thu Oct 10 23:35:00 2018

@author: amitks
"""

from Crypto.Cipher import AES
from Crypto import Random
import random
import socket
import os
import sys

key = "JIIT62INFOSECURE"
iv = b"Y\r*c'\x9b\x06u\x03X\xb7%F\xb6Yi"
rsa_public_key=455,8633
rsa_private_key=6647,8633

class FTPclient:
	def __init__(self, address, port, data_port):
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.address = address
		self.port = int(port)
		self.data_port = int(data_port)

	def create_connection(self):
	  print ('Starting connection to', self.address, ':', self.port)

	  try:
	  	server_address = (self.address, self.port)
	  	self.sock.connect(server_address)
	  	print ('Connected to', self.address, ':', self.port)
	  except KeyboardInterrupt:
	  	self.close_client()
	  except:
	  	print ('Connection to', self.address, ':', self.port, 'failed')
	  	self.close_client()

	def start(self):
		try:
			self.create_connection()
		except Exception as e:
			self.close_client()

		while True:
			try:
				command = input('Enter command: ')
				if not command:
					print ('Need a command.')
					continue
			except KeyboardInterrupt:
				self.close_client()

			cmd  = command[:4].strip().upper()
			path = command[4:].strip()

			try:
				self.sock.send(bytes(command,'utf-8'))
				data = self.sock.recv(1024).decode()
				print (data)

				if (cmd == 'QUIT'):
					self.close_client()
				elif (cmd == 'LIST' or cmd == 'STOR' or cmd == 'RETR'):
					if (data and (data[0:3] == '125')):
						func = getattr(self, str(cmd))
						func(path)
						data = self.sock.recv(1024).decode()
						print (data)
			except Exception as e:
				print (str(e))
				self.close_client()

	def connect_datasock(self):
		self.datasock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.datasock.connect((self.address, self.data_port))

	def LIST(self, path):
		try:
			self.connect_datasock()

			while True:
				dirlist = self.datasock.recv(1024)
				if not dirlist: break
				sys.stdout.write(dirlist)
				sys.stdout.flush()
		except Exception as e:
			print (str(e))
		finally:
			self.datasock.close()

	def STOR(self, path):
		print ('Storing', path, 'to the server')
		try:
			self.connect_datasock()
			file_ext=path.split('.')
			fext=file_ext[len(file_ext)-1].lower()
			fname=path
			if fext in ["txt","cpp","py"]:
				encrypt_text(fname)
			elif fext in ["jpg","jpeg","png"]:
				encrypt_image(fname)
			else:
				encrypt_audio(fname)
			f = open("enc_"+fname, 'rb')

			upload = f.read(1024)
			while upload:
				self.datasock.send(upload)
				upload = f.read(1024)
		except Exception as e:
			print( str(e))
		finally:
			f.close()
			self.datasock.close()

	def RETR(self, path):
		print ('Retrieving', path, 'from the server')
		try:
			self.connect_datasock()

			f = open("enc_"+path,'wb')
			while True:
				download = self.datasock.recv(1024)
				if not download: break
				f.write(download)
			fname=path
			f.close()
			fil_ext=fname.split('.')
			fext=fil_ext[1].lower()
			if fext in ["txt","cpp","py"]:
				decrypt_text(fname)
			elif fext in ["jpg","jpeg","png"]:
				decrypt_image(fname)
			else:
				decrypt_audio(fname)
		except Exception as e:
			print (str(e))
		finally:
			self.datasock.close()


	def close_client(self):
		print ('Closing socket connection...')
		self.sock.close()

		print ('FTP client terminating...')
		quit()

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
    p = 23#int(input("Enter a prime number (17, 19, 23, etc): "))
    q = 31#int(input("Enter another prime number (Not one you entered above): "))
    public, private = generate_keypair(p, q)
    print ("Your public key is ", public ," and your private key is ", private)
    return public,private

def encrypt_rsa(pk, plaintext):
    key, n = pk
    cipher = [(ord(char) ** key) % n for char in plaintext]
    return cipher

def decrypt_rsa(pk, ciphertext):
    key, n = pk
    plain = [chr((char ** key) % n) for char in ciphertext]
    return ''.join(plain)

def encrypt_text(fname):
    f1=open(fname,"rt")
    message=f1.read()
    f1.close()
    encrypted_msg = encrypt_rsa(rsa_private_key, message)
    msg=""
    for i in range (0,len(encrypted_msg)):
        msg=msg+" "+str(encrypted_msg[i])
    f2=open("enc_"+fname,"wt")
    f2.write(''.join(map(lambda x: str(x), msg)))
    f2.close()

def decrypt_text(fname):
    print ("Decrypting message with public key ", rsa_public_key ," . . .")
    f1=open("enc_"+fname,"rt")
    msg=f1.read()
    f1.close()
    msg1=msg.split()
    msg1=list(map(int,msg1))
    print ("Your message is:")
    decrypted_msg=decrypt_rsa(rsa_public_key, msg1)
    f2=open(fname,"wt")
    f2.write(str(decrypted_msg))
    print (decrypted_msg)
    f2.close()




def encrypt_image(fname):
    input_file = open(fname,'rb')
    input_data = input_file.read()
    input_file.close()
    cfb_cipher = AES.new(key, AES.MODE_CFB, iv)
    enc_data = cfb_cipher.encrypt(input_data)
    enc_file = open("enc_"+fname, "wb")
    enc_file.write(enc_data)
    enc_file.close()

def decrypt_image(fname):
    enc_file2 = open("enc_"+fname,"rb")
    enc_data2 = enc_file2.read()
    enc_file2.close()
    cfb_decipher = AES.new(key, AES.MODE_CFB, iv)
    plain_data = cfb_decipher.decrypt(enc_data2)
    output_file = open(fname, "wb")
    output_file.write(plain_data)
    output_file.close()

def encrypt_audio(fname):
    input_file = open(fname,'rb')
    input_data = input_file.read()
    input_file.close()
    cfb_cipher = AES.new(key, AES.MODE_CFB, iv)
    enc_data = cfb_cipher.encrypt(input_data)
    enc_file = open("enc_"+fname, "wb")
    enc_file.write(enc_data)
    enc_file.close()

def decrypt_audio(fname):
    enc_file2 = open("enc_"+fname,"rb")
    enc_data2 = enc_file2.read()
    enc_file2.close()
    cfb_decipher = AES.new(key, AES.MODE_CFB, iv)
    plain_data = cfb_decipher.decrypt(enc_data2)
    output_file = open(fname, "wb")
    output_file.write(plain_data)
    output_file.close()


address = input("Destination address - if left empty, default address is localhost: ")
if not address:
	address = 'localhost'
port = input("Port - if left empty, default port is 10021: ")
if not port:
	port = 10021
data_port = input("Data port - if left empty, default port is 10020: ")

if not data_port:
	data_port = 10020

ftpClient = FTPclient(address, port, data_port)
ftpClient.start()

while(True):
    print("Enter your choice:\n1:Encrypt Image\n2:Decrypt Image\n3:Encrypt Audio\n4:Decrypt Audio\n5:Encrypt Text\n6:Decrypt Text\nOther: End\n\n ")
    choice=int(input(""))
    if choice==1:
        encrypt_image()
    elif choice==2:
        decrypt_image()
    elif choice==3:
        encrypt_audio()
    elif choice==4:
        decrypt_audio()
    elif choice==5:
        encrypt_text(rsa_private_key)
    elif choice==6:
        decrypt_text(rsa_public_key)
    else:
        print("Thank you\n")
        break