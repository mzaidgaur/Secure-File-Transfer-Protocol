

# -*- coding: utf-8 -*-
"""
Created on OCT 10 21:25:09 2018

@author: amitks
"""

from Crypto.Cipher import AES
from Crypto import Random
import random
import socket
import os
import sys
import threading
import time

key = "JIIT62INFOSECURE"
iv = b"Y\r*c'\x9b\x06u\x03X\xb7%F\xb6Yi"
rsa_public_key=455,8633
rsa_private_key=6647,8633

class FTPThreadServer(threading.Thread):
    def __init__(self, client_a_client_address, local_ip, data_port):
        self.client,self.client_address=client_a_client_address
        self.cwd=os.getcwd()
        self.data_address=(local_ip, data_port)
        threading.Thread.__init__(self)

    def start_datasock(self):
        try:
            print ('Creating data socket on' + str(self.data_address) + '...')
            self.datasock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.datasock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.datasock.bind(self.data_address)
            self.datasock.listen(5)
            print ('Data socket is started. Listening to' + str(self.data_address) + '...')
            self.client.send(bytes('125 Data connection already open; transfer starting.\r\n','utf-8'))
            return self.datasock.accept()
        except Exception as e:
            print ('ERROR: test ' + str(self.client_address) + ': ' + str(e))
            self.close_datasock()
            self.client.send(bytes('425 Cannot open data connection.\r\n','utf-8'))

    def close_datasock(self):
          print ('Closing data socket connection...')
          try:
             self.datasock.close()
          except:
              pass

    def run(self):
        try :
            print ('client connected: ' + str(self.client_address) + '\n')
            while True:
                cmd = self.client.recv(1024)
                cmd=cmd.decode()
                if not cmd: break
                print ('commands from ' + str(self.client_address) + ': ' + cmd)
                try:
                    func = getattr(self, cmd[:4].strip().upper())
                    func(cmd)
                    op1=cmd[:4]
                except AttributeError as e:
                    print ('ERROR: ' + str(self.client_address) + ': Invalid Command.')
                    self.client.send(bytes('550 Invalid Command\r\n','utf-8'))
        except Exception as e:
            print ('ERROR: ' + str(self.client_address) + ': ' + str(e))
            self.QUIT('')

    def QUIT(self, cmd):
        try:
            self.client.send(bytes('221 Goodbye.\r\n','utf-8'))
        except:
            pass
        finally:
            print ('Closing connection from ' + str(self.client_address) + '...')
            self.close_datasock()
            self.client.close()
            quit()

    def LIST(self, cmd):
        print ('LIST', self.cwd)
        (client_data, client_address) = self.start_datasock()
        try:
            listdir = os.listdir(self.cwd)
            if not len(listdir):
                max_length = 0
            else:
                max_length = len(max(listdir, key=len))
            header = '| %*s | %9s | %12s | %20s | %11s | %12s |' % (max_length, 'Name', 'Filetype', 'Filesize', 'Last Modified', 'Permission', 'User/Group')
            table = '%s\n%s\n%s\n' % ('-' * len(header), header, '-' * len(header))
            client_data.send(bytes(table,'utf-8'))
            for i in listdir:
                path = os.path.join(self.cwd, i)
                stat = os.stat(path)
                data = '| %*s | %9s | %12s | %20s | %11s | %12s |\n' % (max_length, i, 'Directory' if os.path.isdir(path) else 'File', str(stat.st_size) + 'B', time.strftime('%b %d, %Y %H:%M', time.localtime(stat.st_mtime))
					, oct(stat.st_mode)[-4:], str(stat.st_uid) + '/' + str(stat.st_gid))
                client_data.send(bytes(data,'utf-8'))

            table = '%s\n' % ('-' * len(header))
            client_data.send(bytes(table,'utf-8'))

            self.client.send(bytes('\r\n226 Directory send OK.\r\n','utf-8'))
        except Exception as e:
            print ('ERROR: ' + str(self.client_address) + ': ' + str(e))
            self.client.send(bytes('426 Connection closed; transfer aborted.\r\n','utf-8'))
        finally:
            client_data.close()
            self.close_datasock()



    def MKD(self, cmd):
        path = cmd[4:].strip()
        dirname = os.path.join(self.cwd, path)
        try:
            if not path:
                self.client.send(bytes('501 Missing arguments <dirname>.\r\n','utf-8'))
            else:
                os.mkdir(dirname)
                self.client.send(bytes('250 Directory created: ' + dirname + '.\r\n','utf-8'))
        except Exception as e:
            print ('ERROR: ' + str(self.client_address) + ': ' + str(e))
            self.client.send(bytes('550 Failed to create directory ' + dirname + '.','utf-8'))

    def RMD(self, cmd):
        path = cmd[4:].strip()
        dirname = os.path.join(self.cwd, path)
        try:
            if not path:
                self.client.send(bytes('501 Missing arguments <dirname>.\r\n','utf-8'))
            else:
                os.rmdir(dirname)
                self.client.send(bytes('250 Directory deleted: ' + dirname + '.\r\n','utf-8'))
        except Exception as e:
            print ('ERROR: ' + str(self.client_address) + ': ' + str(e))
            self.client.send(bytes('550 Failed to delete directory ' + dirname + '.','utf-8'))

    def DELE(self, cmd):
        path = cmd[4:].strip()
        filename = os.path.join(self.cwd, path)
        try:
            if not path:
                self.client.send(bytes('501 Missing arguments <filename>.\r\n','utf-8'))
            else:
                os.remove(filename)
                self.client.send(bytes('250 File deleted: ' + filename + '.\r\n','utf-8'))
        except Exception as e:
            print ('ERROR: ' + str(self.client_address) + ': ' + str(e))
            self.client.send(bytes('550 Failed to delete file ' + filename + '.','utf-8'))

    def STOR(self, cmd):
        path = cmd[4:].strip()
        if not path:
            self.client.send(bytes('501 Missing arguments <filename>.\r\n','utf-8'))
            return

        fname = os.path.join(self.cwd, path)
        client_data, client_address = self.start_datasock()
        try:
            file_write = open(fname, 'wb')
            while True:
                data = client_data.recv(1024)
                if not data:
                    break
                file_write.write(data)
            file_write.close()
            fil_ext=fname.split('.')
            fext=fil_ext[1].lower()
            if fext in ["txt","cpp","py"]:
                decrypt_text(fname)
            elif fext in ["jpg","jpeg","png"]:
                decrypt_image(fname)
            else:
                decrypt_audio(fname)

            self.client.send(bytes('226 Transfer complete.\r\n','utf-8'))
        except Exception as e:
            print ('ERROR: ' + str(self.client_address) + ': ' + str(e))
            self.client.send(bytes('425 Error writing file.\r\n','utf-8'))
        finally:
            client_data.close()
            self.close_datasock()



    def RETR(self, cmd):
        path = cmd[4:].strip()
        if not path:
            self.client.send(bytes('501 Missing arguments <filename>.\r\n','utf-8'))
            return

        fname = os.path.join(self.cwd, path)
        (client_data, client_address) = self.start_datasock()
        if not os.path.isfile(fname):
            self.client.send(bytes('550 File not found.\r\n','utf-8'))
        else:
            try:
                file_ext=path.split('.')
                fext=file_ext[len(file_ext)-1].lower()
                fname=path
                if fext in ["txt","cpp","py"]:
                    encrypt_text(fname)
                elif fext in ["jpg","jpeg","png"]:
                    encrypt_image(fname)
                else:
                    encrypt_audio(fname)
                file_read = open("enc_"+fname, "rb")
                data = file_read.read(1024)

                while data:
                    client_data.send(data)
                    data = file_read.read(1024)

                self.client.send(bytes('226 Transfer complete.\r\n','utf-8'))
            except Exception as e:
                print ('ERROR: ' + str(self.client_address) + ': ' + str(e))
                self.client.send(bytes('426 Connection closed; transfer aborted.\r\n','utf-8'))
            finally:
                client_data.close()
                self.close_datasock()
                file_read.close()

class FTPserver:
	def __init__(self, port, data_port):
		self.address = '0.0.0.0'

		self.port = int(port)
		self.data_port = int(data_port)

	def start_sock(self):
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		server_address = (self.address, self.port)

		try:
			print ('Creating data socket on', self.address, ':', self.port, '...')
			self.sock.bind(server_address)
			self.sock.listen(5)
			print ('Server is up. Listening to', self.address, ':', self.port)
		except Exception as e:
			print ('Failed to create server on', self.address, ':', self.port, 'because', str(e.strerror))
			quit()

	def start(self):
		self.start_sock()

		try:
			while True:
				print ('Waiting for a connection')
				thread = FTPThreadServer(self.sock.accept(), self.address, self.data_port)
				thread.daemon = True
				thread.start()
		except KeyboardInterrupt:
			print ('Closing socket connection')
			self.sock.close()
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
    p = int(input("Enter a prime number (17, 19, 23, etc): "))
    q = int(input("Enter another prime number (Not one you entered above): "))
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
    print ("Decrypting message with key ", rsa_public_key ," . . .")
    f1=open(fname,"rb")
    msg=f1.read()
    f1.close()
    msg=msg.decode()
    msg1=msg.split()
    msg1=list(map(int,msg1))
    print ("Your message is:")
    decrypted_msg=decrypt_rsa(rsa_public_key, msg1)
    print (decrypted_msg)
    f2=open(fname,"wt")
    f2.write(str(decrypted_msg))
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
    enc_file2 = open(fname,"rb")
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
    enc_file2 = open(fname,"rb")
    enc_data2 = enc_file2.read()
    enc_file2.close()
    cfb_decipher = AES.new(key, AES.MODE_CFB, iv)
    plain_data = cfb_decipher.decrypt(enc_data2)
    output_file = open(fname, "wb")
    output_file.write(plain_data)
    output_file.close()


port = input("Port - if left empty, default port is 10021: ")
if not port:
	port = 10021

data_port = input("Data port - if left empty, default port is 10020: ")
if not data_port:
	data_port = 10020

server = FTPserver(port, data_port)
server.start()

print ("Main",rsa_public_key,rsa_private_key)
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