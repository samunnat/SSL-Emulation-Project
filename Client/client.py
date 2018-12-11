"""
    client.py - Connect to an SSL server

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 117
        (Feel free to use more or less, this
        is provided as a sanity check)

    Put your team members' names:



"""
import base64
import hashlib
import hashlib
import os
import socket
import uuid
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

iv = b"G4XO4L\X<J;MPPLD"
print(type(iv), "iv")

host = "localhost"
port = 10001


# A helper function that you may find useful for AES encryption
def pad_message(message):
    addOn = " "*((16-len(message))%16)
    return message+addOn

def unpad_message(m):
	return m[:-ord(m[len(m)-1:])]

# TODO: Generate a random AES key
# done
def generate_key():
    return os.urandom(16)


# TODO: Takes an AES session key and encrypts it using the server's
# TODO: public key and returns the value
def encrypt_handshake(session_key):
	pubRSAKey = RSA.importKey(open('id_rsa.pub','r').read())
	cipher = PKCS1_OAEP.new(pubRSAKey)
	return cipher.encrypt(session_key)


# TODO: Encrypts the message using AES. Same as server function
def encrypt_message(message, session_key):
	padded_message = pad_message(message)

	# MODE_CBC = cipher block chaining
	cipher = AES.new(session_key, AES.MODE_CBC, iv)
	return base64.b64encode(iv + cipher.encrypt(padded_message))


# TODO: Decrypts the message using AES. Same as server function
def decrypt_message(message, session_key):
    decoded_message = base64.b64decode(message)
    iv = decoded_message[:16]
    print(iv, "iv")
    cipher = AES.new(session_key, AES.MODE_CBC, iv)
    return unpad_message(cipher.decrypt(decoded_message[16:])).decode('utf-8')


# Sends a message over TCP
def send_message(sock, message):
    sock.sendall(message)


# Receive a message from TCP
def receive_message(sock):
    data = sock.recv(1024)
    return data


def main():
    #user = input("What's your username? ")
    #password = input("What's your password? ")

    """
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    server_address = (host, port)
    print('connecting to {} port {}'.format(*server_address))
    sock.connect(server_address)
	"""
    try:
        # Message that we need to send
        #message = user + ' ' + password

        # TODO: Generate random AES key
        aes_key = generate_key()

        # TODO: Encrypt the session key using server's public key
        encrypted_session_key = encrypt_handshake(aes_key)

        message = "Hello, fella"

       	encrypted_message = encrypt_message(message, aes_key)
       	print("encrypted message", encrypted_message)

       	decrypted_message = decrypt_message(encrypted_message, aes_key)

       	print("decrypted_message", decrypted_message)
        """
        # TODO: Initiate handshake
        send_message()

        # Listen for okay from server (why is this necessary?)
        if receive_message(sock).decode() != "okay":
            print("Couldn't connect to server")
            exit(0)

        # TODO: Encrypt message and send to server

        # TODO: Receive and decrypt response from server and print
        """

    finally:
        print('closing socket')
        #sock.close()



if __name__ in "__main__":
    main()
