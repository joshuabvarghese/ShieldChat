from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives import hashes
import numpy as np

# key creation functions
from Key_Generation import Create_New_Key
from Key_Generation import Load_Public_Key
from Key_Generation import Create_Shared_Key
from Key_Generation import key_derivation


def At_Rest_Encryption(Message, key):
    # encryption for storing the messages on the Client
    # uses Advanced Encryption Standard and cipher-block chaining to encode the message
    # used to store on files
    iv = np.random.bytes(16)
    Encoded_Message = bytes(Message, 'utf-8')
    Padded_Message = Encoded_Message + Add_Padding(Encoded_Message)
    mode = CBC(iv)
    cipher = Cipher(algorithms.AES(key), mode)
    encryptor = cipher.encryptor()
    Encrypted_Message = encryptor.update(Padded_Message) + encryptor.finalize()
    return (iv + Encrypted_Message).decode('latin-1')

def At_Rest_Decryption(Encrypted_Message, key):
    # decrypts the data that is stored at rest,
    # uses Advanced Encryption Standard and cipher-block chaining
    Encrypted_Message = Encrypted_Message.encode('latin-1')
    iv = Encrypted_Message[:16]
    mode = CBC(iv)
    cipher = Cipher(algorithms.AES(key), mode)
    decryptor = cipher.decryptor()
    Message = decryptor.update(Encrypted_Message[16:]) + decryptor.finalize()
    return Message.decode("utf-8")

def Add_Padding(Message):
    # can be used to padd a message to the length for the encrypting and decrypting
    # adds bits to the end if needed
    Padding = ""
    length = len(Message) % 16
    if(length != 0 ):
        Padding_Length = 16 - length
        Padding = b"\0" * Padding_Length
    return Padding

def Integrity_Hashing(Message, key):
    #calculates the hashing value for the message sent over the server
    #used to ensure message integrity
    Message_hash = hashes.Hash(hashes.SHA256())
    Message_hash.update(key)
    Message_hash.update(Message.encode('latin-1'))
    Final_hash = Message_hash.finalize()
    return Final_hash.decode('latin-1')


#Creating keys to test
key_data, my_private_key = Create_New_Key()
Friend_Public_Key = Load_Public_Key(key_data)
shared = Create_Shared_Key(my_private_key, Friend_Public_Key)
key = key_derivation(shared)

#Encoding message
#message = "343 red2"
#print("Message is: " + message)
#Encoded_Message = At_Rest_Encryption(message, key)
#print(Encoded_Message)
##Decoded_Message = At_Rest_Decryption(Encoded_Message , key)
#print(Decoded_Message)
#hash = Integrity_Hashing(Encoded_Message, key)
#print(hash)
#print(len(hash))
