from Crypto.Cipher import AES
from Crypto import Random
import numpy as np

def At_Rest_Encryption(Message, key):
    #Takes 16 bytes of data, and encrypts it to be stored locally
    iv = np.random.bytes(16)
    Encoded_Message = Message.encode()
    Padded_Message = Encoded_Message + Add_Padding(Message)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(Padded_Message)


def At_Rest_Decryption(Encrypted_Message, key):
    iv = Encrypted_Message[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    message_With_Padding = cipher.decrypt(Encrypted_Message[AES.block_size:])
    Message = message_With_Padding.rstrip(b"\0")
    return Message.decode("utf-8")


def Add_Padding(Message):
    Padding = ""
    length = len(Message) % AES.block_size
    if(length != 0 ):
        Padding_Length = AES.block_size - length
        Padding = b"\0" * Padding_Length
    return Padding


key = np.random.bytes(16)
Message = "Hello"

Test_Encryption = At_Rest_Encryption(Message, key)
print(Test_Encryption)
Test_Decryption = At_Rest_Decryption(Test_Encryption, key)
print(Test_Decryption)
