from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, load_der_public_key

def Create_New_Key():
    #this function uses Elliptic curve cryptography to create new keys
    #this function is used to create a public key and a private key
    #the bytes are returned in a way that can be sent over a JSON file if needed
    private_key = ec.generate_private_key( ec.SECP384R1() )
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return public_key_bytes.decode('latin-1'), private_key
    #return public_key, private_key

def Load_Public_Key(Friend_data):
    # this function takes the bytes for a public key and turns it into an object that python can use
    # the latin-1 encoding is used to be able to handle any bytes the key might have
    public_key = Friend_data.encode('latin-1')
    done_public_key = load_der_public_key(public_key)
    return done_public_key

def Create_Shared_Key(Private_Key, Friend_Public_Key):
    # this function takes a private key and someone else's public key to create a shared key
    # this is needed for Diffie-Hellman key exchange which is used for message sending
    shared_key = Private_Key.exchange(ec.ECDH(), Friend_Public_Key)
    return shared_key

def key_derivation(shared_key):
    # this function is used to change the shared key into a size that can be used in the encryption
    # this function uses a hash to create a new key for encryption
    derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'',
    ).derive(shared_key)
    return derived_key

#key_data, my_private_key = Create_New_Key()
#print(key_data)
#Friend_Public_Key = Load_Public_Key(key_data)
#shared = Create_Shared_Key(my_private_key, Friend_Public_Key)
#key_derivation(shared)
