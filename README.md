# ShieldChat
A secure messaging service written in python

## Install and run
1. Open terminal, `cd` to desired location for repo and <br>
   run `git clone https://gitlab.csc.uvic.ccd safe-talka/courses/2021091/SENG360/teams/group-27/safe-talk.git`
2. Once installed, cd to repo (`cd safe-talk`)
3. Run `docker-compose up --build`
4. Give time for all the containers to build and run
5. Once the server writes "Waiting for a connection" you can start a client session
6. Start client by using `docker exec -t -i client1 /bin/bash` on a new terminal within the same directory
7. Once inside the container run `./client.py` to start the client script
8. If you want to start a second client do step 6. (with client2) and 7. again

## Docker
This project is run with docker containers. You will need to have docker installed to the run code.

Open terminal/cmd and cd to main directory where the docker-compose.yml file is. 

The following are some docker commands that may help:

*the containers all have names (app, mysql, client1, client2) so you can use the those instead of container ID's

To build/run containers:
* type `docker-compose up` use `--build` when wanting to update files such as code

To take down containers:
* type `docker-compose down`

To see which containers are currently running:
* type `docker ps`

To stop a container:
* type `docker stop <container_id>`

To enter a containers shell:
* type `docker exec -t -i <container_id> /bin/bash`

To view logs from containers:
* type `docker logs <container_id>` 

To remove all exited containers:
* type `docker container prune`

To remove all stashed container data (AKA start clean):
* type `docker system prune -a`

## MySQL
The apps database runs off MySQL which is hosted separately on a container.

Database credentials: 
* password - root
* username - root
* database name - safedb

To access MySQL commandline client enter mysql container shell then:
* type `mysql -u root -proot`
* then type `use <database name>;`

## Architecture
We have a simple client/server architecture. The software is all bundled in a Docker-Compose setup which allows for easy deployment on any machine without worrying about depenencies. Below is a diagram of the basic architecture structure:
![alt text](https://github.com/cusitristan/python-mysql-docker/blob/main/imgs/Architecture.png?raw=true "Architecture Diagram")

We also see that the server creates a thread for each client connection allowing for concurrent processessing of client requests
### Directory
The following is our projects directory structure with notes:
```
app/
   At_Rest_Encryption.py      #at rest encryption module
   Dockerfile                 #docker config file
   app.py                     #main server code
   requirements.txt           #python requirements (packages used)
client/
   1x1.png                    #test image
   Dockerfile  
   Key_Generation.py          #key generation module
   Message_Encryption.py      #encryption module
   client.py                  #main client code
   dummy_script.py            #script that keeps container alive before running client code
   requirements.txt
mysql/
   Dockerfile
   mysql_schema.sql           #database schema and initial data uploading
imgs/
   Architecture.png           #used for README
Docker-compose.yml            #docker-compose config file
README.md
 ```


### Communication
- The server and clients communicate through python sockets 
- Each client has their own socket connection object created with the server
- Communications through the socket is done through a python dictionary that is converted into a json before encryption
- The format of the dictionary is that each dictionary has a key value pair of ('type' : value) which explains what its purpose is
 
The following are the dictionary types and their parameters:
```yaml
type : "add_user"
user : "username"
pass : "hashed_password"
```
```yaml
type : "add_user_r"
response : 'True/False'
```
```yaml
type : "remove_user"
user : "username"
pass : "hashed_password"
```
```yaml
type : "remove_user_r"
response : 'True/False'
```
```yaml
type : "login"
user : "username"
```
```yaml
type : "login_r"
hashed_password : 'hashed_password/None'
```
```yaml
type : "is_user"
user : "username"
```
```yaml
type : "is_user_r"
response : 'True/False'
```
```yaml
type : "start_chat"
sender : "senders_username"
receiver : "receivers_username"
sender_key : "senders_public_key"
```
```yaml
type : "chat_started"
sender : "senders_username"
receiver : "receivers_username"
sender_key : "senders_public_key"
```
```yaml
type : "confirm_chat"
sender : "senders_username"
receiver : "receivers_username"
receiver_key : "receiver_public_key"
```
```yaml
type : "chat_confirmed"
sender : "senders_username"
receiver : "receivers_username"
receiver_key : "receiver_public_key"
```
```yaml
type : "message"
text : "receiver_public_key"
receiver : "receivers_username"
sender : "senders_username"
picture : "picture_bytes"
picture_filename : "filename"
hash : "hash_value"
```
```yaml
type : "expose_key"
key : 'key_value'
```

## Security

the app uses: key exchange algorithms, hashing, and AES encryption to ensure: Message integrity, end-to-end encryption with perfect forward secrecy, and at-rest encryption.

### Message integrity

in order to ensure Message integrity the app calculates a hash value on the sender side with the message + a secert key that both the sender and the receiver have to calculate a hash value. this hash value is than sent along side the message to the receiver. once the receiver gets the message they also calculate the same hash with the message received and the secert key that was never sent over the network. if the hash matches the hash sent we know that Message integrity can be proven.

``` python
from cryptography.hazmat.primitives import hashes

def Integrity_Hashing(Message, key):
    Message_hash = hashes.Hash(hashes.SHA256())
    Message_hash.update(key)
    Message_hash.update(Message.encode('latin-1'))
    Final_hash = Message_hash.finalize()
    return Final_hash.decode('latin-1')
```

### end-to-end encryption with perfect forward secrecy

in order to ensure end-to-end encryption the system preforms a Diffie–Hellman key exchange before every message, this is done by having a handshake happen before every message with the following functons:

``` python
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
```

### at-rest encryption

the encryption of the data when it is stored on the client machine is done with Advanced Encryption Standard and cipher-block chaining, this is used with a key that is assigned to the user when they create an account and login for the first time. this key is different from the keys used for messaging and therefore is never exposed and will stay secure over the use of the application. the same key is used across all sessions so that users can read data from a previous session. the key is made with the key generation functions described above:

``` python
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
```

### Authentication

Users are authenticated by using the Argon2 password hashing algorithm. When creating a new account, the client sends the username and password hash to the server. The server checks if the username has not been taken already and creates a new user entry. When logging in, the user enters their username and password. A login request is sent to the server and the server sends back the stored password hash corresponding to that user. The client then verifies the hash using the Argon2 library to authenticate the user.


### Considerations
- database and app are kept in separate containers isolating them makes it more difficult to attack the database through the app 
- database credentials should be better than user = root, password = root
- database user for the app should not be root but rather a more limited role
- keeping credentials separate from the code would be good idea
- query parameters from user are fed into query with formatted string (f-string) 

## Limitations
- app can only handle tiny images (2048-bytes) because of limit on socket 
- app cannot display images, only that the image was received
- app simply displays key after use as a way to "expose" it
- limited testing to only the best case scenario
- little error detection/handling
- app only works on localhost
- clients must be in the same docker network to connection
- no unit tests

