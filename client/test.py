import socket
import time
import json
import os
import stat

# Add execute permission on client.py
os.chmod("./client.py", stat.S_IXUSR)

#waiting for other containers to setup -this should be changed to better system
time.sleep(40)

HOST = 'app'  # The server's containername/hostname
PORT = 65432  # The port used by the server

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
  s.connect((HOST, PORT))
  print(f"\nTEST 1: Add user\n")
  message_dict = {
    'type' : 'add_user',
    'user' : 'BigBob',
    'pass' : 'heyimbigbob'
  }

  message_json = json.dumps(message_dict)
  s.sendall(bytes(message_json, encoding="utf-8")) #send message to server
  
  data = s.recv(2048) 
  print('Should be', b'{"type": "add_user_r", "response": true}')
  print('Received ', repr(data)) #print debug message from server
  time.sleep(1)

  print(f"\nTEST 2: User Login\n")
  message_dict = {
    'type' : 'login',
    'user' : 'BigBob',
  }

  message_json = json.dumps(message_dict)
  s.sendall(bytes(message_json, encoding="utf-8")) #send message to server
  
  data = s.recv(2048) 
  print('Should be', b'{"type": "login_r", "hash_password": "heyimbigbob"}')
  print('Received ', repr(data)) #print debug message from server
  time.sleep(1)

  print(f"\nTEST 3: Check if user exists\n")
  message_dict = {
    'type' : 'is_user',
    'user' : 'BigBob',
  }

  message_json = json.dumps(message_dict)
  s.sendall(bytes(message_json, encoding="utf-8")) #send message to server

  data = s.recv(2048) 
  print('Should be', b'{"type": "is_user_r", "response": true}')
  print('Received ', repr(data)) #print debug message from server