import mysql.connector
import time
import socket
import _thread
import json
#*****************************************************************************
# Database stuff
#*****************************************************************************
#this gives db container to boot up
try:
  mydb = mysql.connector.connect(
    host="mysql",
    user="root",
    password="root",
    database="safedb"
  )
except:
  print("Could not connect to MySQL, sleeping 50 sec then trying again")
  #can change this value depending on how slow your machine takes to load up mysql container
  time.sleep(50)
  try:
    mydb = mysql.connector.connect(
      host="mysql",
      user="root",
      password="root",
      database="safedb"
    )
  except:
    print("Could not connect to MySQL after 50sec")
    exit()

#Executes query to the database, 
#returns a list of tuples where each tuple is row from table
def send_query(query):
  try:
    mycursor.execute(query)
    result = mycursor.fetchall()
    return list(result)
  except Exception as e:
    print("Error while querying database:"+str(e))
    return 0

#create cursor which is used to query and itterate results
mycursor = mydb.cursor()

#*****************************************************************************
# Server Code
#*****************************************************************************
HOST = 'app' #containers hostname (works like localhost but on docker network)
PORT = 65432 
#list of clients connected to server + their connection object
clients_online = []

def clientthread(conn, addr):
  """This function is used to create a new thread which is responsible for
     for all interactions between a client and the server"""
  with conn:
    #main server loop
    while True:
      try:
        #wait for messages from client
        message = conn.recv(2048)

        if not message:
          #print("message empty...probably a problem")
          continue
        #extract message into dictionary
        message = json.loads(message.decode("utf-8"))
        #print("recieved this from clients", repr(message))#here for debugging
        message_dict = {}
        #here we figure out what to do with the message
        if message['type'] == 'add_user':
          # assume user doesnt exist
          # add user to database
          # return confirmation T/F
          message_dict['type'] = 'add_user_r'
          message_dict['response'] = add_user(message['user'], message['pass'])

          message_json = json.dumps(message_dict)
          conn.sendall(bytes(message_json, encoding="utf-8")) 

        elif message['type'] == 'remove_user':
          # assume user exists
          # remove user from database
          # return confirmation T/F
          message_dict['type'] = 'remove_user_r'
          message_dict['response'] = remove_user(message['user'])

          message_json = json.dumps(message_dict)
          conn.sendall(bytes(message_json, encoding="utf-8"))         

        elif message['type'] == 'login':
          # check if user exists
          # if so return their hashed password
          # else return None/Null
          message_dict['type'] = 'login_r'
          if is_user(message['user']):
            message_dict['hash_password'] = get_hashed_pass(message['user'])
            #adding username to clientlist since we didnt know username 
            for client in clients_online:
              if client['conn'] is conn:
                client['user'] = message['user']
          else:
            message_dict['hash_password'] = None

          message_json = json.dumps(message_dict)
          conn.sendall(bytes(message_json, encoding="utf-8"))

        elif message['type'] == 'is_user':
          # check if user exists, return T/F
          message_dict['type'] = 'is_user_r'
          message_dict['response'] = is_user(message['user'])

          message_json = json.dumps(message_dict)
          conn.sendall(bytes(message_json, encoding="utf-8"))

        elif message['type'] == 'start_chat':
          #verify user exists
          if not is_user(message['receiver']):
            print("Tried to start chat with user but user not found")
          print("got a start_chat")
          message_dict['type'] = 'chat_started'
          message_dict['sender'] = message['sender']
          message_dict['receiver'] = message['receiver']
          message_dict['sender_key'] = message['sender_key']
          message_json = json.dumps(message_dict)
          #send message to receiver
          send_to(message['receiver'], message_json)
          print("sent a chat_started")

        elif message['type'] == 'confirm_chat':
          print("got a confirm_chat")
          message_dict['type'] = 'chat_confirmed'
          message_dict['receiver_key'] = message['receiver_key']
          message_dict['sender'] = message['sender']
          message_dict['receiver'] = message['receiver']
          message_json = json.dumps(message_dict)
          #send message to sender
          send_to(message['sender'], message_json)
          print('sent a chat_confirmed')

        elif message['type'] == 'message':
          print("message received")
          message_json = json.dumps(message)
          #send message to sender
          send_to(message['receiver'], message_json)
          print("forwarded message")

        elif message['type'] == 'expose_key':
          print("exposing key:",message['key'])

      except Exception as e:
        print("Got an error:"+str(e))
        continue

def is_user(username):
  """check if user exists in database"""
  query = f"SELECT count(1) FROM users WHERE username = '{username}';"
  (result,) = send_query(query)[0]
  if result == 0:
    return False
  else:
    return True

def add_user(username, password):
  """adds user to the database"""
  #print(f"adding user:{username}, pass:{hash_password}")
  query = f"INSERT INTO users (username, password) VALUES ('{username}', '{password}');"

  send_query(query)
  #after adding user I check that it worked and return result
  return is_user(username) 

def remove_user(username):
  """removes user from the database"""
  #print(f"removing user:{username}, pass:{hash_password}")
  query = f"DELETE FROM users WHERE username = '{username}';"
  send_query(query)
  #after adding user I check that it worked and return result
  return not is_user(username)

def get_hashed_pass(username):
  """fetches users hashed password from database and sends to client 
     so client can authenticate"""
  query = f"SELECT password FROM users where username = '{username}';"
  (password,) = send_query(query)[0]
  return password

def send_to(username, message):
  """sends a message to one of the other clients in client_online"""
  for client in clients_online:
    if client['user'] == username:
      try:
        client['conn'].sendall(bytes(message, encoding="utf-8"))
      except:
        print('could not send message')
        client['conn'].close()

#opens server socket 
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
  s.bind((HOST, PORT))
  s.listen()
  print("Waiting for a connection")
  while True:
    conn, addr = s.accept()
    #add client to client list *no username yet
    client_dict = {'conn':conn}
    clients_online.append(client_dict)
    print("server got a connection")
    #when a user connects start a new thread for them
    _thread.start_new_thread(clientthread,(conn,addr))
