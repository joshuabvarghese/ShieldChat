#!/usr/bin/env python3

# SENG 360 A3
# Group 27
# Client Side Code

# Python libraries
import socket
import time
import json
import sys
import os
import re
from getpass import getpass
from argon2 import PasswordHasher

# Key creation functions
from Key_Generation import Create_New_Key
from Key_Generation import Load_Public_Key
from Key_Generation import Create_Shared_Key
from Key_Generation import key_derivation

# Message Encryption functions
from Message_Encryption import At_Rest_Encryption
from Message_Encryption import At_Rest_Decryption
from Message_Encryption import Integrity_Hashing


# Password Hasher for Authentication
ph = PasswordHasher()

# Authentication States
LOGIN = 1
CREATE_ACCOUNT = 2

# At rest encryption key for user
history_key = ""

def main():
  
  # main variables
  HOST = 'app'  # The server's containername/hostname
  PORT = 65432  # The port used by the server
  global history_key

  # Ask user to login or create account
  login_value = create_or_login()
  login_result = ""
  if login_value == LOGIN:
    login_result = login()
  elif login_value == CREATE_ACCOUNT:
    login_result = create_account()

  # Create socket and connect to server
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    # Create login message request to send to server
    message_dict = {}
    if login_value == CREATE_ACCOUNT:
      # If creating account, send new username and password hash to server
      message_dict['type'] = 'add_user'
      message_dict['user'] = login_result[0]
      message_dict['pass'] = login_result[1]  # Is password hash
    else:
      # If logging in, only send username to receive the hash from the server
      message_dict['type'] = 'login'
      message_dict['user'] = login_result[0]

    message_json = json.dumps(message_dict)
    s.sendall(bytes(message_json, encoding="utf-8")) #send message to server

    #User authentication from server, loop until succesful authentication
    user_authenticated = False
    while user_authenticated == False:
      data = s.recv(2048)
      message = json.loads(data.decode("utf-8"))  # Receive message from server

      # Check if properly authenticated
      user_authenticated = user_auth(message, login_value, login_result)
    print("Authenticated")

    # Create at rest encryption key for this Docker instance if it does not exist
    mykey_filename = login_result[0] + "_key.txt"
    if os.path.exists(mykey_filename) == False:
      pass
      public_history_key, Not_important = Create_New_Key()
      Public_Key = Load_Public_Key(public_history_key)
      shared_history = Create_Shared_Key(Not_important, Public_Key)
      history_key = key_derivation(shared_history)
      with open(mykey_filename, "w") as key_file:
        key_file.write(history_key.decode('latin-1'))
    else:
      with open(mykey_filename, "r") as key_file:
        history_key = (key_file.read().encode('latin-1'))

    # Go to main menu
    main_menu(s, login_result, login_value)



def create_or_login():
  """This function takes input from a user to determine to login or create a new account"""

  login_value = ""

  print("1 - Log In\n2 - Create Account")
  while len(login_value) == 0:
    try:
      login_value = int(input("> "))
      if login_value == LOGIN:
        break
      elif login_value == CREATE_ACCOUNT:
        break
      else:
        login_value = ""
    except:
      pass

  return login_value



def login():
  """This function retreives the password and username input from the user on the command line"""

  username = ""
  password = ""
  print("\n--Log In--\n")

  while len(username) == 0:
    username = str(input("Username: "))

  while len(password) == 0:
    password = getpass("Password: ")

  # Send username to server, to receive hash back
  return (username, password)



def create_account():
  """This function prompts the user to create an account, hashes the password, to be sent to server"""
  password = ""
  confirm_pass = ""
  username = ""
  confirm_user = ""
  print("\n--Creating Account--\n")

  # Create username, verify
  while True:
      while len(username) == 0:
          username = str(input("Create Username: "))
      while len(confirm_user) == 0:
          confirm_user = str(input("Confirm Username: "))
      if confirm_user == username:
          break
      else:
          print("\nUsernames do not match.\n")
          username = ""
          confirm_user = ""

  # Create password, verify
  while True:
      while len(password) == 0:
          password = getpass("Create Password: ")
      while len(confirm_pass) == 0:
          confirm_pass = getpass("Confirm Password: ")
      if confirm_pass == password:
          break
      else:
          print("\nPasswords do not match.\n")
          password = ""
          confirm_pass = ""

  # Create password hash
  pass_hash = ph.hash(password)

  return (username, pass_hash)



def user_auth(message, login_value, login_result):
  """This function authenticates the user using the server response, verifies password hash for user signing in"""

  # If logging in existing user, verify password hash
  if login_value == LOGIN:
    try:
      hash = message['hash_password']
      ph.verify(hash, login_result[1])    # Throws error if verify does not work, does NOT return false
      return True
    except:
      print("Login failed. Exiting...")
      sys.exit(1)

  # If creating new account, check if username is taken
  elif login_value == CREATE_ACCOUNT:
    try:
      # If True response, new username was free, account created and signed in
      response = message['response']
      if response == True:
        return True
      else:
        print("Username already taken. Exiting...")
        sys.exit(1)
    except:
      print("Username already taken. Exiting...")
      sys.exit(1)



def main_menu(s, login_result, login_value):
  while True:
    menu_option = 0
    print("\n1 - Send message to user\n2 - Look at message history\n3 - Wait for new messages\n4 - Delete message history\n5 - Delete your account\n6 - Exit")
    while menu_option == 0:
      menu_option = int(input("> " ))

    if menu_option == 1:
      send_message(s, login_result)

    elif menu_option == 2:
      read_message_history()

    elif menu_option == 3:
      wait_for_messages(s)

    elif menu_option == 4:
      delete_message_history()

    elif menu_option == 5:
      delete_account(s, login_result, login_value)

    elif menu_option == 6:
      print("Exiting")
      sys.exit(0)

    else:
      continue



def receive_message(key, message, s):
  """Function to decrypt text or picture messages from another user, store at rest encrypted"""

  user = message['sender']          # Determine who sent the message
  history_file = user + ".txt"      # Select that history file for converstation with that user
  message_string = ""
  
  # If a text message was received
  if message['text']:
    try:
      Encoded_Message = message['text']
      received_hash = message['hash']
      hash = Integrity_Hashing(Encoded_Message, key)

      if (received_hash == hash):
        print("Hash confirmed")
      else:
        print("ERROR: Hash value wrong")

      Decoded_Message = At_Rest_Decryption(Encoded_Message, key)

      message_string = user + ": " + Decoded_Message
      
      # Print message so user can see
      print(message_string)

      encrypted_message = At_Rest_Encryption(message_string, history_key)

      # Open file corresponding to that conversation and add the message
      with open(history_file, 'a') as h_f:
        h_f.write(encrypted_message + "END_OF_MESSAGE")
    except:
      print("Error receiving a text message")

  # Else if received a picture message instead
  elif message['picture']:
    try:
      Picture_Length = message['picture_len']   # Determine how many bytes the picture is
      Encoded_Picture = message['picture']
      Decoded_Picture = At_Rest_Decryption(Encoded_Picture, key)

      Decoded_Picture = Decoded_Picture[:Picture_Length]    # Remove encryption padding
      picture_bytes = bytes.fromhex(Decoded_Picture)
      
      # Set filename to the user its from and the original filename
      picture_filename = message['sender'] + message['picture_filename']

      # Let user know they received a picture
      print(user, "sent you a picture called ", message['picture_filename'])
      
      #TODO encrypt picture bytes
      #encrypted_picture = At_Rest_Encryption(Decoded_Picture, history_key)
      # try:
      #   with open(picture_filename, 'w') as p:
      #     p.write(encrypted_picture)
      # except:
      #   print("error writing picture to a file")

      encrypted_picture_bytes = picture_bytes

      try:
        with open(picture_filename, 'wb') as p:
          p.write(encrypted_picture_bytes)
      except:
        print("error writing picture to a file")

      # encrypt picture filename
      encrypted_message = At_Rest_Encryption(picture_filename, history_key)

      # open file corresponding to that user and add that a picture was received
      with open(history_file, 'a') as h_f:
        h_f.write(encrypted_message + "END_OF_MESSAGE")

    except:
      print("Error receiving a picture message")

  message_server_dict = {}
  message_server_dict['type'] = 'expose_key'
  message_server_dict['key'] = key.decode('latin-1')

  message_json = json.dumps(message_server_dict)
  s.sendall(bytes(message_json, encoding="utf-8")) #send message to server



def acceptchat(s, message):
  """This function is used to create key pairs for exchange when sending messages"""

  #making the key pair shared key
  public_key_bytes, private_key = Create_New_Key()
  user_public_key_bytes = message["sender_key"]
  user_public_key = Load_Public_Key(user_public_key_bytes)
  shared_key = Create_Shared_Key(private_key, user_public_key)
  key = key_derivation(shared_key)

  #sending back the public key and confirmation
  message_server_dict = {}
  message_server_dict['type'] = 'confirm_chat'
  message_server_dict['receiver'] = message['receiver']
  message_server_dict['sender'] = message['sender']
  message_server_dict['receiver_key'] = public_key_bytes

  message_json = json.dumps(message_server_dict)
  s.sendall(bytes(message_json, encoding="utf-8")) #send message to server

  return key



def send_message(s, login_result):
  """This message allows the user to send a text message or picture to another user"""

  # Enter recipient of the message
  user_to_chat_with = ""
  while len(user_to_chat_with) == 0:
    user_to_chat_with = input("Enter the username of recipient: ")

  # Start key exchange with other user
  public_key_bytes, private_key = Create_New_Key()

  message_server_dict = {}
  message_server_dict['type'] = 'start_chat'
  message_server_dict['receiver'] = user_to_chat_with
  message_server_dict['sender'] = login_result[0]
  message_server_dict['sender_key'] = public_key_bytes

  # Send to server
  message_json = json.dumps(message_server_dict)
  s.sendall(bytes(message_json, encoding="utf-8")) #send message to server

  # Get response from user I wanted to chat with
  data = s.recv(2048)
  message = json.loads(data.decode("utf-8"))

  # Creating shared key from user public key and my private key
  user_public_key_bytes = message["receiver_key"]
  user_public_key = Load_Public_Key(user_public_key_bytes)
  shared_key = Create_Shared_Key(private_key, user_public_key)
  key = key_derivation(shared_key)


  # Choose between text or picture message
  text_or_picture = 0
  text_to_send = ""
  picture_filename = ""
  picture_string = ""
  picture_len = 0
  while text_or_picture == 0:
    print("\n1 - Send text\n2 - Send picture\n")
    text_or_picture = int(input("> "))

    # If text, enter text
    if text_or_picture == 1:
      text_to_send = ""
      while len(text_to_send) == 0:
        text_to_send = input("Enter Message to " + user_to_chat_with + ": ")

    # If picture, enter filename
    elif text_or_picture == 2:
      picture_filename = ""
      while len(picture_filename) == 0:
        picture_filename = input("Enter picture filename to sent to " + user_to_chat_with + ": ")

      try:
        with open(picture_filename, "rb") as p:
          picture_string = (p.read()).hex()
          picture_len = len(picture_string)
      except:
        print("Error reading:", picture_filename)

    else:
      text_or_picture = 0


  # Form message to send
  message_to_user = {}
  message_to_user['type'] = 'message'
  message_to_user['text'] = text_to_send
  message_to_user['receiver'] = user_to_chat_with
  message_to_user['sender'] = login_result[0]
  message_to_user['picture'] = picture_string
  message_to_user['picture_filename'] = picture_filename
  message_to_user['picture_len'] = picture_len

  # encrypt message to user before sending
  if text_or_picture == 1:
        Encoded_Message = At_Rest_Encryption(text_to_send, key)
        hash = Integrity_Hashing(Encoded_Message, key)
        message_to_user['hash'] = hash
        message_to_user['text'] = Encoded_Message

  # Encrypt picture string (string containing hex values)
  if text_or_picture == 2:
      Encoded_Picture = At_Rest_Encryption(picture_string, key)
      message_to_user['picture'] = Encoded_Picture
      hash = Integrity_Hashing(Encoded_Picture, key)
      message_to_user['hash'] = hash

  # Send to server
  message_user_json = json.dumps(message_to_user)
  s.sendall(bytes(message_user_json, encoding="utf-8")) #send message to server



def wait_for_messages(s):
  """Function to let user wait for incoming messages from another user"""

  while True:
    data = s.recv(2048)
    message = json.loads(data.decode("utf-8"))

    # Initial key exchange
    if message['type'] == "chat_started":
      key = acceptchat(s, message)

    # If received a message from a user
    if message['type'] == "message":
      receive_message(key, message, s)

    # Let user refresh to check for more messages
    print("\n1 - Refresh messages\n2 - Return to menu\n")
    user_input = int(input("> "))

    if user_input == 1:
      continue
    elif user_input == 2:
      return
    else:
      continue



def read_message_history():
  """This function decrypts and reads out an entire conversation with another user"""

  # User enters the username of the conversation they would like to read from
  conversation = input("Enter which user: ")
  history_file = conversation + ".txt"
  picture_pattern = conversation + "\w+.png"
  picture_pattern = re.compile(picture_pattern)

  # If a conversation does not exist with that user, print and return
  if os.path.exists(history_file) == False:
    print("Conversation with " + conversation + " does not exist.")
    return

  with open(history_file, 'r') as f:
    contents = f.read()

  messages = contents.split("END_OF_MESSAGE")
  messages = [msg for msg in messages if len(msg) > 0]
  for message in messages:
    decrypted_message = At_Rest_Decryption(message, history_key)      # Decrypt message
    picture_match = re.search(picture_pattern, decrypted_message)
    
    # Check if it was a photo sent
    if picture_match:
      picture_file = picture_match.group()
      print(conversation, "sent this photo:", picture_file)
    
    # Else print text message
    else:
      print(decrypted_message)

  return



def delete_message_history():
  """This function delets all text messages and pictures from a specified user"""

  conversation = input("Enter which user: ")    # Enter which conversation to delete
  history_file = conversation + ".txt"
  picture_pattern = conversation + "\w+.png"
  picture_pattern = re.compile(picture_pattern)

  # If not conversation history with that user exists, exit
  if os.path.exists(history_file) == False:
    print("Conversation with " + conversation + " does not exist.")
    return

  # Find all picture files sent in this conversation in the main conversation file
  picture_files = []

  with open(history_file, 'r') as f:
    contents = f.read()

  messages = contents.split("END_OF_MESSAGE")
  messages = [msg for msg in messages if len(msg) > 0]
  for message in messages:
    decrypted_message = At_Rest_Decryption(message, history_key)
    picture_match = re.search(picture_pattern, decrypted_message)
    if picture_match:
      picture_file = picture_match.group()
      picture_files.append(picture_file)        # Find picture files to delete
    else:
      continue

  # Delete all picture files
  for picture_file in picture_files:
    if os.path.exists(picture_file):
      os.remove(picture_file)

  # Delete main conversation
  if os.path.exists(history_file):
    os.remove(history_file)

  return


def delete_account(s, login_result, login_value):
  """This function sends a request to the server to delete the user from the database"""

  my_username = login_result[0]
  hash = ""

  if login_value == LOGIN:
    hash = ph.hash(login_result[1])
  elif login_value == CREATE_ACCOUNT:
    hash = login_result[1]

  # Create delete request
  delete_account_message = {}
  delete_account_message['type'] = "remove_user"
  delete_account_message['user'] = my_username
  delete_account_message['pass'] = hash

  # Send to server
  message_user_json = json.dumps(delete_account_message)
  s.sendall(bytes(message_user_json, encoding="utf-8")) #send message to server

  # Wait for response
  data = s.recv(2048)
  server_delete_response = json.loads(data.decode("utf-8"))

  # Let user know if delete was confirmed
  if server_delete_response['response'] == True:
    print("Account successfuly deleted")
    sys.exit(0)
  else:
    print("Account deletion not successful :(")





if __name__ == "__main__":
  main()
