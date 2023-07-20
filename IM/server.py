import threading
import socket
import threading
import socket
#from keyGen import *
import secrets
from security import *
import rsa


host = '127.0.0.1'
port = 9876

# server is bound to specific port
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen()

clients = []
keys_list = []

# Loads public rsa key for the server


def loadKeys(var):
    publick = f"server_keys/{var}/publicKey.pem"
    with open(publick, 'rb') as p:
        publicKey = rsa.PublicKey.load_pkcs1(p.read())
    return publicKey

# Handles all receive communications from the client


def handle(client):
    while True:
        try:
            msg = client.recv(1024).decode('ascii')
            response = ""
            # Handles list command case and returns list of active users
            if msg == "!list":
                response = list_clients()
                print(response)  # keep
                client.send(response.encode('ascii'))
            # Handles case where client wants to connect back to server again
            elif msg == "!reconnect":
                for mark in clients:
                    if mark.client == client:
                        mark.state = "IDLE"
                        mark.port = -1
            # Handles case where client wants to establish session with other clients
            elif "!session" in msg:
                split = msg.split()
                if split[1] == "host":
                    for host in clients:
                        if host.client == client:
                            host.port = int(split[2])
                    client.send("Waiting for connection...".encode('ascii'))
                # Marks the client as busy now
                else:
                    for mark in clients:
                        if mark.client == client:
                            mark.state = "BUSY"
                    c1 = get_nickame(client)
                    # Marks client back to idle if error occurs
                    response = init_session(c1, split[1])
                    if 'ERROR' in response:
                        mark.state = "IDLE"
                        client.send(response.encode('ascii'))
                    else:
                        client.send(b'Connects--'+b'\:n:\n'.join(response))
        except:
            # Handles case where client is disconnected and closes connection
            for left_client in clients:
                if left_client.client == client:
                    nickname = left_client.nickname
                    clients.remove(left_client)
            client.close()
            print(f"{nickname} left the chat!")
            break

# Server sends details for client to initiate client to client communication


def init_session(client1_name, client2_name):
    for client in clients:
        if client.nickname == client2_name:
            if client.port == -1:
                return "SESSION ERROR: CLIENT_NOT_HOSTING"
            if (client.state == "BUSY"):
                return "SESSION ERROR: BUSY_CLIENT"
            #client.state = "BUSY"
            else:
                loc = f"server_keys/{client1_name}/sessionKey.txt"
                with open(loc, "rb") as binary_file:
                    c1session = binary_file.read()
                c1_keys = generated_keys(c1session)

                # generate client-client session key
                ccsessionKey = secrets.token_bytes(16)

                loc = f"server_keys/{client2_name}/sessionKey.txt"
                with open(loc, "rb") as binary_file:
                    c2session = binary_file.read()
                c2_keys = generated_keys(c2session)
                # encrypt client-client session key with client-server session key of client 2
                encrypt_ccsession = encryptText(
                    ccsessionKey, c2_keys[0], c2_keys[2])
                # encrypt and send message to client 1:port of client 2 + client-client session key + encrypted client-client session key for client 2
                var = ("SESSION: " + str(client.port)+':\n:\nSK1: ').encode() + \
                    ccsessionKey + b':\n:\nSK2: ' + b''.join(encrypt_ccsession)
                encrypted = encryptText(var, c1_keys[0], c1_keys[2])
                client.state = "BUSY"
                return encrypted
    return "SESSION ERROR: CLIENT_NOT_FOUND"

# Lists all active clients along with states


def list_clients():
    msg = "Connected Clients: \n"
    for i in range(len(clients)):
        msg += f'{clients[i].nickname}\t{clients[i].state}\n'
    return msg

# This method gets the client's username


def get_name():
    while True:
        client, address = server.accept()
        client.send('NICK'.encode('ascii'))
        nickname = client.recv(1024).decode('ascii')
        clients.append(ClientInfo(client, address, nickname.strip(), "IDLE"))
        print(f'Client {nickname} has joined.')
        send_nonce(client)

# This method generates and sends the client a random nonce, then calls the authentication method


def send_nonce(client):
    nonce = secrets.token_urlsafe()
    tmpMsg = 'NONCE' + nonce
    client.send(tmpMsg.encode('ascii'))
    authentication(client, nonce)

# This method is used to get client's username


def get_nickame(c):
    for nclient in clients:
        if nclient.client == c:
            nickname = nclient.nickname
            return nickname

# This method recieves the client's digital signature and verifies it with their public key
# If it passes verification, the communication thread is started


def authentication(client, nonce):
    client.send('GETSIGN'.encode('ascii'))
    signa = client.recv(1024)
    new_nonce = nonce.encode()
    nick = get_nickame(client)
    publicKey = loadKeys(nick)
    # If client is safe for auth, this will return "SHA-1"
    text = rsa.verify(new_nonce, signa, publicKey)
    if "SHA-1" in text:
        # generate client-server session key
        sessionKey = secrets.token_bytes(16)
        loc = f"server_keys/{nick}/sessionKey.txt"
        with open(loc, "wb") as binary_file:
            # Write bytes to file
            binary_file.write(sessionKey)
        client.send('YES'.encode('ascii'))
        text2 = client.recv(1024).decode('ascii')
        if "thanks" in text2:
            # send client-server session key by encrypting with client's private key
            encoded_session = rsa.encrypt(sessionKey, publicKey)
            client.send(encoded_session)
            generated_keys(sessionKey)

            thread = threading.Thread(target=handle, args=(client,))
            thread.start()
    else:
        print("Sorry trudy you cannot be authenticated!")

# Stores all attributes needed for each client


class ClientInfo:
    def __init__(self, client, address, nickname, state):
        self.client = client
        self.address = address
        self.nickname = nickname
        self.state = state
        self.port = -1


print("Server is listening...")
get_name()
