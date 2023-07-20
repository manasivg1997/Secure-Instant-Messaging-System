import socket
import threading
#from keyGen import *
import sys
import os
from security import *
import calendar
import time
import rsa

# Information on how to use the messenger
print("WELCOME!")
print("Helpful commands: ")
print("To make yourself available for connection: !session host")
print(
    "To start communicating with a client: !session [Username of client you wish to speak with]")
print("To view a list of online clients and their statuses: !list")
print("To disconnect from a client and reconnect back to the server: !disconnect")

# Gets client's nickname
nickname = input("Enter your username: ")

# Used for communication from client to server
client_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_server.connect(('127.0.0.1', 9876))

# Used for communication from client to client
client_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_client.bind(('127.0.0.1', 0))
stop_server = threading.Event()

cc_sessionKeyB = bytes()

# Loads public and private rsa keys for client


def loadKeys(var):
    publick = f"client_keys/{var}/publicKey.pem"
    privatek = f"client_keys/{var}/privateKey.pem"
    with open(publick, 'rb') as p:
        publicKey = rsa.PublicKey.load_pkcs1(p.read())
    with open(privatek, 'rb') as p:
        privateKey = rsa.PrivateKey.load_pkcs1(p.read())
    return publicKey, privateKey


publicKey, privateKey = loadKeys(nickname)
keys_list = []

firstFlagRec = 0
firstFlagW = 0

# Used to listen and receive messages from the server


def receive():

    initFlag = 0
    serverSessionFlag = 0
    while True:
        try:
            # Runs only when client wants to listen to server
            # Stops once client connects to another client
            if not stop_server.is_set():
                # Enter this if loop for initial authentication process
                if initFlag == 0:
                    message = client_server.recv(1024).decode('ascii')
                    if message == 'NICK':  # client sends username
                        client_server.send(nickname.encode('ascii'))
                    elif "NONCE" in message:  # client receives random nonce from server
                        data = message[5:]
                    elif "GETSIGN" in message:  # client signs it with their private key and sends back to server
                        encodeddata = data.encode()
                        signature = rsa.sign(encodeddata, privateKey, 'SHA-1')
                        client_server.send(signature)
                    elif "YES" in message:  # client gets confirmation from client if they are authenticated and sets flag to 1 to indicate that auth is complete
                        print("You can begin communicating.")
                        client_server.send('SHA-1thanks'.encode('ascii'))
                        initFlag = 1
                # Enter this loop for all other further communication
                elif serverSessionFlag == 0:
                    message = client_server.recv(1024)
                    # get client-server session key
                    sessionKey = rsa.decrypt(message, privateKey)

                    loc = f"client_keys/{nickname}/sessionKeyServer.txt"
                    with open(loc, "wb") as binary_file:
                        binary_file.write(sessionKey)

                    keys = generated_keys(sessionKey)
                    serverSessionFlag = 1

                else:
                    message = client_server.recv(1024)
                    # Error handling if the server can't connect the user to the host
                    if b'ERROR' in message:
                        message = message.decode('ascii')
                        if message == "SESSION ERROR: BUSY_CLIENT":
                            print("ERROR: Client is busy!")
                        elif message == "SESSION ERROR: CLIENT_NOT_FOUND":
                            print("ERROR: Client not found!")
                        elif message == "SESSION ERROR: CLIENT_NOT_HOSTING":
                            print("ERROR: Client is not hosting!")
                    # Connection handling to get session key
                    elif b'Connects' in message:
                        msg = message[10:]
                        msgblocks = msg.split(b'\:n:\n')
                        msgArr = []
                        for mblock in msgblocks:
                            msgArr.append(bytearray(mblock))
                        decrypted = decryptText(msgArr, keys[0], keys[2])
                        dc = b''.join(decrypted)

                        tmpMs = dc.split(b':\n:\n')
                        message = tmpMs[0].decode()
                        sska = tmpMs[1]
                        sskb = tmpMs[2]
                        # get client-client session key that was encrypted using client-server session key
                        cc_sessionKey = sska[5:]

                        loc = f"client_keys/{nickname}/sessionKeyClient.txt"
                        with open(loc, "wb") as binary_file:
                            binary_file.write(cc_sessionKey)

                        cc_sessionKeyB = sskb[5:]
                        loc = f"client_keys/{nickname}/sessionKeyClient2.txt"
                        with open(loc, "wb") as binary_file:
                            # Write bytes to file
                            binary_file.write(cc_sessionKeyB)
                        # Session handling if client is able to connect to the other client
                        if "SESSION: " in message:
                            address = message.split()
                            client_client.connect(
                                ('127.0.0.1', int(address[1])))
                            print("Connected to client!")
                            # Sets event so that client-server communication is halted for client-client comms
                            stop_server.set()
                            writeC_thread = threading.Thread(
                                target=client_write, args=(client_client,))
                            writeC_thread.start()

                            receiveC_thread = threading.Thread(
                                target=client_receive, args=(client_client,))
                            receiveC_thread.start()
                        else:
                            print(message)
                    else:
                        # handles !list, !help etc
                        print(message.decode('ascii'))

        except Exception as e:
            print("An error occured!")
            print('Error on line {}'.format(
                sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
            client_server.close()
            break

# Used to write messages to the server


def write():
    while True:
        # Runs only when client wants to speak to server
        # Stops once client connects to another client
        if not stop_server.is_set():
            message = f'{input("")}'
            if stop_server.is_set():
                print("Messages will now be sent to client:")
                continue
            # Allows client to start listening for session invite
            if message == "!session host":
                message += " " + str(client_client.getsockname()[1])
                stop_server.set()
                receiveC_thread = threading.Thread(
                    target=client_receive, args=(client_client, True,))
                receiveC_thread.start()
            client_server.send(message.encode('ascii'))

# Used to listen and receive messages from other clients


def client_receive(client, check=False):
    global firstFlagRec
    global firstFlagW
    run_loop = True
    # Runs if-statement if client is the host (aka listening)
    # If client is connecting, then it skips this step
    if check:
        client_client.listen(1)
        client, address = client_client.accept()
        print(f"Connected with {str(address)}")
        #message = client.recv(1024).decode('ascii')
        writeC_thread = threading.Thread(target=client_write, args=(client,))
        writeC_thread.start()
    # Runs until client stops communication to talk to the server again
    while run_loop and stop_server.is_set():
        try:
            # Initial receive handling (session key)
            if firstFlagRec == 0:
                # Fetch session key for enc/dec
                message = client.recv(1024)
                # print(message)
                l = f"client_keys/{nickname}/sessionKeyClient2.txt"
                if os.path.getsize(l) == 0:
                    loc = f"client_keys/{nickname}/sessionKeyServer.txt"
                    with open(loc, "rb") as binary_file:
                        sess = binary_file.read()
                    skeys = generated_keys(sess)

                    # decrypt the client-client session key using client-server key
                    decArr = []
                    decArr.append(bytearray(message))
                    decryptedss = decryptText(decArr, skeys[0], skeys[2])
                    loc = f"client_keys/{nickname}/sessionKeyClient.txt"
                    with open(loc, "wb") as binary_file:
                        binary_file.write(decryptedss[0])
                    firstFlagRec = 1
                    firstFlagW = 1
            else:
                loc = f"client_keys/{nickname}/sessionKeyClient.txt"
                with open(loc, "rb") as binary_file:
                    ccSessionKey = binary_file.read()

                c_keys = generated_keys(ccSessionKey)
                # Gets the ciphertext from other client
                message = client.recv(1024)  # ciphertext
                # Handling message after disconnect
                if(message == b''):
                    print("Messages will now be sent to the server:")
                    break
                # Parses ciphertext to get name and all of the blocks
                cipher = message.split(b': ')
                name = cipher[0]
                cblocks = cipher[1].split(b'\:n:\n')
                encrypted = []
                for cblock in cblocks:
                    encrypted.append(bytearray(cblock))

                # Decrypts ciphertext to get original message
                decrypted = decryptText(encrypted, c_keys[0], c_keys[2])
                dec = b''.join(decrypted).split(b':;:')
                plain_text = dec[0].decode()
                msgTimestamp = dec[1].decode()
                mh = dec[2]
                gmt = time.gmtime()
                currentTimestamp = calendar.timegm(gmt)
                isVerified = verifyMD(
                    plain_text, mh, c_keys[1])  # integrity check
                # Integrity verification
                # Makes sure message is not tampered or timestamp has expired
                if isVerified:
                    # check timestamp
                    if (currentTimestamp - int(msgTimestamp))/60 <= 2:
                        if plain_text == "!disconnect":
                            client_client.close()
                            stop_server.clear()
                            print(
                                "Disconnected from client & reconnected to server...")
                            client_server.send("!reconnect".encode("ascii"))
                            run_loop = False
                            break
                        # keep and print message if it also passes timestamp check
                        print(name.decode() + ": " + plain_text)
                    else:
                        print('Message discarded - Timestamp Expired')
                        client.close()
                else:
                    print('Message discarded - Integrity check failed')
                    client.close()
        except Exception as e:
            print("An error occured in something!")
            print('Error on line {}'.format(
                sys.exc_info()[-1].tb_lineno), type(e).__name__, e)
            client.close()
            loc = f"client_keys/{nickname}/sessionKeyClient2.txt"
            with open(loc, "r+") as file:
                file.truncate(0)
            break

# Used to send messages to the other client


def client_write(client):
    global firstFlagRec
    global firstFlagW
    # Will run until client-client communication is stopped
    while True and stop_server.is_set():
        # Initial join handling (sending session key)
        if firstFlagW == 0:
            # first message - send session key to other client
            loc = f"client_keys/{nickname}/sessionKeyClient2.txt"
            with open(loc, "rb") as binary_file:
                sess = binary_file.read()
            client.send(sess)
            firstFlagRec = 1
            firstFlagW = 1

        else:
            loc = f"client_keys/{nickname}/sessionKeyClient.txt"
            with open(loc, "rb") as binary_file:
                ccSessionKey = binary_file.read()
            c_keys = generated_keys(ccSessionKey)
            # use client-client session key for encryption
            message = f'{input("")}'  # plaintext

            # Server handling initial disconnect from client
            if (not stop_server.is_set()):
                print("Messages will now be sent to server:")
                break

            # generate hash of message for checking integrity
            messageHash = generateMD(c_keys[1], message.encode())
            gmt = time.gmtime()
            ts = calendar.timegm(gmt)
            message2 = message.encode() + b':;:' + str(ts).encode() + b':;:' + messageHash
            encrypted = encryptText(message2, c_keys[0], c_keys[2])
            client.send((nickname + ": ").encode() + b'\:n:\n'.join(encrypted))
            # Used to disconnect communication from other client and revert back to client-server comms
            if message == "!disconnect":
                stop_server.clear()
                print("Disconnected from client & reconnected to server...")
                client_server.send("!reconnect".encode("ascii"))
                break


receive_thread = threading.Thread(target=receive)
receive_thread.start()

write_thread = threading.Thread(target=write)
write_thread.start()
