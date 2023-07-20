#CS 6349.001 F22- Instant Messaging System

#Submitted By-
#Amogh Yatnatti - ary180001
#Avani Gumudavelli - axg200002
#Manasi Gosavi - mvg200001
#Shatavari Shinde - svs210001

Steps to run the IM:
1) Pre-requisites:
	pip install rsa
	pip install cryptography
2) Navigate to the location of the files.
3) On one terminal window, run the following command to start the server:
	python server.py
4) Then for each client you wish to connect, run the following on new terminal windows: 
	python client.py
5) When prompted for usernames: Choose any from A,B,C,D,E,F
6) Helpful commands:
	- To make yourself available for connection: !session host
	- To start communicating with a client: !session [Username of client you wish to talk to]
	- To view a list of online clients and their statuses: !list
	- To disconnect from a client and reconnect back to the server: !disconnect


Libraries used:
socket
threading
security
rsa
secrets
hmac
hashlib
cryptography

All libraries are in-built python libraries.
