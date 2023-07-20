import hmac
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

###################### ENCRYPT/DECRYPT/INTEGRITY ###################################
# Method to generate a hashed message digest
def generateMD(key, val):
	hmac1 = hmac.new(key=key, msg=val, digestmod = hashlib.sha256)
	message_digest = hmac1.digest()
	#print("{} - Message Digest 1 : {}".format(hmac1.name, message_digest))
	return message_digest

def verifyMD(rec_msg, rec_md, k):
    hm = hmac.new(key=k, msg=rec_msg.encode(), digestmod = hashlib.sha256)
    md = hm.digest()
    #print(md)
    if md == rec_md:
        isValid = True
        #print("Verified")
    else:
        isValid = False        
        #print("Wrong")
    return isValid    
 
# Method to split plain text into MD-length blocks
def split_str(plaintext, block_size):
    lst = []
    skip_tail=False
    if block_size <= len(plaintext):
        lst.extend([plaintext[:block_size]])
        lst.extend(split_str(plaintext[block_size:], block_size))
    elif not skip_tail and plaintext:
        str = [plaintext][0]
        lst.extend([str]) #if no padding uncomment
    return lst 

# Method to calculate bitwise xor
def bitwise_xor(text, key):
    return bytearray([ text[i] ^ key[i] for i in range(len(text))])
   
# Method to encrypt the given plain text using cfb    
def encryptText(plain_text, kAB, iv ):	
    b1 = generateMD(kAB, iv) 
    textSplit = split_str(plain_text, len(b1) )
    cipherblocks = []
    idx = 0
    for ptblock in textSplit:
        if idx == 0 : 
            bt = b1
        else:
            bt = generateMD(kAB, cipherblocks[idx-1] )
        idx = idx + 1
        cipherblocks.append( bitwise_xor(ptblock, bt) )
    return (cipherblocks)

# Method to decrypt cipher text using cfb
def decryptText(cipherblocks, kAB, iv ):
    ptblocks = []
    idx = len(cipherblocks) - 1
    for ctblock in reversed(cipherblocks):
        if idx == 0 : 
            bt = generateMD(kAB, iv) 
        else:
            bt = generateMD(kAB, cipherblocks[idx-1] )
        idx = idx - 1
        ptblocks.append( bitwise_xor(ctblock, bt) )   
        plainText = ptblocks[::-1]
    return plainText       

################################# SESSION KEY FUNCTIONS #####################################
def genKeys(info):
    hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=info
    )
    return hkdf

#generate keys for encryption, integrity, and an initialization vector from session key on both sides
def generated_keys(sessionKey):
    e = "encryptionKey".encode()
    i = "integrityKey".encode()
    iv = "initvector".encode()
    
    ekey = genKeys(e).derive(sessionKey)
    ikey = genKeys(i).derive(sessionKey)
    ivkey = genKeys(iv).derive(sessionKey)

    keys_list = [ekey, ikey, ivkey]
    return keys_list
