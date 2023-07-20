import rsa

def generateKeys():
  (publicKey, privateKey) = rsa.newkeys(1024)
  var = "F"
  publick = f"client_keys/{var}/publicKey.pem"
  privatek = f"client_keys/{var}/privateKey.pem"
  with open(publick, 'wb') as p:
       p.write(publicKey.save_pkcs1('PEM'))
  with open(privatek, 'wb') as p:
       p.write(privateKey.save_pkcs1('PEM'))

generateKeys()
