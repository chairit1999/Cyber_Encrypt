from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
import os
from Crypto.Random import get_random_bytes

# create RSA keys --> public and private
def create_RSA_keys():
    #generate RSA
    key = RSA.generate(2048)

    #create pritekey
    private_key = key.export_key()
    file_out = open("RSA/private.key", "wb")
    file_out.write(private_key)
    file_out.close()

    #create public key
    public_key = key.publickey().export_key()
    file_out = open("RSA/public.key", "wb")
    file_out.write(public_key)
    file_out.close()

# create Digital_signature
def Digital_signature():
    #get message
    file_in = open("ciphertext/(enc).ciphertext.txt", "rb")
    ciphertext = file_in.read()
    file_in.close()

    #get private key
    key = RSA.import_key(open('RSA/private.key').read())
    
    #get digital signature
    hash = SHA512.new(ciphertext)
    signer=pkcs1_15.new(key)
    signature=signer.sign(hash)

    #save digital signature 
    file_sig = open("signature/signature.pem", "wb")
    file_sig.write(signature)
    file_sig.close()


# verify message
def verify_keys(filename):
    #get public key
    key = RSA.import_key(open('RSA/public.key').read())

    #get cipherText
    cipher = open(filename, "rb")
    message=cipher.read()
    cipher.close()

    #get digital signature
    sig = open("signature/signature.pem", "rb")
    signature=sig.read()
    sig.close()

    
    hash = SHA512.new(message)
    try:
        #check digital signature and hash message+public
        pkcs1_15.new(key).verify(hash, signature)
        return True
    except (ValueError, TypeError):
        return False

#encrypt 
def encrypt(key, filename):
    split = filename.split('.')
    size = 64*1024
    ciphertext = "ciphertext/(enc).ciphertext."+split[1]
    filesize = str(os.path.getsize(filename)).zfill(16)
    IV = Random.new().read(16)
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    with open(filename, 'rb') as infile:  
        with open(ciphertext, 'wb') as outfile:  
            outfile.write(filesize.encode('utf-8'))
            outfile.write(IV)
            while True:
                chunk = infile.read(size)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' '*(16-(len(chunk) % 16))
                outfile.write(encryptor.encrypt(chunk))
    split = filename.split('.')
    if(split[1] == 'txt'):
        create_RSA_keys()
        Digital_signature()
    return True

#decrypt 
def decrypt(key, filename):
    size = 64*1024
    painText = 'paintext/paintext'+filename[11:]
    split = filename.split('.')
    if split[1] == 'txt':
        if not verify_keys(filename):
            return False   
    with open(filename, 'rb') as infile:
        filesize = int(infile.read(16))
        IV = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, IV)
        with open(painText, 'wb') as outfile:
            while True:
                chunk = infile.read(size)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))
            outfile.truncate(filesize)
    return True

    #random key AES
def createAES():
    # key AES 256 bits
    key = get_random_bytes(32)
    # save AES key
    fileAES = "AES/(enc).aes.txt"
    with open(fileAES, 'wb') as f:
        f.write(key)
        f.close()
    #print("create AES ")
    return key

# get AES for decrypt
def getAES():
    file_in = open("AES/(enc).aes.txt", "rb")
    key = file_in.read()
    file_in.close()
    #print("get AES ")
    return key

def MainFunc():
    while True:
        num = int(input(" 1. Press '1' to Encrypt file.\n 2. Press '2' to Decrypt file.\n 3. Press '3' to exit.\nSelect? : "))
        if num == 1:
            filename = input("File encrypt: ")
            if(encrypt(createAES(),filename)):
                print("encrypt !!!")
        elif num == 2:
            filename = input("File decrypt: ")
            if not decrypt(getAES(),filename):
                print("cant decrypt")
                break
            print("decrypt !!!")
        elif num == 3:
            exit()
        else:
            print("select option 1, 2 or 3")

MainFunc()