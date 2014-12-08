### Crypto helper functions
from Crypto import Random
import Crypto.PublicKey.RSA as RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
import hashlib


def sha1HexHash(toHash):
	return hashlib.sha1(toHash).hexdigest()

def newAESEncryptionKey():
    return Random.new().read(AES.block_size)

def newInitVector(vectorSize):
    return Random.new().read(vectorSize)

def newRSAKey(rsaKeyBits):
    return RSA.generate(rsaKeyBits)

def newRSAKeyPair(rsaKeyBits, rsakey=None):
    if rsakey is None:
        rsakey = newRSAKey(rsaKeyBits)
    publicKey = rsakey.publickey().exportKey("PEM")
    privateKey = rsakey.exportKey("PEM")
    return (publicKey, privateKey)

def rsaEncryptKey(publicKey, keyToEncrypt):
    rsakey = RSA.importKey(publicKey)
    rsakey = PKCS1_OAEP.new(rsakey)
    encryptedKey = rsakey.encrypt(keyToEncrypt)
    return encryptedKey

def rsaDecryptKey(privateKey, keyToDecrypt):
    rsakey = RSA.importKey(privateKey)
    rsakey = PKCS1_OAEP.new(rsakey)
    decryptedKey = rsakey.decrypt(keyToDecrypt)
    return decryptedKey

def rsaSign(toSign, rsaKey):
    toSignHash = SHA256.new(toSign).digest()
    return rsaKey.sign(toSignHash, '')
