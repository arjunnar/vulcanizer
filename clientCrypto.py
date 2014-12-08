### Crypto helper functions

import Crypto.PublicKey.RSA as RSA

def newRSAKeyPair(rsaKeyBits, rsakey=None):
    if rsakey is None:
        rsakey = newRSAKey(rsaKeyBits)
    publicKey = rsakey.publickey().exportKey("PEM")
    privateKey = rsakey.exportKey("PEM")
    return (publicKey, privateKey)

def newRSAKey(rsaKeyBits):
    return RSA.generate(rsaKeyBits)