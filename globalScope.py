### globals

import hashlib
import Crypto.PublicKey.RSA as RSA
from Crypto.Cipher import AES
from Crypto import Random
import ClientFile
import pickle
from Crypto.Cipher import PKCS1_OAEP


MockServer = {}
userPublicKeys = {}

dbDirectoryLoc = '/db'
fileKeysDBLoc = '/fileKeys.db'