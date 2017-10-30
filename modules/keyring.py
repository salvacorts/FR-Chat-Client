from Crypto.Signature import PKCS1_PSS
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
import base64
import os

PUBLIC_FILE = "keys/public.key"
PRIVATE_FILE = "keys/private.key"

def ResetKeys():
    private = RSA.generate(1024)
    public = private.publickey()

    pubFile = open(PUBLIC_FILE, "wb")
    privFile = open(PRIVATE_FILE, "wb")

    pubFile.write(public.exportKey())
    privFile.write(private.exportKey())

def GetKeys():

    if not os.path.exists(PUBLIC_FILE) or not os.path.exists(PRIVATE_FILE):
        ResetKeys()

    pubFile = open(PUBLIC_FILE, "r")
    privFile = open(PRIVATE_FILE, "r")

    private = RSA.importKey(privFile.read())
    public = private.publickey()

    return public.exportKey().decode("utf-8"), private.exportKey().decode("utf-8")


def Sign(msg, privKey):
    rsaKey = RSA.importKey(privKey)
    h = SHA.new()
    h.update(msg.encode("utf-8"))

    signer = PKCS1_PSS.new(rsaKey)
    signature = signer.sign(h)

    return base64.b64encode(signature)


# def ValidCredentials(currentPubKey, signature):
#     signature = base64.b64decode(signature);
#     print (currentPubKey)
#     print(signature)
#
#     rsaKey = RSA.importKey(currentPubKey)
#     h = SHA.new()
#     h.update("abracadabra".encode("utf-8"))
#     verifier = PKCS1_PSS.new(rsaKey)
#
#     return verifier.verify(h, signature)
#
# pub, priv = GetKeys()
# signature = Sign("abracadabra", priv)
# print(ValidCredentials(pub, signature))
