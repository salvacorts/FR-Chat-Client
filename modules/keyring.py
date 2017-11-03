from Crypto.Signature import PKCS1_PSS
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA
from modules.constants import *
import base64
import os

def ResetKeys():
    """Generate RSA Public and Private keys.

    Generate public and private keys and write them to public.key
    and private.key files.
    """
    private = RSA.generate(2048)
    public = private.publickey()

    keysPath = "/".join(PUBLIC_FILE.split("/")[0:-1])

    if not os.path.exists(keysPath): os.makedirs(keysPath)

    pubFile = open(PUBLIC_FILE, "wb")
    privFile = open(PRIVATE_FILE, "wb")

    pubFile.write(public.exportKey())
    privFile.write(private.exportKey())

def GetKeys():
    """Returns RSA Public and Private keys.

    Read public and private keys from .key files. If them
    doesnt exists; This function will call ResetKeys() in order
    to create them.

    Returns:
        publicKey: String with RSA Public key
        privateKey: String with RSA Private key

    """
    if not os.path.exists(PUBLIC_FILE) or not os.path.exists(PRIVATE_FILE):
        ResetKeys()

    pubFile = open(PUBLIC_FILE, "r")
    privFile = open(PRIVATE_FILE, "r")

    private = RSA.importKey(privFile.read())
    public = private.publickey()

    return public.exportKey().decode("utf-8"), private.exportKey().decode("utf-8")


def Sign(msg, privKey):
    """Sign a message.

    Sing a message using RSA and SHA and return sign encoded on Base 64

    Args:
        msg: String with the plaintext message.
        privKey: String with the RSA Public Key.

    Returns:
        A string containing base64 encoded sign
    """
    rsaKey = RSA.importKey(privKey)
    h = SHA.new()
    h.update(msg.encode("utf-8"))

    signer = PKCS1_PSS.new(rsaKey)
    signature = signer.sign(h)

    return base64.b64encode(signature)


def EncryptAsimetric(msg, pubKey):
    """Returns encrypted msg.

    Encrypt msg with Public Key using RSA

    Args:
        msg: String with the plaintext message.
        pubKey: String with the RSA Public Key.

    Returns:
        A string containing encrypted message
    """
    rsaKey = RSA.importKey(privKey)
    encryptedMsg = rsaKey.encrypt(msg)

    return encryptedMsg


def DecryptAsimetric(msg, privKey):
    """Returns decrypted msg.

    Decrypt message with Private Key using RSA

    Args:
        msg: String with the encrypted message.
        privKey: String with the RSA Private Key.

    Returns:
        A string containing plaintext decrypted message
    """
    rsaKey = RSA.importKey(privKey);
    plainText = rsaKey.decrypt(msg)

    return plainText


def EncryptSimetric(msg, key):
    """Returns encrypted msg.

    Encrypt msg with key using AES-128

    Args:
        msg: String with the plaintext message.
        key: String with the passphrase to encrypt msg.

    Returns:
        A string containing encrypted message
    """
    cif = AES.new(key, 16)  # Use AES-128 with key
    encryptedMsg = cif.encrypt(msg)

    return encryptedMsg


def DecryptSimetric(msg, key):
    """Returns decrypted msg.

    Decrypt msg with key using AES-128

    Args:
        msg: String with the encrypted message.
        key: String with the passphrase to decrypt msg.

    Returns:
        A string containing plaintext decrypted message
    """
    cif = AES.new(key, 16)  # Use AES-128 with key
    plainText = cif.decrypt(msg)

    return plainText
