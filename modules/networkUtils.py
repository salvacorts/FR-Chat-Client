from modules.constants import *
from threading import Thread
import requests
import socket

# TODO: añadir TCP Hole Putching o si se pasa de dificil, UPnP

def GetPublicIP():
    return requests.get('https://ip.42.pl/raw').text

def GetLocalIP():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()

    return ip


def Listen(port):
    s = socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    s.bind(("", port))
    s.listen(1)

    while True:
        try:
            conn, addr = s.accept()
            print("[+] Listening incoming conections")
        except:
            continue


def Connect(localAddr, PeerAddr):
    s = socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    s.bind((localAddr, LOCAL_PORT))

    while True:
        try:
            s.connect(PeerAddr, PEER_PORT)
            print("[+] Conncted to peer")
        except:
            continue

def Start(peerLocalIP, peerPublicIP):
    localIP = socket.gethostname(socket.gethostname())

    threads = {
        'local_accept': Thread(target=Listen, args=(LOCAL_PORT,)),
        'public_accept': Thread(target=Listen, args=(PEER_PORT,)),
        'local_connect': Thread(target=Connect, args=(localIP, peerPublicIP,)),
        'public_connect': Thread(target=Connect, args=(localIP, peerLocalIP,))
    }

    for threadKey in threads.keys():
        threads[threadKey].start()

    while threads:
        for threadKey in threads.keys():
            threads[threadKey].join(1)
