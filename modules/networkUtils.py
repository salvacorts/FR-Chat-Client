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


# Print Incomming messages
def Incoming(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

    s.bind(("", port))
    s.settimeout(5)
    s.listen(1)
    conn = None

    while conn == None:
        try:
            print("[+] Listening incoming conections")
            conn, addr = s.accept()
        except:
            continue

    while True:
        print("[peer]> {}".format(s.recv(1024)))


# Send messages
def Outgoing(addr, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    while True:
        try:
            s.connect(addr, port)
            print("[+] Connected to peer")
            break;
        except:
            continue

    while True:
        msg = input("[you]> ")
        s.send(msg)

def StartPeerConnection(peerIP):
    threads = {
        "local-incoming": Thread(target=Incoming, args=(INCOMING_PORT,)),
        "local-outgoing": Thread(target=Incoming, args=(OUTGOING_PORT,)),
        "peer-incoming": Thread(target=Outgoing, args=(peerIP, INCOMING_PORT_PEER)),
        "peer-outgoing": Thread(target=Outgoing, args=(peerIP, OUTGOING_PORT_PEER))
    }

    for threadKey in threads.keys():
        threads[threadKey].start()

    while threads:
        for threadKey in threads.keys():
            threads[threadKey].join(1)
