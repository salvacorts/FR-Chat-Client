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


def LaunchAndWaitThreads(threads):
    for threadKey in threads.keys():
        threads[threadKey].start()

    while threads:
        for threadKey in threads.keys():
            threads[threadKey].join(1)

# Print Incomming messages
def Listen(port):
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


# Send messages
def Connect(addr, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    while True:
        try:
            s.connect(addr, port)
            print("[+] Connected to peer")
            break;
        except:
            continue

    threads = {
        "send": Thread(target=Send, args=(s,)),
        "receive": Thread(target=Receive, args=(s,)),
    }

    LaunchAndWaitThreads(threads)
    

def Send(sock):
    while True:
        msg = input("[you]> ")
        s.send(msg)


def Receive(sock):
    while True:
        print("[peer]> {}".format(s.recv(1024)))


def StartPeerConnection(peerIP):
    threads = {
        "local-listen": Thread(target=Listen, args=(LISTEN_PORT,)),
        "peer-conn": Thread(target=Connect, args=(peerIP, PEER_PORT)),
    }

    LaunchAndWaitThreads(threads)
