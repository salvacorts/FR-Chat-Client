from modules.constants import *
from threading import Thread
import requests
import socket

KEEP_TRYING_CONN = True

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
    # DOC: https://stackoverflow.com/questions/14388706/socket-options-so-reuseaddr-and-so-reuseport-how-do-they-differ-do-they-mean-t
    # DOC: http://pubs.opengroup.org/onlinepubs/009695399/functions/setsockopt.html
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    s.bind(("", port))
    s.settimeout(5)
    s.listen(1)
    conn = None

    global KEEP_TRYING_CONN
    while conn == None or KEEP_TRYING_CONN:
        try:
            print("[+] Listening incoming conections")
            conn, addr = s.accept()
        except:
            continue

    if conn != None:
        KEEP_TRYING_CONN = False
        threads = {
            "send": Thread(target=Send, args=(s,)),
            "receive": Thread(target=Receive, args=(s,)),
        }

        LaunchAndWaitThreads(threads)


# Send messages
def Connect(addr, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    s.bind(("", port))
    success = False

    global KEEP_TRYING_CONN
    while KEEP_TRYING_CONN:
        try:
            s.connect(addr, port)
            print("[+] Connected to peer")
            KEEP_TRYING_CONN = False
            success = True
            break;
        except:
            continue

    if success:
        threads = {
            "send": Thread(target=Send, args=(s,)),
            "receive": Thread(target=Receive, args=(s,)),
        }

        LaunchAndWaitThreads(threads)


def Send(sock):
    # TODO: Close socket when finish
    while True:
        msg = input("[you]> ")
        s.send(msg)

        if msg == ".quit":  break

    s.close()


def Receive(sock):
    while True:
        msg = s.recv(1024)
        print("[peer]> {}".format(msg))

        if msg == ".quit":  break;

    s.close()


def StartPeerConnection(peerIP):
    threads = {
        "local-listen": Thread(target=Listen, args=(LISTEN_PORT,)),
        "peer-conn": Thread(target=Connect, args=(peerIP, PEER_PORT)),
    }

    LaunchAndWaitThreads(threads)
