import modules.keyring as keyring
import modules.constants as const
from threading import Thread
from threading import Lock
import requests
import socket
import time


KEEP_TRYING_CONN = True
SIMETRIC_KEY = None
mutexListen = Lock()
mutexKeys = Lock()


def GetPublicIP():
    """Give Public IP.

    Retrieves Public IP from https://ip.42.pl/raw

    Returns:
        A string containing your public IP
    """
    return requests.get('https://ip.42.pl/raw').text


def GetLocalIP():
    """Give Public IP.

    Retrieves Local IP generationg a conexion socket and seeinf it information

    Returns:
        A string containing your Local IP. For example:

        192.168.1.7
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()

    # return ip
    return "192.168.56.1"


def LaunchAndWaitThreads(threads):
    """Launch and wait for given threads to finish.
    """
    for threadKey in threads.keys():
        threads[threadKey].start()

    while threads:
        for threadKey in threads.keys():
            threads[threadKey].join(1)


def Listen(port, peerPubKey):
    """Listen for incomming Connections.

    Bin a socket to localhost and incoming port.
    socket.SO_REUSEADDR and socket.SO_REUSEPORT are used in order to be able
    to bind to an already binded address:port

    When a connection is stablished; it will launch threads to interact with it
    """
    # DOC: https://stackoverflow.com/questions/14388706/socket-options-so-reuseaddr-and-so-reuseport-how-do-they-differ-do-they-mean-t
    # DOC: http://pubs.opengroup.org/onlinepubs/009695399/functions/setsockopt.html
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    s.bind((GetLocalIP(), port))
    s.settimeout(5)  # Avoid high CPU usage
    s.listen(1)
    conn = None
    success = False

    global KEEP_TRYING_CONN
    global mutexListen

    while conn is None and KEEP_TRYING_CONN:
        try:
            print("[*] Listening incoming conections")
            conn, addr = s.accept()
        except socket.timeout:
            continue
        except Exception as e:
            print("ERROR: {0}".format(e.message))
        finally:
            mutexListen.acquire()
            if conn is not None and KEEP_TRYING_CONN:
                KEEP_TRYING_CONN = False
                success = True
            mutexListen.release()

    if success:
        print("[+] Connection received")
        s.settimeout(0)

        threads = {
            "send": Thread(target=Send, args=(conn, peerPubKey,)),
            "receive": Thread(target=Receive, args=(conn,)),
        }

        LaunchAndWaitThreads(threads)

    s.close()


def Connect(peerAddr, peerPort, localPort, peerPubKey):
    """Try to connect to remote host.

    Bin a socket to localhost and incoming port.
    socket.SO_REUSEADDR and socket.SO_REUSEPORT are used in order to be able
    to bind to an already binded address:port

    When a connection is stablished; it will launch threads to interact with it

    Args:
        peerAddr: Remote address to try to connect with.
        peerPort: Port to connect to
        localPort: Port to bind on localhost
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    s.bind((GetLocalIP(), localPort))
    success = False

    global KEEP_TRYING_CONN
    global mutexListen

    while KEEP_TRYING_CONN:
        try:
            print("[*] Connecting to peer")
            s.connect((peerAddr, peerPort))
            KEEP_TRYING_CONN = False
            success = True
            break
        except socket.error:
            time.sleep(0.5)  # Avoid High CPU usage
            continue
        except Exception as e:
            print("ERROR: {0}".format(e.message))
        finally:
            mutexListen.acquire()
            if success and KEEP_TRYING_CONN:
                KEEP_TRYING_CONN = False
                success = True
            mutexListen.release()

    if success:
        print("[+] Connected!")

        threads = {
            "send": Thread(target=Send, args=(s, peerPubKey,)),
            "receive": Thread(target=Receive, args=(s,)),
        }

        LaunchAndWaitThreads(threads)

    s.close()


def Send(sock, peerPubKey):
    """Send messagges to socket from user input.

    It will send user input until ".quit" is written

    Args:
        sock: Socket to send messages to.
    """
    global SIMETRIC_KEY
    global mutexKeys

    # (Send key) Simetric key exchange with asimetric encryption
    mutexKeys.acquire()
    if SIMETRIC_KEY is None:
        SIMETRIC_KEY = keyring.GenRandKey()
        simKeyEncrypted = keyring.EncryptAsimetric(SIMETRIC_KEY, peerPubKey)
        sock.sendall(simKeyEncrypted)
    mutexKeys.release()

    while True:
        print(SIMETRIC_KEY)
        msgPlain = input("[you]> ")
        msgEnc = keyring.EncryptSimetric(msgPlain, SIMETRIC_KEY)
        sock.send(msgEnc)

        if msgPlain == ".quit":
            break

    sock.close()


def Receive(sock):
    """Receive messages from socket and print them.

    It will be receiving messages until a ".quit" is received

    Args:
        sock: Socket to receive messages from.
    """
    global SIMETRIC_KEY
    global mutexKeys

    # (Receive key) Simetric key exchange with asimetric encryption
    simKeyCiphered = sock.recv(1024)
    pubKey, privKey = keyring.GetKeys()
    mutexKeys.acquire()
    if SIMETRIC_KEY is None:
        SIMETRIC_KEY = keyring.DecryptAsimetric(simKeyCiphered, privKey)
    mutexKeys.release()

    while True:
        print(SIMETRIC_KEY)
        msgEnc = sock.recv(1024)
        msgPlain = keyring.DecryptSimetric(msgEnc, SIMETRIC_KEY)
        print("[peer]> {}".format(msgPlain))

        if msgPlain == ".quit":
            break

    sock.close()


def StartPeerConnection(peerIP, peerPubKey):
    """Start chat connection with peer.

    It will use TCP Hole Punching Technique

    Args:
        peerIP: Remote Peer IP address.
    """

    threads = {
        "local-listen": Thread(target=Listen, args=(const.LISTEN_PORT, peerPubKey)),
        "peer-conn": Thread(target=Connect, args=(peerIP, const.PEER_PORT, const.LISTEN_PORT, peerPubKey)),
    }

    LaunchAndWaitThreads(threads)
