import modules.keyring as keyring
import modules.constants as const
from threading import Thread
import requests
import socket
import time


KEEP_TRYING_CONN = True


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

    return ip

def LaunchAndWaitThreads(threads):
    """Launch and wait for given threads to finish.
    """
    for threadKey in threads.keys():
        threads[threadKey].start()

    while threads:
        for threadKey in threads.keys():
            threads[threadKey].join(1)


def Listen(port):
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

    global KEEP_TRYING_CONN
    while conn is None and KEEP_TRYING_CONN:
        try:
            print("[*] Listening incoming conections")
            conn, addr = s.accept()
            print("[+] Connection received")
        except:
            continue

    if conn is None:
        print("[+] Connected to peer")
        KEEP_TRYING_CONN = False

        # TODO: AQUI DEBE IR El intercambio de claves
        # simKeyCiphered = s.recv(1024)
        # pubKey, privKey = GetKeys()
        # simKey = DecryptAsimetric(simKeyCiphered, PrivKey)
        # NOTE: Pasar simKey a Send() y Receive() como argumento en las hebras
        threads = {
            "send": Thread(target=Send, args=(conn,)),
            "receive": Thread(target=Receive, args=(conn,)),
        }

        LaunchAndWaitThreads(threads)

    s.close()


def Connect(peerAddr, peerPort, localPort):
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
    while KEEP_TRYING_CONN:
        try:
            print("[*] Connecting to peer")
            key
            s.connect(peerAddr, peerPort)
            print("[+] Connected!")
            KEEP_TRYING_CONN = False
            success = True
            break
        except:
            time.sleep(0.5)  # Avoid High CPU usage
            continue

    if success:
        # TODO: AQUI DEBE IR El intercambio de claves
        # simKey = GenRandKey()
        # msgExchange = EncryptAsimetric(simKey, peerPubKey)
        # s.sendall(msgExchange)
        # NOTE: Pasar simKey a Send() y Receive() como argumento en las hebras
        threads = {
            "send": Thread(target=Send, args=(s,)),
            "receive": Thread(target=Receive, args=(s,)),
        }

        LaunchAndWaitThreads(threads)

    s.close()


def Send(sock):
    """Send messagges to socket from user input.

    It will send user input until ".quit" is written

    Args:
        sock: Socket to send messages to.
    """
    while True:
        msg = input("[you]> ")
        sock.send(msg.encode("utf-8"))

        if msg == ".quit":  break

    sock.close()


def Receive(sock):
    """Receive messages from socket and print them.

    It will be receiving messages until a ".quit" is received

    Args:
        sock: Socket to receive messages from.
    """
    while True:
        msg = sock.recv(1024).decode("utf-8")
        print("[peer]> {}".format(msg))

        if msg == ".quit":  break;

    sock.close()


def StartPeerConnection(peerIP):
    """Start chat connection with peer.

    It will use TCP Hole Punching Technique

    Args:
        peerIP: Remote Peer IP address.
    """
    threads = {
        "local-listen": Thread(target=Listen, args=(const.LISTEN_PORT,)),
        "peer-conn": Thread(target=Connect, args=(peerIP, const.PEER_PORT, const.LISTEN_PORT,)),
    }

    LaunchAndWaitThreads(threads)
