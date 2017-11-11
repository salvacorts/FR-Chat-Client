import modules.keyring as keyring
import modules.constants as const
from threading import Thread
from threading import Lock
import miniupnpc
import requests
import socket
import queue
import time


KEEP_TRYING_CONN = True
mutexListen = Lock()

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


def Listen(port, returns):
    """Listen for incomming Connections.

    Bin a socket to localhost and incoming port.
    socket.SO_REUSEADDR and socket.SO_REUSEPORT are used in order to be able
    to bind to an already binded address:port

    When a connection is stablished; it will retyrun the socket
    if a connection is received

    Args:
        port: Port to bind on localhost
        returns: Queue to put returns on (Threading)

    Returns
        See argument returns
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
        returns.put(conn)  # Add Socket to the resturns queue
        s.close()


def Connect(peerAddr, peerPort, localPort, returns):
    """Try to connect to remote host.

    Bin a socket to localhost and incoming port.
    socket.SO_REUSEADDR and socket.SO_REUSEPORT are used in order to be able
    to bind to an already binded address:port

    When a connection is stablished; it will return the socket.

    Args:
        peerAddr: Remote address to try to connect with.
        peerPort: Port to connect to
        localPort: Port to bind on localhost
        returns: Queue to put returns on (Threading)

    Returns
        See argument returns
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    s.bind((GetLocalIP(), localPort))
    success = False

    global KEEP_TRYING_CONN
    global mutexListen

    print("[*] Connecting to peer")
    while KEEP_TRYING_CONN:
        try:
            s.connect((peerAddr, peerPort))
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
        print("[+] Connected")
        returns.put(s)  # Add Socket to the resturns queue


def Send(sock, peerPubKey, msg):
    """Send messagges to socket from user input.

    It will send user input until ".quit" is written

    Args:
        sock: Socket to send messages to.
        peerPubKey: Peer Public key to encrypt with
        msg: message to be encrypted and sent
    """

    msgEnc = keyring.EncryptAsimetric(msg, peerPubKey)
    sock.send(msgEnc)


def Receive(sock):
    """Receive message from socket and decrypt it

    It will receive a messages from the socket and decript it
    with your private key

    Args:
        sock: Socket to receive messages from.

    Returns:
        A string containing the plain text message received
    """
    pubKey, privKey = keyring.GetKeys()
    msgEnc = sock.recv(1024)
    msgPlain = keyring.DecryptAsimetric(msgEnc, privKey)

    return msgPlain


def EndConnections(socks):
    for s in socks:
        s.close()


def LaunchUPnP(port, remoteIP):
    """Open ports on router to receive connections.

    It will launch IGD service (based on UPnP).
    http://miniupnp.free.fr/nat-pmp.html

    Args:
        port: Port to open on router and to listen on localhost
        peerIP: Peer IP address to accept connections from
    """
    upnp = miniupnpc.UPnP()
    upnp.discoverdelay = 10
    upnp.discover()
    upnp.selectigd()  # Use IGD (Internet Gateway Device)

    # Args: external_port, protocol, internal_host, internal_port, description, remote_host
    upnp.addportmapping(port, "TCP", GetLocalIP(), port, "Chat P2P", remoteIP)


def StartPeerConnection(peerIP, peerPort, peerPubKey):
    """Start chat connection with peer.

    It will use TCP Hole Punching Technique

    Args:
        peerIP: Remote Peer IP address.
    """

    # Start UPnP
    try:
        LaunchUPnP(const.LISTEN_PORT, peerIP)
        print("[*] UPnP Service launched")
    except Exception:
        print("[!] Quizas tengas que configurar Port Forwarding en el router")

    # Queue to store threads returns
    threads_returns = queue.Queue()

    # Threads to be launched
    threads = {
        "local-listen": Thread(target=Listen, args=(const.LISTEN_PORT, threads_returns,)),
        "peer-conn": Thread(target=Connect, args=(peerIP, peerPort, const.LISTEN_PORT, threads_returns,)),
    }

    # Start threads
    for threadKey in threads.keys():
        threads[threadKey].start()

    # Wait threads to finish
    for threadKey in threads.keys():
        threads[threadKey].join(1)  # Timeout to one

    # Retrive threads returns and return them
    sockets = []
    for thread in threads:
        sockets.append(threads_returns.get())

    return sockets
