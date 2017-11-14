import modules.exceptions as exceptions
import modules.networkUtils as network
import modules.constants as const
import modules.keyring as keyring
import requests
import json

class TrackerAPI:
    """Tracker API comunication class.

    It let you interact with the REST Server in order to retrieve
    infromation about your user and the peer you want to connect with

    Attributes:
        baseUrl: Rest server base URL
        urlAdd: URL to add user
        urlGet: URL to retrieve users info
        urlUpdate: URL to update user information
        urlKey: URL that returns the the key to sign with on authentication
        payloadAdd: payload to use on urlAdd with POST method
        payloadUpdate: payload to use on urlUpdate with POST method
    """
    baseUrl = "https://fr-ugr-rest.herokuapp.com"
    urlAdd = baseUrl + "/users/add/"
    urlGet = baseUrl + "/users/get/{0}"
    urlUpdate = baseUrl + "/users/update/"
    urlKey = baseUrl + "/key"

    payloadAdd = {"name": None, "ip": None, "port": None, "pubKey": None}
    payloadUpdate = {"name": None, "ip": None, "port": None, "validationMSG": None}

    @staticmethod
    def AddUser(name):
        """Add user to the tracker server.

        It will perform a POST message over http on the rest server adding
        the user name alongside with its IP, its Listening port and
        RSA Public key.

        Args:
            name: user name

        Raises:
            DuplicatedUser: User already exists on the server.
                            You must use UpdateUser function instead
        """
        ip = network.GetPublicIP()
        pubKey, privKey = keyring.GetKeys()

        TrackerAPI.payloadAdd["name"] = name
        TrackerAPI.payloadAdd["ip"] = ip
        TrackerAPI.payloadAdd["port"] = const.LISTEN_PORT
        TrackerAPI.payloadAdd["pubKey"] = pubKey

        r = requests.post(TrackerAPI.urlAdd, data=TrackerAPI.payloadAdd)

        if r.status_code == 409:
            raise exceptions.DuplicatedUser("User already exists")

    @staticmethod
    def GetUser(name):
        """Get user info from the server.

        It will perform a GET message over http on the rest server retriving
        the user name alongside with its IP, its Listening port and
        RSA Public key for the user identified by "name".

        Args:
            name: user name of the user to get information about

        Returns:
            Disctionary with its user name ("name"), IP address ("ip"),
            listening port number ("port") and its public rsa key ("pubKey")
        """
        r = requests.get(TrackerAPI.urlGet.format(name))

        if r.status_code == 200:
            return json.loads(r.text)
        else:
            return None

    @staticmethod
    def UpdateUser(name, ip):
        """Update user information on the server.

        It will perform a POST message over http on the rest server updating
        the IP address "ip", its Listening port and
        RSA Public key for the user identified by "name".

        To update its information, it will send a validation message
        wich is signed with your private key and will be validated
        on the server with your last public key

        Args:
            name: user name

        Raises:
            UnknownUser: The user "name" doesnt exists
            InvalidCredentials: Your signature is not valid,
                                you cant update information
            Exception: An unexpected error has occured
        """
        pubKey, privKey = keyring.GetKeys()
        key = requests.get(TrackerAPI.urlKey).text.replace('"', '')
        validationMSG = keyring.Sign(key, privKey)

        TrackerAPI.payloadUpdate["name"] = name
        TrackerAPI.payloadUpdate["ip"] = ip
        TrackerAPI.payloadUpdate["port"] = const.LISTEN_PORT
        TrackerAPI.payloadUpdate["validationMSG"] = validationMSG

        r = requests.post(TrackerAPI.urlUpdate, TrackerAPI.payloadUpdate)

        if r.status_code == 404:
            raise exceptions.UnknownUser("Unknown User")
        elif r.status_code == 403:
            raise exceptions.InvalidCredentials("Invalid Credentials")
        elif r.status_code != 202:
            raise Exception("Unknown error")
