import modules.keyring as keyring
import requests

class TrackerAPI:
    urlAdd = "http://127.0.0.1:8000/users/add/"
    urlGet = "http://127.0.0.1:8000/users/get/{0}"
    urlUpdate = "http://127.0.0.1:8000/users/update/"
    urlKey = "http://127.0.0.1:8000/key"

    payloadAdd = {"name": None, "ip": None, "pubKey": None}
    payloadUpdate = {"name": None, "ip": None, "validationMSG": None}

    @staticmethod
    def AddUser(name):
        ip = requests.get('http://ip.42.pl/raw').text
        pubKey, privKey = keyring.GetKeys()

        TrackerAPI.payloadAdd["name"] = name
        TrackerAPI.payloadAdd["ip"] = ip
        TrackerAPI.payloadAdd["pubKey"] = pubKey

        r = requests.post(TrackerAPI.urlAdd, data=TrackerAPI.payloadAdd)

        if r.status_code == 201:
            return True
        else:
            return False

    @staticmethod
    def GetUser(name):
        r = requests.get(TrackerAPI.urlGet.format(name))

        if r.status_code == 200:
            return r.text
        else:
            return None

    @staticmethod
    def UpdateUser(name, ip):
        pubKey, privKey = keyring.GetKeys()
        key = requests.get(TrackerAPI.urlKey).text.replace('"', '')
        validationMSG = keyring.Sign(key, privKey)

        # print(privKey)
        # print()
        # print(pubKey)
        # print()
        # print(validationMSG)

        TrackerAPI.payloadUpdate["name"] = name
        TrackerAPI.payloadUpdate["ip"] = ip
        TrackerAPI.payloadUpdate["validationMSG"] = validationMSG

        r = requests.post(TrackerAPI.urlUpdate, TrackerAPI.payloadUpdate)
        # print(r)
        # print(r.text)

        if r.status_code == 404:
            raise Exception("Unknown User")
        elif r.status_code == 403:
            raise Exception("Invalid Credentials")
        elif r.status_code != 202:
            raise Exception("Unknown error")
