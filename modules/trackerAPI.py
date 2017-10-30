import modules.networkUtils as network
import modules.keyring as keyring
import requests, json

class TrackerAPI:
    baseUrl="https://fr-ugr-rest.herokuapp.com"
    urlAdd = baseUrl+"/users/add/"
    urlGet = baseUrl+"/users/get/{0}"
    urlUpdate = baseUrl+"/users/update/"
    urlKey = baseUrl+"/key"

    payloadAdd = {"name": None, "ip": None, "pubKey": None}
    payloadUpdate = {"name": None, "ip": None, "validationMSG": None}

    @staticmethod
    def AddUser(name):
        ip = network.GetIP()
        pubKey, privKey = keyring.GetKeys()

        TrackerAPI.payloadAdd["name"] = name
        TrackerAPI.payloadAdd["ip"] = ip
        TrackerAPI.payloadAdd["pubKey"] = pubKey

        r = requests.post(TrackerAPI.urlAdd, data=TrackerAPI.payloadAdd)

        if r.status_code == 409:
            raise Exception("User already exists")

    @staticmethod
    def GetUser(name):
        r = requests.get(TrackerAPI.urlGet.format(name))

        if r.status_code == 200:
            return json.loads(r.text)
        else:
            return None

    @staticmethod
    def UpdateUser(name, ip):
        pubKey, privKey = keyring.GetKeys()
        key = requests.get(TrackerAPI.urlKey).text.replace('"', '')
        validationMSG = keyring.Sign(key, privKey)

        TrackerAPI.payloadUpdate["name"] = name
        TrackerAPI.payloadUpdate["ip"] = ip
        TrackerAPI.payloadUpdate["validationMSG"] = validationMSG

        r = requests.post(TrackerAPI.urlUpdate, TrackerAPI.payloadUpdate)

        if r.status_code == 404:
            raise Exception("Unknown User")
        elif r.status_code == 403:
            raise Exception("Invalid Credentials")
        elif r.status_code != 202:
            raise Exception("Unknown error")
