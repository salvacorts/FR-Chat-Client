from OpenSSL import crypto
import requests

class TrackerAPI:
    urlAdd = "http://127.0.0.1:8000/users/add/"
    urlGet = "http://127.0.0.1:8000/users/get/{0}"
    payload = {"name": None, "ip": None, "pubKey": None}

    @staticmethod
    def AddUser(name):
        ip = requests.get('http://ip.42.pl/raw').text
        keys = crypto.PKey()
        keys.generate_key(crypto.TYPE_RSA, 4096)

        TrackerAPI.payload["name"] = name
        TrackerAPI.payload["ip"] = ip
        TrackerAPI.payload["pubKey"] = crypto.dump_publickey(crypto.FILETYPE_PEM, keys)

        r = requests.post(TrackerAPI.urlAdd, data=TrackerAPI.payload)

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
