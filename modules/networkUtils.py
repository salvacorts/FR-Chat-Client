import requests

def GetIP():
    return requests.get('http://ip.42.pl/raw').text
