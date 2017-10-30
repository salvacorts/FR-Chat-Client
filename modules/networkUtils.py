import requests

def GetIP():
    return requests.get('https://ip.42.pl/raw').text
