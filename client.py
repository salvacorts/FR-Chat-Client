from modules.trackerAPI import TrackerAPI
import modules.networkUtils as network

name = input("[+] nombre: ")

info = TrackerAPI.GetUser(name)
currentIP = network.GetIP()

if info == None:
    TrackerAPI.AddUser(name)
    print("[*] Usuario Añadido")
elif info["ip"] != currentIP:
    TrackerAPI.UpdateUser(name, currentIP)
    print("[*] Datos de usuario actualizados")
else:
    print("[*] Los datos estan actualizados")

info = TrackerAPI.GetUser(name)

out = """
Name: {0}
IP: {1}
Public Key:
{2}
""".format(info["name"], info["ip"], info["pubKey"])

print(out)
