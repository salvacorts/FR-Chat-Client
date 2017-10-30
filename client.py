from modules.trackerAPI import TrackerAPI

name = input("[+] nombre: ")

if TrackerAPI.AddUser(name):
    print("[*] Usuario Añadido")
else:
    print("[!] Error añadiendo usuario")

print(TrackerAPI.GetUser(name))

print ("\n\n[*] Probando a cambiar info")
TrackerAPI.UpdateUser(name, "192.168.1.255")
print("[*] Usuario modificado")

print(TrackerAPI.GetUser(name))
