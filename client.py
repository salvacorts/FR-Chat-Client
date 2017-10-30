from modules.trackerAPI import TrackerAPI

name = input("[+] nombre: ")

if TrackerAPI.AddUser(name):
    print("[*] Usuario Añadido")
else:
    print("[!] Error añadiendo usuario")
    exit(1)

print(TrackerAPI.GetUser(name))
