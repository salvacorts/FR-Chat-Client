from modules.trackerAPI import TrackerAPI
import modules.exceptions as exceptions
import modules.networkUtils as network

def UpdateUserInfo(name, t=3):
    info = TrackerAPI.GetUser(name)
    currentIP = network.GetIP()

    try:
        if info == None:
            TrackerAPI.AddUser(name)
            print("[*] Usuario Añadido")
        elif info["ip"] != currentIP:
            TrackerAPI.UpdateUser(name, currentIP)
            print("[*] Datos de usuario actualizados")
        else:
            print("[*] Los datos estan actualizados")
            return info # NOTE: Para no volver a llamar al servidor
    except exceptions.DuplicatedUser:
        print("[!] El usuario ya existe")
    except exceptions.UnknownUser:
        print("[!] Usurio desconocido")
    except exceptions.InvalidCredentials:
        print("[!] Credenciales invalidas")
    except:
        print("[!] Error desconocido... Intentando nuevamente")
        if t >= 0: UpdateUserInfo(name, --t)


    return TrackerAPI.GetUser(name)

name = input("[+] Nombre: ")

info = UpdateUserInfo(name)

out = """
Name: {0}
IP: {1}
Public Key:
{2}
""".format(info["name"], info["ip"], info["pubKey"])

print(out)
