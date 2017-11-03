#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from modules.trackerAPI import TrackerAPI
import modules.exceptions as exceptions
import modules.networkUtils as network

def UpdateUserInfo(name, t=3):
    info = TrackerAPI.GetUser(name)
    currentIP = network.GetLocalIP()

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


def main():
    userName = input("[+] Tu Nombre: ")
    peerName = input("[+] Nombre del amigo: ")

    UserInfo = UpdateUserInfo(userName)


    PeerInfo = TrackerAPI.GetUser(peerName)

    if PeerInfo == None:
        print("[!] El nombre de tu amigo no existe")
        exit(1)


    print("""
    Name: {0}
    IP: {1}
    Public Key:
    {2}
    """.format(UserInfo["name"], UserInfo["ip"], UserInfo["pubKey"]))

    print("""\n\n
    Name: {0}
    IP: {1}
    Public Key:
    {2}
    """.format(PeerInfo["name"], PeerInfo["ip"], PeerInfo["pubKey"]))

    network.StartPeerConnection(PeerInfo["ip"])


if __name__ == '__main__':
    main()
