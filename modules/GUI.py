#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A Graphic User Interface for chat client"""

from tkinter import *
from tkinter import ttk, font
from threading import Thread
from modules.trackerAPI import TrackerAPI
import modules.networkUtils as network


#Function that center a window on the screen:
def center_window(window, width, height):
    # get screen width and height
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()

    # calculate position x and y coordinates
    x = (screen_width/2) - (width/2)
    y = (screen_height/2) - (height/2)
    window.geometry('%dx%d+%d+%d' % (width, height, x, y))


#Required function:
def UpdateUserInfo(name, t=3):
    info = TrackerAPI.GetUser(name)
    currentIP = network.GetPublicIP()

    try:
        if info is None:
            TrackerAPI.AddUser(name)
            print("[*] Usuario Añadido")
        elif info["ip"] != currentIP:
            TrackerAPI.UpdateUser(name, currentIP)
            print("[*] Datos de usuario actualizados")
        else:
            print("[*] Los datos estan actualizados")
            return info  # NOTE: Para no volver a llamar al servidor
    except exceptions.DuplicatedUser:
        print("[!] El usuario ya existe")
    except exceptions.UnknownUser:
        print("[!] Usurio desconocido")
    except exceptions.InvalidCredentials:
        print("[!] Credenciales invalidas")
    except Exception as e:
        print("[!] Error: {}".format(e.message))

        if t >= 0:
            UpdateUserInfo(name, --t)

    return TrackerAPI.GetUser(name)


class GUI:
    #Create main window
    def __init__(self):
        self.mainChat = Tk()

        #Basic propierties
        self.mainChat.geometry('500x450')
        center_window(self.mainChat, 500, 450)
        self.mainChat.title("Lmao-Chat Desktop")
        self.mainChat.lift()
        #Not resizable:
        self.mainChat.resizable(0,0)

        #Var that contain the message to send:
        self.message = StringVar()

        #Elements:
        self.chatPanel = Text(self.mainChat, state='disabled')
        self.chatPanel.configure(bg = 'white')
        self.messageInput = ttk.Entry(self.mainChat, textvariable=self.message, width=500)
        self.separator = ttk.Separator(self.mainChat, orient=HORIZONTAL)
        self.sendButton = ttk.Button(self.mainChat, text="Send", command=self.sendMessage)

        #Position:
        self.chatPanel.pack(side=TOP, fill=BOTH, expand=True, padx=10, pady=5)
        self.separator.pack(side=TOP, fill=BOTH, expand=True, padx=10, pady=5)
        self.messageInput.pack(side=TOP, fill=X, expand=True, padx=10, pady=5)
        self.sendButton.pack(side=TOP, fill=BOTH, expand=True, padx=10, pady=5)

        #Create names window
        self.namesCaptureWindow()
        #Move momentarily the main window to back:
        self.mainChat.attributes('-topmost', False)
        self.mainChat.mainloop()


    #Create name capture window
    def namesCaptureWindow(self):
        self.inputNamesWindow = Toplevel()

        #Basic propierties:
        self.inputNamesWindow.geometry('300x200')
        center_window(self.inputNamesWindow, 300, 200)
        self.inputNamesWindow.title("Lmao-Chat Desktop (Names)")
        #Not resizable:
        self.inputNamesWindow.resizable(0,0)

        #Names obtained:
        self.yourName = StringVar()
        self.friendName = StringVar()

        #Elements:
        fontType = font.Font(weight='bold')
        self.nameLabel1 = ttk.Label(self.inputNamesWindow, text="Your name:", font=fontType)
        self.nameLabel2 = ttk.Label(self.inputNamesWindow, text="Your friend's name:", font=fontType)
        self.localClientName = ttk.Entry(self.inputNamesWindow, textvariable=self.yourName, width=30)
        self.remoteClientName = ttk.Entry(self.inputNamesWindow, textvariable=self.friendName, width=30)
        self.chatButton = ttk.Button(self.inputNamesWindow, text="Chat!", command=self.startChat)

        #Element's position:
        self.nameLabel1.pack(side=TOP, fill=BOTH, expand=True, padx=5, pady=5)
        self.localClientName.pack(side=TOP, fill=X, expand=True, padx=5, pady=5)
        self.nameLabel2.pack(side=TOP, fill=BOTH, expand=True, padx=5, pady=5)
        self.remoteClientName.pack(side=TOP, fill=X, expand=True, padx=5, pady=5)
        self.chatButton.pack(side=LEFT, fill=BOTH, expand=True, padx=5, pady=5)

        #Start window function and focus the cursor on localClientName:
        self.localClientName.focus_set()
        #Make main window wait for that
        self.mainChat.wait_window(self.inputNamesWindow)


    #Function called when chat button is pressed (nameCaptureWindow):
    def startChat(self):
        #Destroy input Names Window.
        self.inputNamesWindow.destroy()

        #Print initial info:
        self.chatPanel.config(state='normal')
        self.chatPanel.insert(END, "[**Server**] > Welcome to Lmao-Chat!\n")
        self.chatPanel.insert(END, "[**Server**] > See your terminal to view the log\n")
        self.chatPanel.config(state='disabled')

        #Obtain User and Peer information:
        self.UserInfo = UpdateUserInfo(self.yourName.get())
        self.PeerInfo = TrackerAPI.GetUser(self.friendName.get())

        if self.PeerInfo is None:
            print("[!] El nombre de tu amigo no existe")
            exit(1)

        #Print more boring stuff:
        print("""
        Name: {0}
        IP: {1}
        Port: {2}
        Public Key:
        {3}
        """.format(self.UserInfo["name"], self.UserInfo["ip"], self.UserInfo["port"], self.UserInfo["pubKey"]))

        print("""\n\n
        Name: {0}
        IP: {1}
        Port: {2}
        Public Key:
        {3}
        """.format(self.PeerInfo["name"], self.PeerInfo["ip"], self.PeerInfo["port"], self.PeerInfo["pubKey"]))

        #Obtain P2P socket:
        self.sockets = network.StartPeerConnection(self.PeerInfo["ip"], self.PeerInfo["port"], self.PeerInfo["pubKey"])
        #Run listen incoming messages thread:
        Thread(target=self.putMessage).start()


    #Send-Button function
    def sendMessage(self):
        self.chatPanel.config(state='normal')
        msg = self.message.get()

        if(msg != ""):
            network.Send(self.sockets, self.PeerInfo["pubKey"], msg)
            aux_msg = "You > " + msg + "\n"
            self.chatPanel.insert(END, aux_msg)
            self.chatPanel.see(END)
            self.message.set("")

        self.chatPanel.config(state='disabled')


    #Print incoming remote messages on text panel:
    def putMessage(self):
        while True:
            msg = network.Receive(self.sockets)
            self.chatPanel.config(state='normal')
            msg = "Peer > " + msg + "\n"
            self.chatPanel.insert(END, msg)
            self.chatPanel.see(END)
            self.chatPanel.config(state='disabled')
