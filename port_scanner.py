#!/usr/bin/env python3

import socket
from datetime import date
from optparse import OptionParser
from pickle import load, dump
from multiprocessing import Pool, cpu_count
from colorama import Fore, Back, Style
from time import strftime, localtime, time

status_color = {
	'+': Fore.GREEN,
	'-': Fore.RED,
	'*': Fore.YELLOW,
	':': Fore.CYAN,
	' ': Fore.WHITE,
}

def get_time():
	return strftime("%H:%M:%S", localtime())
def display(status, data):
	print(f"{status_color[status]}[{status}] {Fore.BLUE}[{date.today()} {get_time()}] {status_color[status]}{Style.BRIGHT}{data}{Fore.RESET}{Style.RESET_ALL}")

def get_arguments(*args):
	parser = OptionParser()
	for arg in args:
		parser.add_option(arg[0], arg[1], dest=arg[2], help=arg[3])
	return parser.parse_args()[0]

class PortScanner():
	def __init__(self, host, ports = [], timeout=-1):
		self.host = host
		self.timeout = timeout
		if ports == []:
			self.ports = list(range(0, 65537))
		else:
			self.ports = ports
		self.open_ports = []
	def checkPort(self, port):
		try:
			self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			if self.timeout != -1:
				socket.setdefaulttimeout(self.timeout)
			result = self.socket.connect_ex((self.host, port))
		except:
			return False
		else:
			if result == 0:
				return True
			self.socket.close()
	def scanner(self, ports):
		open_ports = []
		for port in ports:
			status = self.checkPort(port)
			if status:
				open_ports.append(port)
		return open_ports
	def scan(self):
		t1 = time()
		thread_count = cpu_count()
		pool = Pool(thread_count)
		port_count = len(self.ports)
		port_divisions = [self.ports[group*port_count//thread_count: (group+1)*port_count//thread_count] for group in range(thread_count)]
		threads = []
		for port_division in port_divisions:
			threads.append(pool.apply_async(self.scanner, (port_division, )))
		for thread in threads:
			self.open_ports.extend(thread.get())
		pool.close()
		pool.join()
		t2 = time()
		return self.open_ports, [port for port in self.ports if port not in self.open_ports], t2-t1

if __name__ == "__main__":
	data = get_arguments(('-t', "--target", "target", "IP Address/Addresses of the Target/Targets to scan Ports (seperated by ',')"),
		      			 ('-p', "--port", "port", "Port/Ports (seperated by ',') to scan"),
					     ('-P', "--port-range", "port_range", "Range of Ports to scan (seperated by '-', start-stop)"),
						 ('-d', "--timeout", "timeout", "Timeout for Single Port Scan"),
						 ('-l', "--load", "load", "Load Targets from a file"),
						 ('-r', '--read', "read", "File to read a Previous Scan Result"),
						 ('-w', "--write", "write", "Dump the output to a File (Optional)"))
	if data.read:
		try:
			with open(data.read, 'rb') as file:
				result = load(file)
		except FileNotFoundError:
			display('-', "File not Found!")
			exit(0)
		except:
			display('-', "Error in Reading the File")
			exit(0)
		for target, open_ports in result.items():
			display(':', f"Target     = {target}")
			display(':', f"Open Ports = {len(open_ports)}")
			print(f"{Fore.GREEN}Open Ports{Fore.RESET}\n{'-'*10}{Fore.CYAN}")
			print('\n'.join([str(port) for port in open_ports]))
			print('\n')
		print(Fore.RESET)
		exit(0)
	if not data.target:
		if not data.load:
			display('-', f"Please specifiy a Target")
			exit(0)
		else:
			try:
				with open(data.load, 'r') as file:
					file_data = file.read().split('\n')
				data.target = [target for target in file_data if target != '']
			except FileNotFoundError:
				display('-', "File not Found!")
				exit(0)
			except:
				display('-', "Error in Reading the File")
				exit(0)
	else:
		data.target = data.target.split(',')
	if not data.port:
		if not data.port_range:
			ports  = list(range(0, 65537))
		else:
			start_port, stop_port = data.port_range.split('-')
			start_port = int(start_port.strip())
			stop_port = int(stop_port.strip())
			ports = list(range(start_port, stop_port+1))
	elif ',' not in data.port:
		ports = [int(data.port)]
	else:
		ports = data.port.split(',')
		ports = [int(port.strip()) for port in ports]
	if not data.timeout:
		data.timeout = -1
	else:
		data.timeout = int(data.timeout)
	result = {}
	for target in data.target:
		scanner = PortScanner(target, ports=ports, timeout=data.timeout)
		display(':', f"Starting Port Scan on {Back.MAGENTA}{target}{Back.RESET} for {Back.MAGENTA}{len(ports)}{Back.RESET} ports with {Back.MAGENTA}{cpu_count()}{Back.RESET} threads")
		open_ports, closed_ports, time_taken = scanner.scan()
		result[target] = open_ports
		display('+', f"Port Scan Finished!\n")
		display(':', f"Scanned Ports      = {Back.MAGENTA}{len(ports)}{Back.RESET}")
		display(':', f"Open Ports         = {Back.MAGENTA}{len(open_ports)}{Back.RESET}")
		display(':', f"Closed Ports       = {Back.MAGENTA}{len(closed_ports)}{Back.RESET}")
		display(':', f"Time Taken to Scan = {Back.MAGENTA}{time_taken}{Back.RESET}\n")
		print(f"{Fore.GREEN}Open Ports{Fore.RESET}\n{'-'*10}{Fore.CYAN}")
		print('\n'.join([str(port) for port in open_ports]))
		print(Fore.RESET)
		print('\n')
	if data.write:
		if data.write == '':
			with open(get_time(), 'wb') as file:
				dump(result, file)
		else:
			with open(data.write, 'wb') as file:
				dump(result, file)