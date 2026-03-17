#!/usr/bin/env python3

import socket
from shlex import split
from datetime import date
from argparse import ArgumentParser
from pickle import load, dump
from queue import Queue, Empty
from threading import Thread, Lock
from subprocess import run, DEVNULL
from colorama import Fore, Back, Style
from time import strftime, localtime, time

status_color = {
    '+': Fore.GREEN,
    '-': Fore.RED,
    '*': Fore.YELLOW,
    ':': Fore.CYAN,
    ' ': Fore.WHITE,
}

ping_hosts = False
lock = Lock()
thread_count = 100

def get_time():
    return strftime("%H:%M:%S", localtime())
def display(status, data):
    print(f"{status_color[status]}[{status}] {Fore.BLUE}[{date.today()} {get_time()}] {status_color[status]}{Style.BRIGHT}{data}{Fore.RESET}{Style.RESET_ALL}")

def get_arguments():
    description = "Port Scanner"
    parser = ArgumentParser(description=description)
    parser.add_argument('-t', "--target", type=str, help="IP Address/Addresses of the Target/Targets to scan Ports (seperated by ',')")
    parser.add_argument('-p', "--port", type=str, help="Port/Ports (seperated by ',') to scan")
    parser.add_argument('-s', "--port-range", type=str, help="Range of Ports to scan (seperated by '-', start-stop)")
    parser.add_argument('-P', "--ping", action="store_true", help=f"Ping to check Alive Hosts (True/False, Default={ping_hosts})", default=ping_hosts)
    parser.add_argument('-d', "--timeout", type=float, help="Timeout for Single Port Scan")
    parser.add_argument('-T', "--threads", type=int, help=f"Number of Threads for Port Scanning (Default={thread_count})", default=thread_count)
    parser.add_argument('-l', "--load", type=str, help="Load Targets from a file")
    parser.add_argument('-r', "--read", type=str, help="File to read a Previous Scan Result")
    parser.add_argument('-w', "--write", type=str, help="Dump the output to a File (Optional)", default=f"{date.today()} {strftime('%H_%M_%S', localtime())}")
    return parser.parse_args()

class PortScanner():
    def __init__(self, hosts, ports=[], thread_count=100, timeout=None):
        self.hosts = hosts
        self.timeout = timeout
        if ports == []:
            self.ports = list(range(0, 65537))
        else:
            self.ports = ports
        self.thread_count = thread_count
        self.up_hosts = []
        self.down_hosts = []
        self.open_ports = {host:[] for host in self.hosts}
    def checkHost(self, host, count=4, timeout=2):
        return run(split(f"ping -w {timeout} -c {count} {host}"), shell=False, stdout=DEVNULL, stderr=DEVNULL).returncode == 0
    def checkHosts(self, queue):
        while True:
            try:
                host = queue.get_nowait()
            except Empty:
                break
            if self.checkHost(host):
                with lock:
                    display('+', f"Host {Back.MAGENTA}{host}{Back.RESET} Alive")
                    self.up_hosts.append(host)
            else:
                with lock:
                    display('*', f"Host {Back.MAGENTA}{host}{Back.RESET} Unreachable")
                    self.down_hosts.append(host)
    def checkPort(self, host, port):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if self.timeout != None:
                socket.setdefaulttimeout(self.timeout)
            result = self.socket.connect_ex((host, port))
        except:
            return False
        else:
            if result == 0:
                return True
            self.socket.close()
    def scanner(self, queue, ports):
        while True:
            try:
                host = queue.get_nowait()
            except Empty:
                break
            for port in ports:
                status = self.checkPort(host, port)
                if status:
                    with lock:
                        self.open_ports[host].append(port)
                        display(':', f"Open => {Back.MAGENTA}{host}:{port}{Back.RESET}")
    def scan(self):
        t1 = time()
        if ping_hosts:
            display(':', f"Detecting Alive Hosts with {Back.MAGENTA}{thread_count} Threads{Back.RESET}")
            threads = []
            queue = Queue()
            for host in self.hosts:
                queue.put(host)
            for thread_index in range(self.thread_count):
                threads.append(Thread(target=self.checkHosts, args=(queue, )))
                threads[-1].start()
            for thread in threads:
                thread.join()
            for host in self.down_hosts:
                self.open_ports.pop(host)
                self.hosts.remove(host)
            display('+', f"Total Alive Hosts = {Back.MAGENTA}{len(self.open_ports)}{Back.RESET}")
        display(':', f"Starting Port Scanning {Back.MAGENTA}{thread_count} Threads{Back.RESET}")
        threads = []
        queue = Queue()
        for host in self.hosts:
            queue.put(host)
        for thread_index in range(self.thread_count):
            threads.append(Thread(target=self.scanner, args=(queue, self.ports, )))
            threads[-1].start()
        for thread in threads:
            thread.join()
        for thread in threads:
            thread.get()
        t2 = time()
        return self.open_ports, self.host_down, t2-t1

if __name__ == "__main__":
    data = get_arguments()
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
        for target, open_ports in result["result"].items():
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
    result = {}
    scanner = PortScanner(data.target, ports=ports, timeout=data.timeout)
    display(':', f"Starting Port Scan on {Back.MAGENTA}{len(data.target)} Targets{Back.RESET} for {Back.MAGENTA}{len(ports)}{Back.RESET} ports with {Back.MAGENTA}{data.threads} Threads{Back.RESET} ")
    result, host_down, time_taken = scanner.scan()
    display('+', f"Port Scan Finished!\n")
    display(':', f"Time Taken for Full Scan = {Back.MAGENTA}{time_taken}{Back.RESET}\n")
    if data.write:
        with open(data.write, 'wb') as file:
            dump({"port_scan": result, "host_down": host_down, "time_taken": time_taken}, file)