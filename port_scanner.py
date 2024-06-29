#!/usr/bin/env python3

import socket, os
from datetime import date
from optparse import OptionParser
from pickle import load, dump
from multiprocessing import Pool, cpu_count, Lock
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

ping_hosts = True
lock = Lock()

class PortScanner():
    def __init__(self, hosts, ports = [], timeout=-1):
        self.hosts = hosts
        self.timeout = timeout
        if ports == []:
            self.ports = list(range(0, 65537))
        else:
            self.ports = ports
        self.host_down = []
        self.open_ports = {host:[] for host in self.hosts}
    def checkHost(self, host):
        return os.system(f"ping -c 1 {host} >/dev/null") == 0
    def checkHosts(self, hosts):
        up_hosts, down_hosts = [], []
        for host in hosts:
            if self.checkHost(host):
                up_hosts.append(host)
            else:
                with lock:
                    display('*', f"Host {Back.MAGENTA}{host}{Back.RESET} Unreachable")
                down_hosts.append(host)
        return up_hosts, down_hosts
    def checkPort(self, host, port):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if self.timeout != -1:
                socket.setdefaulttimeout(self.timeout)
            result = self.socket.connect_ex((host, port))
        except:
            return False
        else:
            if result == 0:
                return True
            self.socket.close()
    def scanner(self, hosts, ports):
        open_ports = {host:[] for host in hosts}
        for host in hosts:
            for port in ports:
                status = self.checkPort(host, port)
                if status:
                    with lock:
                        display(':', f"Open => {Back.MAGENTA}{host}:{port}{Back.RESET}")
                    open_ports[host].append(port)
        return open_ports
    def scan(self):
        t1 = time()
        thread_count = cpu_count()
        display(':', f"Detecting Alive Hosts with {Back.MAGENTA}{thread_count} Threads{Back.RESET}")
        if ping_hosts:
            pool = Pool(thread_count)
            host_count = len(self.hosts)
            host_divisions = [self.hosts[group*host_count//thread_count: (group+1)*host_count//thread_count] for group in range(thread_count)]
            threads = []
            for host_division in host_divisions:
                threads.append(pool.apply_async(self.checkHosts, (host_division, )))
            for thread in threads:
                up_hosts, down_hosts = thread.get()
                for host in down_hosts:
                    self.open_ports.pop(host)
                    self.hosts.remove(host)
            pool.close()
            pool.join()
            display('+', f"Total Alive Hosts = {Back.MAGENTA}{len(self.open_ports)}{Back.RESET}")
        display(':', f"Starting Port Scanning {Back.MAGENTA}{thread_count} Threads{Back.RESET}")
        pool = Pool(thread_count)
        host_count = len(self.hosts)
        host_divisions = [self.hosts[group*host_count//thread_count: (group+1)*host_count//thread_count] for group in range(thread_count)]
        threads = []
        for host_division in host_divisions:
            threads.append(pool.apply_async(self.scanner, (host_division, self.ports)))
        for thread in threads:
            current_thread_open_ports = thread.get()
            for host, ports in current_thread_open_ports.items():
                self.open_ports[host].extend(ports)
        pool.close()
        pool.join()
        t2 = time()
        return self.open_ports, self.host_down, t2-t1

if __name__ == "__main__":
    data = get_arguments(('-t', "--target", "target", "IP Address/Addresses of the Target/Targets to scan Ports (seperated by ',')"),
                           ('-p', "--port", "port", "Port/Ports (seperated by ',') to scan"),
                         ('-s', "--port-range", "port_range", "Range of Ports to scan (seperated by '-', start-stop)"),
                         ('-P', "--ping", "ping", f"Ping to check Alive Hosts (True/False, Default={ping_hosts})"),
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
    if data.ping == "False":
        ping_hosts = False
    if not data.timeout:
        data.timeout = -1
    else:
        data.timeout = int(data.timeout)
    if not data.write:
        data.write = f"{date.today()} {strftime('%H_%M_%S', localtime())}"
    result = {}
    scanner = PortScanner(data.target, ports=ports, timeout=data.timeout)
    display(':', f"Starting Port Scan on {Back.MAGENTA}{len(data.target)} Targets{Back.RESET} for {Back.MAGENTA}{len(ports)}{Back.RESET} ports with {Back.MAGENTA}{cpu_count()} Threads{Back.RESET} ")
    result, host_down, time_taken = scanner.scan()
    display('+', f"Port Scan Finished!\n")
    display(':', f"Time Taken for Full Scan = {Back.MAGENTA}{time_taken}{Back.RESET}\n")
    if data.write:
        with open(data.write, 'wb') as file:
            dump({"port_scan": result, "host_down": host_down, "time_taken": time_taken}, file)