#! /usr/bin/env python3

from scapy.all import *
from os import geteuid
from datetime import date
from optparse import OptionParser
from pickle import load, dump
from threading import Thread
from multiprocessing import Pool, Lock, cpu_count
from colorama import Fore, Back, Style
from time import strftime, localtime, sleep

status_color = {
    '+': Fore.GREEN,
    '-': Fore.RED,
    '*': Fore.YELLOW,
    ':': Fore.CYAN,
    ' ': Fore.WHITE
}

def display(status, data, start='', end='\n'):
    print(f"{start}{status_color[status]}[{status}] {Fore.BLUE}[{date.today()} {strftime('%H:%M:%S', localtime())}] {status_color[status]}{Style.BRIGHT}{data}{Fore.RESET}{Style.RESET_ALL}", end=end)

def get_arguments(*args):
    parser = OptionParser()
    for arg in args:
        parser.add_option(arg[0], arg[1], dest=arg[2], help=arg[3])
    return parser.parse_args()[0]

self_ip = None
default_wait_time = 100
targets = []
alive_hosts = []
ports_to_scan = []
thread_count = cpu_count()
lock = Lock()
result = {}

def check_root():
    return geteuid() == 0

def sendPacket(ip, port, flags='S', count=1, interface=None, interval=0.1):
    if self_ip == None:
        ip_layer = IP(dst=ip)
    else:
        ip_layer = IP(src=self_ip, dst=ip)
    tcp_layer = TCP(dport=port, flags=flags)
    packet = ip_layer / tcp_layer
    if interface == None:
        send(packet, count=count, inter=interval, verbose=False)
    else:
        send(packet, iface=interface, count=count, inter=interval, verbose=False)
def sendPacketHandler(ips, ports, interface):
    for target in ips:
        for port in ports:
            try:
                sendPacket(target, port, interface=interface)
            except Exception as error:
                with lock:
                    display('-', f"Can't send Packet to {Back.MAGENTA}{target}:{port}{Back.RESET} => {Back.YELLOW}{error}{Back.RESET}")
def processPacket(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        with lock:
            if packet[IP].src in targets and sorted(list(str(packet[TCP].flags))) == ['A', 'S'] and packet[TCP].sport in ports_to_scan:
                display(':', f"Open => {Back.MAGENTA}{packet[IP].src}:{packet[TCP].sport}{Back.RESET}")
                result[packet[IP].src].append(packet[TCP].sport)
            elif packet[IP].src in targets:
                alive_hosts.append(packet[IP].src)

if __name__ == "__main__":
    arguments = get_arguments(('-t', "--target", "target", "IP Address/Addresses of the Target/Targets to scan Ports (seperated by ',')"),
                              ('-i', "--interface", "interface", "Interface to use"),
                              ('-p', "--port", "port", "Port/Ports (seperated by ',') to scan"),
                              ('-s', "--port-range", "port_range", "Range of Ports to scan (seperated by '-', start-stop)"),
                              ('-l', "--load", "load", "Load Targets from a file"),
                              ('-T', "--timeout", "timeout", f"Timeout for Listening for Packets (Default={default_wait_time} seconds)"),
                              ('-r', '--read', "read", "File to read a Previous Scan Result"),
                              ('-w', "--write", "write", "Dump the output to a File (Optional)"))
    if not check_root():
        display('-', f"This Program requires {Back.MAGENTA}root{Back.RESET} Privileges")
        exit(0)
    if arguments.read:
        try:
            with open(arguments.read, 'rb') as file:
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
    if not arguments.target:
        if not arguments.load:
            display('-', f"Please specifiy a Target")
            exit(0)
        else:
            try:
                with open(arguments.load, 'r') as file:
                    file_data = file.read().split('\n')
                arguments.target = [target for target in file_data if target != '']
            except FileNotFoundError:
                display('-', "File not Found!")
                exit(0)
            except:
                display('-', "Error in Reading the File")
                exit(0)
    else:
        arguments.target = arguments.target.split(',')
    if not arguments.port:
        if not arguments.port_range:
            ports  = list(range(0, 65537))
        else:
            start_port, stop_port = arguments.port_range.split('-')
            start_port = int(start_port.strip())
            stop_port = int(stop_port.strip())
            ports = list(range(start_port, stop_port+1))
    elif ',' not in arguments.port:
        ports = [int(arguments.port)]
    else:
        ports = arguments.port.split(',')
        ports = [int(port.strip()) for port in ports]
    ports_to_scan = ports
    if not arguments.timeout:
        arguments.timeout = default_wait_time
    else:
        arguments.timeout = float(arguments.timeout)
    if not arguments.interface:
        arguments.interface = None
        display(':', f"Starting Sniffing")
        Thread(target=sniff, kwargs={"prn": processPacket, "store": False}, daemon=True).start()
    elif arguments.interface not in get_if_list():
        display('*', f"Interface {Back.MAGENTA}{arguments.interface}{Back.RESET} not present")
        display(':', f"Available Interfaces : {Back.MAGENTA}{get_if_list()}{Back.RESET}")
        display('+', f"Using Default Interface")
        display(':', f"Starting Sniffing")
        Thread(target=sniff, kwargs={"prn": processPacket, "store": False}, daemon=True).start()
    else:
        self_ip = get_if_addr(arguments.interface)
        display(':', f"Got IP {Back.MAGENTA}{self_ip}{Back.RESET} for Interface {Back.MAGENTA}{arguments.interface}{Back.RESET}")
        display(':', f"Starting Sniffing on Interface {Back.MAGENTA}{arguments.interface}{Back.RESET}")
        Thread(target=sniff, kwargs={"prn": processPacket, "iface": arguments.interface, "store": False}, daemon=True).start()
    if not arguments.write:
        arguments.write = f"{date.today()} {strftime('%H_%M_%S', localtime())}"
    targets.extend(arguments.target)
    result = {target:[] for target in targets}
    total_targets = len(targets)
    display('+', f"Sending {Back.MAGENTA}SYN Packets{Back.RESET} to {Back.MAGENTA}{total_targets} Targets{Back.RESET} for {Back.MAGENTA}{len(ports)} Ports{Back.RESET} with {Back.MAGENTA}{thread_count}{Back.RESET} Threads")
    pool = Pool(thread_count)
    target_divisions = [targets[group*total_targets//thread_count: (group+1)*total_targets//thread_count] for group in range(thread_count)]
    threads = []
    for target_division in target_divisions:
        threads.append(pool.apply_async(sendPacketHandler, args=(target_division, ports, arguments.interface, )))
    for thread in threads:
        thread.get()
    pool.close()
    pool.join()
    with lock:
        display('*', f"Done Sending {Back.MAGENTA}SYN Packets{Back.RESET} to {Back.MAGENTA}{total_targets} Targets{Back.RESET} for {Back.MAGENTA}{len(ports)} Ports{Back.RESET} with {Back.MAGENTA}{thread_count}{Back.RESET} Threads")
        display(':', f"Now waiting for {Back.MAGENTA}{arguments.timeout} seconds{Back.RESET}")
    try:
        sleep(arguments.timeout)
    except KeyboardInterrupt:
        display('*', f"Keyboard Interrupt Detected!", start='\n')
        display(':', "Exiting")
    except Exception as error:
        display('-', f"Error Occured => {Back.YELLOW}{error}{Back.RESET}")
    display(':', f"Filtering Obtained Results")
    for target, open_ports in result.items():
        required_ports = []
        for port in open_ports:
            if port in ports:
                required_ports.append(port)
        result[target] = required_ports
    if arguments.write:
        display(':', f"Dumping Data to File {Back.MAGENTA}{arguments.write}{Back.RESET}")
        with open(arguments.write, 'wb') as file:
            with lock:
                dump({"result": result, "alive_hosts": alive_hosts}, file)