#! /usr/bin/env python3

from os import geteuid
from datetime import date
from optparse import OptionParser
from pickle import load, dump
from colorama import Fore, Back, Style
from time import strftime, localtime

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

def check_root():
    return geteuid() == 0

if __name__ == "__main__":
    data = get_arguments(('-t', "--target", "target", "IP Address/Addresses of the Target/Targets to scan Ports (seperated by ',')"),
                         ('-p', "--port", "port", "Port/Ports (seperated by ',') to scan"),
                         ('-s', "--port-range", "port_range", "Range of Ports to scan (seperated by '-', start-stop)"),
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
    if not data.write:
        data.write = f"{date.today()} {strftime('%H_%M_%S', localtime())}"