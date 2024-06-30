# Port Scanner
Scans for Open ports in the given IPv4 Targets using TCP Protocol

## Requirements
Language Used = Python3
Modules/Packages used:
* scapy
* socket
* os
* datetime
* optparse
* pickle
* multiprocessing
* colorama
* time
<!-- -->
Install the dependencies:
```bash
pip install -r requirements.txt
```
## port_scanner.py
### Input
* '-t', "--target": IP Address/Addresses of the Target/Targets to scan Ports (seperated by ',')
* '-p', "--port": Port/Ports (seperated by ',') to scan
* '-s', "--port-range": Range of Ports to scan (seperated by '-', start-stop)
* '-d', "--timeout": Timeout for Single Port Scan
* '-l', "--load": Load Targets from a file
* '-r', "--read": File to read a Previous Scan Result
* '-w', "--write": Dump the output to a File (Optional)

### Output
The Program will display the Number of : Scaned Ports, Open Port and Close Ports, List of Open Ports and time taken to scan for each target. <br />
If the write argument is provided, it will dump the data of scan into a file named as the argument provided. <br />
If the read argument is provided, it will read the dump file of a previous scan.
## scapy_port_scanner.py
This program requires root privileges. It is good for scanning a large amount of Hosts. It sends SYN Packets parallely and sniffs the incomming packet using a daemonic thread.
### Input
* '-t', "--target": IP Address/Addresses of the Target/Targets to scan Ports (seperated by ',')
* '-i', "--interface" : Interface to use
* '-p', "--port": Port/Ports (seperated by ',') to scan
* '-s', "--port-range": Range of Ports to scan (seperated by '-', start-stop)
* '-l', "--load": Load Targets from a file
* '-T', "--timeout": Timeout for Single Port Scan
* '-r', "--read": File to read a Previous Scan Result
* '-w', "--write": Dump the output to a File (Optional)

### Output
The Program will display the Number of : Scaned Ports, Open Port and Close Ports, List of Open Ports and time taken to scan for each target. <br />
If the write argument is provided, it will dump the data of scan into a file named as the argument provided. <br />
If the read argument is provided, it will read the dump file of a previous scan.