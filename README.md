# Port Scanner
Scans for Open ports in the given IPv4 Targets using TCP Protocol

## Requirements
Language Used = Python3
Modules/Packages used:
* socket
* queue
* optparse
* pickle
* threading
* colorama
* time

## Input
* '-t', "--target": IP Address/Addresses of the Target/Targets to scan Ports (seperated by ',')
* '-p', "--port": Port/Ports (seperated by ',') to scan
* '-P', "--port-range": Range of Ports to scan (seperated by '-', start-stop)
* '-T', "--threads": Number of Port Scanning Threads  (default = 100)
* '-d', "--timeout": Timeout for Single Port Scan
* '-l', "--load": Load Targets from a file
* '-r', "--read": File to read a Previous Scan Result
* '-w', "--write": Dump the output to a File (Optional)

## Output
The Program will display the Number of : Scaned Ports, Open Port and Close Ports, List of Open Ports and time taken to scan for each target. <br />
If the write argument is provided, it will dump the data of scan into a file named as the argument provided. <br />
If the read argument is provided, it will read the dump file of a previous scan.