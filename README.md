# Port Scanner

Scans for Open ports in the given IPv4 Targets using TCP Protocol

# Requirements

* Python 3.x

### Python Libraries

```
colorama
scapy
```

Install dependencies:

```bash
pip install -r requirements.txt
```

> Note: `scapy` scanner requires **root privileges**.

# Tools Included

## 1. port_scanner.py

A **multi-threaded TCP connect scanner** using Python sockets.

### Features

* Multi-threaded scanning (fast)
* Host discovery using ping
* Custom port ranges / lists
* Timeout control
* Save & load scan results
* Colored terminal output

## 2. scapy_port_scanner.py

A **SYN-based (half-open) port scanner** using Scapy.

### Features

* SYN packet scanning (stealthier than TCP connect)
* Packet sniffing for responses
* Multi-processing support
* Interface selection
* Root privilege enforcement
* Save & load results

# Usage

## port_scanner.py

```
usage: port_scanner.py [-h] [-t TARGET] [-p PORT] [-s PORT_RANGE]
                       [-P] [-d TIMEOUT] [-T THREADS]
                       [-l LOAD] [-r READ] [-w WRITE]

Port Scanner
```

### Arguments

| Argument             | Description                       |
| -------------------- | --------------------------------- |
| `-t`, `--target`     | Target IP(s), comma-separated     |
| `-p`, `--port`       | Port(s), comma-separated          |
| `-s`, `--port-range` | Port range (e.g., `20-80`)        |
| `-P`, `--ping`       | Enable ping check for alive hosts |
| `-d`, `--timeout`    | Timeout for each port scan        |
| `-T`, `--threads`    | Number of threads (default: 100)  |
| `-l`, `--load`       | Load targets from file            |
| `-r`, `--read`       | Read previous scan results        |
| `-w`, `--write`      | Save output to file               |

---

## scapy_port_scanner.py

```
usage: scapy_port_scanner.py [-t TARGET] [-i INTERFACE]
                             [-p PORT] [-s PORT_RANGE]
                             [-l LOAD] [-T TIMEOUT]
                             [-r READ] [-w WRITE]
```

### Arguments

| Argument             | Description                     |
| -------------------- | ------------------------------- |
| `-t`, `--target`     | Target IP(s), comma-separated   |
| `-i`, `--interface`  | Network interface to use        |
| `-p`, `--port`       | Port(s), comma-separated        |
| `-s`, `--port-range` | Port range (e.g., `20-80`)      |
| `-l`, `--load`       | Load targets from file          |
| `-T`, `--timeout`    | Sniffing timeout (default: 30s) |
| `-r`, `--read`       | Read previous scan results      |
| `-w`, `--write`      | Save output to file             |

# Output

* Displays:

  * Alive hosts
  * Open ports
  * Scan duration
* Optionally saves results using **pickle format**
