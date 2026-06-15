# Syntecxhub_PortScanner

## TCP Port Scanner

This project is a TCP Port Scanner developed using Python as part of the Syntecxhub Cybersecurity Internship Program.

### Features

* Scan a target host or IP address
* Scan a custom range of TCP ports
* Single-port scanning support
* Multithreaded scanning for improved performance
* Hostname resolution
* Logging of scan results
* Common service identification (HTTP, HTTPS, SSH, etc.)
* Error and timeout handling

### Technologies Used

* Python
* Socket Programming
* Threading
* Logging
* Argparse

### Usage

Run the scanner:

```bash
python port_scanner.py scanme.nmap.org
```

Scan a custom range:

```bash
python port_scanner.py scanme.nmap.org -s 1 -e 1024
```

Scan a single port:

```bash
python port_scanner.py scanme.nmap.org -p 80
```

### Learning Outcomes

* TCP/IP Networking
* Socket Programming
* Multithreading
* Network Reconnaissance
* Cybersecurity Fundamentals


