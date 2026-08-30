# CYBERSHoT Port Scanner v1.0

**CYBERSHoT Port Scanner** is a lightweight and multithreaded TCP port scanning tool developed in Python for basic network reconnaissance and security testing.

The tool takes a target hostname/IP address and a starting and ending port as command-line arguments. It resolves the target address and scans the specified range of TCP ports to identify which ports are open. Multithreading is used to perform port scans concurrently, helping improve scanning speed.

### Features

* TCP port scanning
* IP/hostname resolution
* Custom start and end port range
* Multithreaded scanning
* 1-second connection timeout
* Simple command-line interface
* Invalid target and port input handling

### Usage

```bash
python3 CYBERSHoT_Port_Scanner_v1.0.py <Target> <Start_Port> <End_Port>
```


### Download
```bash
git clone https://github.com/Nikhilpankaj/CYBERSHoT_Port_scanner.git
```


### Example

```bash
python3 CYBERSHoT_Port_Scanner_v1.0.py 192.168.1.1 1 1000
```


Example output:

```text
======================================================================
CYBERSHoT Port Scanner
======================================================================
Port 22 is open
Port 80 is open
Port 443 is open
```


### Technology Used

* **Python 3**
* `socket` — TCP connection and target resolution
* `threading` — concurrent port scanning
* `sys` — command-line argument handling

### Purpose

CYBERSHoT Port Scanner is intended for **educational purposes, network reconnaissance, and authorized security testing**. Only scan systems and networks for which you have permission.

### Version

**v1.0**
