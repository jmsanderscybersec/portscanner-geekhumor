**Dependencies for the program:**

Python3 

Scapy: pip install scapy for scanner functionality 

tqdm: pip install tqdm for progress bar

**Commands** 
Example: sudo python3 scanner.py TARGETIPADDRESS -p 1-100 -t XYZ --tcp

Whereas -p is the port range to scan

Whereas XYZ can be: 

SYN for TCP SYN Scan 

CONNECT for TCP Connect Scan 

ACK for TCP ACK Scan 

XMAS for TCP XMAS Scan

Use --udp for UDP scan

**Only scan what you have permission to scan**
