# Chimay-Red-tiny
Exploit x86 and mipsbe **Mikrotik** routers and gain credentials.

## Author
#### Wikileaks	+= Vulnerability Disclosure
#### BigNerd95	+= Implemented the vulnerability
#### Reivhax	+= Ropchain Compilation and packing.
## Requirements
All you need to successfully exploit a router:

- A vulnerable router
- Network Access to the router
- < 20 seconds of patience
## Description
This exploit will exploit x86-based and mipsbe Mikrotik routers with Firmware version < **6.38.5**

The Ropchains file contains ropchains for all 6.* firmware releases.

The specified command will copy the user data file to an accessible location hence we will be able to download the data and decrypt credentials.

## Setup and Use
Clone this Repo

 	git clone https://github.com/reivhax/Chimay-Red-tiny.git

Move to the new folder

 	cd Chimay-Red-tiny

Run the script against your target

 	python chimayred.py TARGET_IP

## Dependencies
This exploits **does not** require any dependecies.
It uses default python modules; requests,socket,hashlib and time.

## Bug reports and support
Incase of any problem, please open a issue, I will be ready to assist you.

## References
[Wikileaks](https://wikileaks.org/ciav7p1/cms/page_16384604.html)

[BigNerd95](https://github.com/BigNerd95/)
