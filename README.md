--------------------------
Ultimate Wireless Sniffer
__________________________

Works In Python 2.
Set your wireless adapter into monitor mode for this program to work and sniff wireless devices around you.

______________________________
Requirements:

1.Scapy module
2.The Standard Python Library

______________________________
Usage:

python ultimate-Wireless-Sniffer.py  -i <interface>
or
python ultimate-Wireless-Sniffer.py

_______________________________
How It Works:

The Ultimate Wireless Sniffer, will scan for all wireless traffic nearby, obtains the SSID's and ESSID's of Access Points
and client/user devices such as mobile phones and laptops or desktops. All captured credentials are stored in the file
sniffed_devices which is created automatically when the program runs and updated every time the program runs.
In the file, sniffed_devices, the [DE] represents clients/users devices while [AP] respresents Access Points.
The program also keeps a log of all the devices and their MAC addresses in the sniffer.log file. Remember to delete the log files
in case they grow too large.

Designed to work on a Linux system. Tested on Kali Linux Rolling.

_______________________________
Contact:

This tool is currently maintained by Anthony 'phystro' Karoki.
- Email : phystroq@gmail.com
- Blog : thehackerrealm.blogspot.com
