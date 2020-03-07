Wifi sniffer
========

Sniff Wifi traffic, log device addresses.

Uses [Scapy](https://github.com/secdev/scapy/).

Running
-------

There's two different sets of configuration for Mac OS and Linux in `wifispy.py`, you'll have to comment out the appropriate set before running. I've only been able to make it work on Linux so far.

    $ pip install -r requirements.txt
    $ sudo python sniffer.py

Needs to be run with `sudo` because we're doing system-level stuff. 


Approach
--------

1. Put card into [monitor mode](https://en.wikipedia.org/wiki/Monitor_mode). This means it will passively sniff all wireless traffic it sees. It differs from the somewhat similar [promiscuous mode](https://en.wikipedia.org/wiki/Promiscuous_mode), which (as I understand it) gives you more information, but requires you to be connected to a network. Not all cards support monitor mode. This is done via a terminal command, as it doesn't seem possible through Python.

2. Sniff packets using scapy. Each packet received goes into a function for processing.
