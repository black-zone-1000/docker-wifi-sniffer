Wifi sniffer
============

Sniff wifi packets on specific channel and by a filter, and send the packets in JSON format to an HTTP destination

Uses [Scapy](https://github.com/secdev/scapy/).

Running
-------

    $ pip install -r requirements.txt
    $ sudo python sniffer.py

Needs to be run with `sudo` because we're doing system-level stuff. 


Running with docker
-------------------
    $ docker build -t wifi-sniffer .
    $ docker run -d \
        --restart=always \
        --net=host \
        --privileged \
        --name=wifi-sniffer \
        -e SNIFFER_INTERFACE=[interface to listen on] \
        -e SNIFFER_CHANNEL=[channel to listen on] \
        -e SNIFFER_FILTER=[filter in tcpdump format] \
        -e SNIFFER_DESTINATION=[http destnation to send packets] \
        wifi-sniffer
               

Approach
--------

1. Put card into [monitor mode](https://en.wikipedia.org/wiki/Monitor_mode). This means it will passively sniff all wireless traffic it sees. It differs from the somewhat similar [promiscuous mode](https://en.wikipedia.org/wiki/Promiscuous_mode), which (as I understand it) gives you more information, but requires you to be connected to a network. Not all cards support monitor mode. This is done via a terminal command, as it doesn't seem possible through Python.

2. Sniff packets using scapy. Each packet received goes into a function for processing.

3. Convert the packets to JSON

4. Send the packets to HTTP/S destination
