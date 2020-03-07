import logging
import os
import sys
import scapy

# linux
original_interface = os.environ['SNIFFER_INTERFACE']
channel = os.environ['SNIFFER_CHANNEL']
interface = original_interface + 'mon'

monitor_enable = 'ifconfig ' + original_interface + ' down; ' \
                  'iw dev ' + original_interface + ' interface add ' + interface + ' type monitor; ' \
                  'ifconfig ' + interface + ' down; ' \
                  'iw dev ' + interface + ' set type monitor; ' \
                  'ifconfig ' + interface + ' up; ' \
                  'iw dev ' + interface + ' set channel ' + channel

monitor_disable = 'iw dev ' + interface + ' del; ' \
                  'ifconfig ' + original_interface + ' up'


def handle_packet(pkt):
    pkt.show()


def start():
    logging.basicConfig(filename='wifi-sniffer.log', format='%(levelname)s:%(message)s', level=logging.INFO)

    # First disable the monitor mode in case it was enabled in the past
    try:
        os.system(monitor_disable)
    except any:
        pass

    try:
        # Enable monitoring mode
        os.system(monitor_enable)
        scapy.sniff(interface, prn=handle_packet)
    except KeyboardInterrupt:
        sys.exit()
    finally:
        os.system(monitor_disable)


start()
