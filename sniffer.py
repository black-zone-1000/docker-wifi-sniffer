import logging
import os
import sys
from scapy.all import *
from jsonpacket import *

http_destination = os.environ['SNIFFER_DESTINATION']
sniffing_filter = os.environ['SNIFFER_FILTER']
original_interface = os.environ['SNIFFER_INTERFACE']
channel = os.environ['SNIFFER_CHANNEL']
interface = original_interface + 'mon'

monitor_enable = [
    'ifconfig ' + original_interface + ' down',
    'iw dev ' + original_interface + ' interface add ' + interface + ' type monitor',
    'ifconfig ' + interface + ' down',
    'iw dev ' + interface + ' set type monitor',
    'ifconfig ' + interface + ' up',
    'iw dev ' + interface + ' set channel ' + channel
]

monitor_disable = ['iw dev ' + interface + ' del',
                   'ifconfig ' + original_interface + ' up']


def os_execute(commands):
    success = True
    for command in commands:
        logging.info("Executing: " + command)
        try:
            result = os.system(command)
            exit_code = result >> 8
            if exit_code != 0:
                logging.error("Error executing - " + command + ". Exit code:" + str(exit_code))
                success = False
        except Exception as exp:
            logging.error("Error executing - " + command + ". Error:" + str(exp))
    return success


def handle_packet(pkt):
    logging.info("Pkt captured")
    converted = JsonPacket(pkt)
    logging.info(converted)

    print(converted)


def start():
    logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.INFO)
    logging.info("Starting sniffer")
    logging.info("interface=" + original_interface)
    logging.info("channel=" + channel)
    logging.info("filter=" + sniffing_filter)
    logging.info("http destination=" + http_destination)

    logging.info("Disabling monitor mode interface for re-init")
    # First disable the monitor mode in case it was enabled in the past
    os_execute(monitor_disable)

    try:
        logging.info("Enabling monitor mode on interface")
        success = os_execute(monitor_enable)
        if success:
            logging.info("Interfaced ready starting capture...")
            sniff(iface=interface, prn=handle_packet, store=0, filter=sniffing_filter)
        else:
            logging.error("Error changing to monitor mode. Exiting...")
    except KeyboardInterrupt:
        sys.exit()
    finally:
        logging.info("Disable monitor mode on interface")
        os_execute(monitor_disable)


start()
