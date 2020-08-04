#!/usr/bin/env python
import os, time, netifaces, sys, logging
from sys import platform
from scapy.all import *
from socket import *
from binascii import hexlify
import struct
import binascii
import re
import threading

def promiscuousTest():
        net=["100.100.2.100", "100.100.2.101", "100.100.2.102","100.100.2.103","100.100.2.104","100.100.2.105"]
        global currentTestIp
        while True:
                for ip in net:
                        currentTestIp=ip
                        sendp(Ether(dst="01:00:00:00:00:00")/ARP(pdst=ip),verbose=False)
                        time.sleep(60)

def sanitizeARP():
    net=["100.100.2.100", "100.100.2.101", "100.100.2.102","100.100.2.103","100.100.2.104","100.100.2.105","100.100.2.1"]
    while True:
        for ip in net:
            os.system("arping -c 2 "+ip+" >/dev/null")

def check_spoof (source, mac, destination):
    logging.basicConfig(format='%(levelname)s: %(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', filename=filename, filemode="a", level=logging.DEBUG)
    # Function checks if a specific ARP reply is part of an ARP spoof attack or not
    if destination == broadcast:
        if not mac in replies_count:
            replies_count[mac] = 0

    if not source in requests and source != local_ip:
        if not mac in replies_count:
            replies_count[mac] = 0
        else:
            replies_count[mac] += 1
        if (replies_count[mac] > request_threshold):
            # Check number of replies reaches threshold or not, and whether or not we have sent a notification for this MAC addr
            logging.error("Detected an on-going ARP Poisoning attack originated from this MAC address {}".format(mac)) # Logs the attack in the log file
            # Issue eth frame Notification to the detected Attacker ####
            issue_msg(local_MAC, mac,"We have detected an on-going ARP Poisoning attack originated from this address")
            if sanitizing==1:
                pass
            else:
                thread4 = threading.Thread(target = sanitizeARP)
                thread4.start()
    else:
        if source in requests:
            requests.remove(source)

def packet_filter (packet):
    logging.basicConfig(format='%(levelname)s: %(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', filename=filename, filemode="a", level=logging.DEBUG)
    # Retrieve necessary parameters from packet
    source = packet.sprintf("%ARP.psrc%")
    dest = packet.sprintf("%ARP.pdst%")
    source_mac = packet.sprintf("%ARP.hwsrc%")
    operation = packet.sprintf("%ARP.op%")
    if source == local_ip:
        requests.append(dest)
    if source == currentTestIp and dest== local_ip and operation=="is-at":
        logging.error("Detected a promiscuous mode NIC at this MAC Address {}".format(source_mac)) # Logs the attack in the log file
        issue_msg(local_MAC, source_mac,"We have detected a promiscuous mode NIC at this MAC Address, sniffing is not allowed in this network")
    if operation == 'is-at':
        return check_spoof (source, source_mac, dest)

def eui48_to_bytes(s: str):
    """Convert MAC address (EUI-48) string to bytes."""
    if re.match(r'^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$', s):
        sep = ':'
    elif re.match(r'^([0-9A-Fa-f]{2}-){5}([0-9A-Fa-f]{2})$', s):
        sep = '-'
    else:
        raise ValueError('invalid format')
    return binascii.unhexlify(''.join(s.split(sep)))

def issue_msg(src, dst, msg):
    ETH_P_802_EX1 = 0x88B5      # Local Experimental Ethertype 1
    # Create a layer 2 raw socket
    with socket(AF_PACKET, SOCK_RAW) as client_socket:
        # Bind an interface
        client_socket.bind((interface, 0))
        # Send a frame
        client_socket.sendall(
            # Pack in network byte order
            struct.pack('!6s6sH{}s'.format(len(msg)),
                        eui48_to_bytes(dst),             # Destination MAC address
                        eui48_to_bytes(src),    # Source MAC address
                        ETH_P_802_EX1,                      # Ethernet type
                        msg.encode()))                     # Payload

def arpwatchDetect():
    logging.basicConfig(format='%(levelname)s: %(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', filename=filename, filemode="a", level=logging.DEBUG)
    num=os.popen("cat syslog | wc -l").read()
    comando="sed '"+num.strip()+"q;d' syslog"
    flipflop_check={}
    mismatch_check={}
    while True:
        newEntry=os.popen(comando).read()
        parts=[]
        if newEntry:
            parts=newEntry.split(" ")[5:]
            if parts[0]== "bogon" and parts[1]!="0.0.0.0":
                issue_msg(local_MAC, parts[2], "Detected a non legit Bogon Message from this MAC Address")
                logging.error("Detected a non legit Bogon Message from the MAC Address {}".format(parts[2])) # Logs the attack in the log file
            elif parts[0]=="changed":
                 flipflop_check[parts[3]]=1

            elif parts[0]=="flip":
                try:
                    flipflop_check[parts[2]]=flipflop_check[parts[2]]+1
                    if flipflop_check[parts[2]]==3:
                        issue_msg(local_MAC, parts[3], "We have detected a probable ARP Spoofing attack originated from this MAC Address")
                        flipflop_check[parts[2]]=0
                        logging.error("Detected a probable ARP Spoofing attack originated from this MAC Address {}".format(parts[3])) # Logs the attack in the log file
                        if sanitizing==1:
                            pass
                        else:
                            thread4 = threading.Thread(target = sanitizeARP)
                            thread4.start()
                except:
                     flipflop_check[parts[2]]=0
            elif parts[0]=="ethernet":
                if parts[1]=="mismatch":
                    try:
                        mismatch_check[parts[2]]=mismatch_check[parts[2]]+1
                        if mismatch_check[parts[2]]==3:
                            issue_msg(local_MAC, parts[3], "We have detected a probable ARP Spoofing attack originated from this MAC Address")
                            mismatch_check[parts[2]]=0
                            logging.error("Detected a probable ARP Spoofing attack originated from this MAC Address {}".format(parts[3])) # Logs the attack in the log file
                            if sanitizing==1:
                                pass
                            else:
                                thread4 = threading.Thread(target = sanitizeARP)
                                thread4.start()
                    except Exception as e:
                        mismatch_check[parts[2]]=1
                elif parts[1]=="broadcast":
                    issue_msg(local_MAC, parts[3], "We have detected a  broadcast message in frame source, it is used only to hide the identity, stop the attack or you will be detected")
                    logging.error("Detected a  broadcast message in frame source, it is used only to hide the identity {}".format(parts[3])) # Logs the attack in the log file
            num=int(str(num).strip())+1
            comando="sed '"+str(num)+"q;d' syslog"
        else:
            pass

if __name__ == '__main__':
    global local_MAC, interface, filename
    global sanitizing
    sanitizing=0
    # ARP Replies limit from a certain MAC after which it is flagged as an Attacker
    request_threshold = 3
    # Check if running user is root
    if os.geteuid() != 0:
        exit("The tool needs Root permisson to use network interfaces")
    # Name log file
    filename = input("Please input desired log file name. [spoof.log]")
    if filename == "":
        filename = "spoof.log"
    # Set logging structure
    logging.basicConfig(format='%(levelname)s: %(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', filename=filename, filemode="a", level=logging.DEBUG)
    # listing available network interfaces
    available_interfaces = netifaces.interfaces()
    # Ask user for desired interface
    interface = input("Guard on interface [available ones: {}]:".format(str(available_interfaces)))
    # Get local mac ####
    local_MAC = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]["addr"]
    #local_MAC = bytes.fromhex(local_MAC.replace(":",""))
    # Verificare che se invio con questo genere di mac address vada
    # MYMAC=hexlify(s.getsockname()[4]) o meglio prova !!!-> bytes.fromhex( "001122334455" )

    # Check if specified interface is valid
    if not interface in available_interfaces:
        exit("Interface {} not available.".format(interface))
    # Retrieve network addresses (IP, broadcast) from the network interfaces
    addrs = netifaces.ifaddresses(interface)
    try:
        local_ip = addrs[netifaces.AF_INET][0]["addr"]
        broadcast = addrs[netifaces.AF_INET][0]["broadcast"]
    except KeyError:
        exit("Cannot read address/broadcast address on interface {}".format(interface))

    requests = []
    replies_count = {}

    logging.info("Started on {}".format(local_ip))

    print("ARP Spoofing Detection Started ...")
    # Rely on scapy sniff function to do the hard job - sniffing packets.
    # scapy sniff function Help:
    # sniff(count=0, store=1, offline=None, prn=None, lfilter=None, L2socket=None, timeout=None, *arg, **karg)
    #    Sniff packets
    #    sniff([count=0,] [prn=None,] [store=1,] [offline=None,] [lfilter=None,] + L2ListenSocket args) -> list of packets
    #    Select interface to sniff by setting conf.iface. Use show_interfaces() to see interface names.
    #      count: number of packets to capture. 0 means infinity
    #      store: wether to store sniffed packets or discard them
    #        prn: function to apply to each packet. If something is returned,
    #             it is displayed. Ex:
    #             ex: prn = lambda x: x.summary()
    #    lfilter: python function applied to each packet to determine
    #             if further action may be done
    #             ex: lfilter = lambda x: x.haslayer(Padding)
    #    offline: pcap file to read packets from, instead of sniffing them
    #    timeout: stop sniffing after a given time (default: None)
    #    L2socket: use the provided L2socket
    thread1 = threading.Thread(target = promiscuousTest)
    thread1.start()
    thread2 = threading.Thread(target = arpwatchDetect)
    thread2.start()
    sniff(filter="arp", prn=packet_filter, store=0)
