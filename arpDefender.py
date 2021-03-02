# python !

import argparse
import time
import sys
import os
from threading import Thread

from scapy.all import *
from scapy.layers.dhcp import *
from scapy.layers.l2 import Ether, ARP
from uuid import getnode as get_mac
from scapy.layers.inet import ICMP
from python_arptable import *

my_mac = get_mac()
my_mac = str(':'.join(("%012X" % my_mac)[i:i + 2] for i in range(0, 12, 2)))    # our mac address
my_mac = my_mac.lower()                                                         # make its letters to lower
my_ip = str(conf.route.route()[1])                                              # our ip address
FLAG1 = 0
FLAG2 = 0
FLAG3 = 0
dict_of_arp = {}            # dictionary which contain the arp data


def handle_is_at(pkt):      # the first method which checking if we are under attack
    global FLAG1
    # check whether the arp packet is: "is at" packet, and if our ip and mac is the destination of this arp packet
    if pkt[ARP].op == 2 and my_ip == pkt[ARP].pdst and my_mac == pkt[ARP].hwdst:
        # sending a arp packet: "who has" to check the reliability of the address we have
        r = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=pkt[ARP].psrc, psrc=my_ip, hwsrc=my_mac))
        if r[0][0][1].hwsrc != pkt[ARP].hwsrc:  # if the 2 sources are not equals, we probably under attack...
            FLAG1 = 1
            # print("FLAG1 is now check_is_at method")

def check_is_at():          # a call method which call the first method which checking if we are under attack
    global FLAG1
    while FLAG1 != 1:
        sniff(filter="arp", prn=handle_is_at, count=1)      # sniffing only arp packets
    print("FLAG1 is Up ", FLAG1)


def handle_duplicates(pkt):             # the second method which checking if we are under attack
    global FLAG2
    global dict_of_arp
    if pkt.haslayer(ARP) and pkt[ARP].op == 2:
        if pkt[Ether].dst == "ff:ff:ff:ff:ff:ff":
            return True
        val = pkt[ARP].hwsrc
        key = pkt[ARP].psrc
        if key not in dict_of_arp:
            dict_of_arp[key] = val
        else:
            if dict_of_arp[key] != val:
                return True
    print(dict_of_arp)

def check_for_duplicates():         # a call method which call the second method which checking if we are under attack
    global FLAG2
    # if we are in Linux os we checking whether we have duplicates information in the arp table
    if "linux" in sys.platform or "posix" in os.name:
        while 1 == 1:
            tab = get_arp_table()
            for i in tab:
                for j in tab:
                    if i["HW address"] == j["HW address"]:
                        if i["IP address"] != j["IP address"]:  # if the ip are not equals, we probably under attack
                            FLAG2 = 1
                            # print("FLAG2 is Up ", FLAG2)
                            return
    # if we are not in Linux os, we will use this method
    else:
        sniff(stop_filter=handle_duplicates)
        FLAG2 = 1
    # print("FLAG2 is Up ",FLAG2)


def handle_check_ping(pkt):     # the third method which checking if we are under attack
    global FLAG3
    if pkt[ARP].op != 2:    # check whether the our arp packet is:"is at" packet, if not we don't need to continue with it...
        return
    r = srp(Ether(dst=pkt[ARP].hwsrc) / IP(dst=pkt[ARP].psrc) / ICMP(), timeout=0.5)
    if len(r[1]) != 0:
        FLAG3 = 1

def check_ping():                   # a call method which call the third method which checking if we are under attack
    global FLAG3
    while FLAG3 != 1:
        time.sleep(0.2)
        sniff(filter="arp", prn=handle_check_ping, count=1)     # sniffing only arp packets
    # print("FLAG3 is Up ",FLAG3)


def handle_active_defender(pkt):        # bonus method, which prevent the arp attack on our computer
    if pkt[ARP].op == 2 and my_ip == pkt[ARP].pdst and my_mac == pkt[ARP].hwdst:
        r = sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=pkt[ARP].psrc, psrc=my_ip, hwsrc=my_mac))

def active_defender():      # a call method which call the bonus method which prevent the arp attack on our computer
    sniff(filter="arp", prn=handle_active_defender, count=1)        # sniffing only arp packets


def warning(m1, m2, m3):    # a method which always checking whether we have at the moment 2 or more than 2 active FLAGs
    global FLAG1
    global FLAG2
    global FLAG3
    while 1 == 1:
        if FLAG1+FLAG2+FLAG3 >= 2:  # if we indeed have 2 or more than 2 active FLAGs, we will alert and stop the system
            if m1.is_alive():
                m1.join(timeout=0)
            if m2.is_alive():
                m2.join(timeout=0)
            if m3.is_alive():
                m3.join(timeout=0)
            print("WARNING YOU ARE UNDER ATTACK!", " f1", FLAG1, "f2", FLAG2, "f3", FLAG3)
            # after we discover that we are under attack, we will activate the defender program, which prevent the attack
            while 1 == 1:
                active_defender()
            sys.exit("WARNING YOU ARE UNDER ATTACK!")


def main():         # the main method, which start all the Threads, and methods
    check_is_at_THREAD = Thread(target=check_is_at)
    check_for_duplicates_THREAD=Thread(target=check_for_duplicates)
    check_ping_THREAD=Thread(target=check_ping)
    warn_thread = Thread(target=warning, args=[check_is_at_THREAD, check_for_duplicates_THREAD, check_ping_THREAD])
    warn_thread.start()
    check_is_at_THREAD.start()
    check_for_duplicates_THREAD.start()
    check_ping_THREAD.start()


if __name__ == '__main__':      # start the main method
    main()
