
import os
import sys
import collections
import datetime
import csv
import requests
from scapy.all import *
import random
from collections import Counter
# pip install numpy
# pip install pandas
# pip install matplotlib
# pip install requests

# konstanty pre subory
PCAP_FILES_LIST = "zoznamVstupnychFiles.txt"
PROTOCOLS_LIST = "protocols.txt"

# citanie ciest k suborom z pomocneho suboru PCAP_FILES_LIST
def useFiles():

    # z relativnej cesty k suboru sa vytvori relativna cesta zacinajuca v priecinku kodu
    path_to_pcap_file = os.path.join(os.path.dirname(__file__), PCAP_FILES_LIST)

    print("PCAP_FILES_LIST is: " + path_to_pcap_file)

    # vytiahnutie vsetkych pcap subor z pomocneho suboru PCAP_FILES_LIST
    temp_file = open(path_to_pcap_file, "r")
    pcap_files_paths = temp_file.readlines()
    temp_file.close()

    for i, line in enumerate(pcap_files_paths, 1):
        print(f"{i}: {line}", end="")

    while True:
        print("Pre ukoncenie programu napis: e")
        print("Pre vlastnu cestu k suboru zadaj: 0")
        print(f"Pre vyber cisla suboru od 1 do {len(pcap_files_paths)}(vratane)")

        user_input = input()

        if (user_input == "e"):
            print("Exit..")
            exit()

        try: # sem este treba osetrit trycache
            user_input = int(user_input)
        except ValueError:
            print("The input was not a valid integer")
            main()

        if (user_input == 0):
            print("Zadaj relativnu cestu k suboru: ")
            user_path = input()
            return os.path.join(os.path.dirname(__file__), user_path)

        elif (user_input > 0 and user_input <= len(pcap_files_paths)):
            return os.path.join(os.path.dirname(__file__), (pcap_files_paths[user_input - 1])[:-1])

        print("Zly vstup, zadaj znova..")


'''
***** Funkcie pre analýzu a rozbor komunikácie *****
'''

def analyze_bajty(ramec):
    return raw(ramec)

# uloha 1b
def print_ramec_len(raw_ramec):

    len_of_raw_ramec = len(raw_ramec)

    print(f"dĺžka rámca poskytnutá pcap API - {len_of_raw_ramec} B")

    if (len_of_raw_ramec <= 60):
        len_of_raw_ramec = 64
    else:
        len_of_raw_ramec += 4

    print(f"dĺžka rámca prenášaného po médiu - {len_of_raw_ramec} B")
    pass

# uloha 1c
def analyze_ramec_type(raw_ramec):

    print("Typ rámca: ", end="")

    if raw_ramec[12] < 0x06:
        if raw_ramec[14] == 0xFF:
            ramec_type = "Novell 802.3 RAW"
        elif raw_ramec[14] == 0xAA:
            ramec_type = "IEEE 802.3 LLC + SNAP"
        else:
            ramec_type = "IEEE 802.3 LLC"
    else:
        ramec_type = "Ethernet II"

    return ramec_type
    pass

# uloha 1d
def print_MAC_address(raw_ramec):
    raw_ramec = raw_ramec.hex()
    print("Zdrojová MAC adresa: " + raw_ramec[12:14] + ":" + raw_ramec[14:16] + ":" + raw_ramec[16:18] + ":" + raw_ramec[18:20] + ":" + raw_ramec[20:22] + ":" + raw_ramec[22:24])
    print("Cieľová MAC adresa: " + raw_ramec[0:2] + ":" + raw_ramec[2:4] + ":" + raw_ramec[4:6] + ":" + raw_ramec[6:8] + ":" + raw_ramec[8:10] + ":" + raw_ramec[10:12])


# potrebne pre ulohu 2
def creat_protocols_dict():

    protocol_dict = {} # create a Dictionary
    with open(PROTOCOLS_LIST, 'r') as protocol_file:
        while True:
            line = protocol_file.readline()

            if line.startswith("#"):
                protocol_name = line.split()[0][1:]
            elif not line:
                break
            else:
                key, value = line.split(" ", 1)  # splitujem to cez medzeru a iba jedna vec potom nasleduje lebo nazov je jeden ks
                protocol_dict[protocol_name, int(key, 16)] = value[:-1]
                # protocol_dict[protocol_name, key] = value[:-1]
        return protocol_dict

'''
    protocol_from_ramec = raw_ramec[(12):(14)].hex()

    with open(PROTOCOLS_LIST, 'r') as protocol_file:
        while True:
            line = protocol_file.readline()

            if line.startswith("#"):
                continue
            elif not line:
                break
            else:
                protocol_key, protocol_name = line.split(" ", 1)
                protocol_name = protocol_name[:-1]
                if protocol_key == protocol_from_ramec:
                    print(protocol_name.rstrip())
    pass
'''

# k ulohe 2
def find_nested_protocol(raw_ramec, ramec_type, protocols_dict):

    nested_protocol = ""

    if ramec_type == "Novell 802.3 RAW":
        nested_protocol = "IPX"

    elif ramec_type == "IEEE 802.3 LLC + SNAP":
        num2021 = 256 * raw_ramec[20] + raw_ramec[21]
        try:
            nested_protocol = protocols_dict['Ethertypes', num2021]
        except KeyError:
            nested_protocol = "Neznámy Ethertype 0x{:04x}".format(num2021)

    elif ramec_type == "IEEE 802.3 LLC":
        try:
            nested_protocol += "DSAP " + protocols_dict['SAPs', raw_ramec[14]]
            nested_protocol += "\n"
            nested_protocol += "SSAP " + protocols_dict['SAPs', raw_ramec[15]]
        except KeyError:
            nested_protocol = "Neznámy SAP 0x{:02x}".format(raw_ramec[14])

    # Ethernet II
    else:
        num1213 = 256 * raw_ramec[12] + raw_ramec[13]
        try:
            nested_protocol = protocols_dict['Ethertypes', num1213]
        except KeyError:
            nested_protocol = "Neznámy Ethertype 0x{:04x}".format(num1213)

    return nested_protocol


# potebne k ulohe 3, uloha 3
def find_IP(raw_ramec):
    raw_ramec = raw_ramec.hex()
    source_ip = str(int(raw_ramec[26 * 2:27 * 2], 16)) + "." + str(int(raw_ramec[27 * 2:28 * 2], 16)) + "." + str(int(raw_ramec[28 * 2:29 * 2], 16)) + "." + str(int(raw_ramec[29 * 2:30 * 2], 16))
    destination_ip = str(int(raw_ramec[30 * 2:31 * 2], 16)) + "." + str(int(raw_ramec[31 * 2:32 * 2], 16)) + "." + str(int(raw_ramec[32 * 2:33 * 2], 16)) + "." + str(int(raw_ramec[33 * 2:34 * 2], 16))
    return source_ip, destination_ip


# vypisky k ulohe 1
def ramec_info(ramec, ramec_number):

    print(f"rámec: {ramec_number}")
    raw_ramec = analyze_bajty(ramec)

    print_ramec_len(raw_ramec)

    ramec_type = analyze_ramec_type(raw_ramec)
    print(ramec_type)

    print_MAC_address(raw_ramec)

    hexdump(raw_ramec)
    print("\n", end="")
    pass

# vypisky k ulohe 2
def ramec_info2(ramec, ramec_number):

    print(f"rámec: {ramec_number}")
    raw_ramec = analyze_bajty(ramec)

    print_ramec_len(raw_ramec)

    ramec_type = analyze_ramec_type(raw_ramec)
    print(ramec_type)

    print_MAC_address(raw_ramec)

    # vnoreny protokol
    protocols_dict = creat_protocols_dict()
    protocol = find_nested_protocol(raw_ramec, ramec_type, protocols_dict)
    print(protocol)

    hexdump(raw_ramec)
    print("\n", end="")
    pass

# vypisky k ulohe 3
def ramec_info3(ramec, ramec_number):

    print(f"rámec: {ramec_number}")
    raw_ramec = analyze_bajty(ramec)

    print_ramec_len(raw_ramec)

    ramec_type = analyze_ramec_type(raw_ramec)
    print(ramec_type)

    print_MAC_address(raw_ramec)

    # vnoreny protokol
    protocols_dict = creat_protocols_dict()
    protocol = find_nested_protocol(raw_ramec, ramec_type, protocols_dict)
    print(protocol)

    # IPcky
    # zoznam IP adries vsetkych odosielajucich uzlov
    global ip_counter
    if protocol == "TCP" or protocol == "IPv4":
        source_ip, destination_ip = find_IP(raw_ramec)

        if protocol == "IPv4":
            if ip_counter[source_ip] == 0:
                ip_counter[source_ip] = 1
            elif ip_counter[source_ip] > 0:
                ip_counter[source_ip] += 1

        print(f"zdrojová IP adresa: {source_ip}")
        print(f"cieľová IP adresa: {destination_ip}")

    # hexdump(raw_ramec)
    print("\n", end="")
    pass

# pomocne funkcie k ulohe 4
def find_next_protocol(raw_ramec, ramec_type, protocol, protocols_dict):

    eth_2 = False

    DLH_off_set = 14
    # 14b pre DLH

    IPv4 = False
    ARP = False

    IP_off_set = 0
    TCP = False
    UDP = False
    ICMP = False

    next_protocol = None
    if ramec_type == "Ethernet II":
        eth_2 = True

    # ak mam ethernet 2 tak dalej hladam ARP a IPv4
    if eth_2:

        num1213 = 256 * raw_ramec[12] + raw_ramec[13]

        try:
            if protocols_dict['Ethertypes', num1213] == "ARP":
                ARP = True
                try:
                    next_protocol = protocols_dict['ARP', raw_ramec[21]]
                except KeyError:
                    print(f"Neznáma ARP operácia {raw_ramec[21]}\n")

            # v IPv4 hladam dalej TCP, UDP, ICMP
            if protocols_dict['Ethertypes', num1213] == "IPv4":
                IPv4 = True

                try:
                    next_protocol = protocols_dict['IP', raw_ramec[23]]
                except KeyError:
                    print(f"Neznamy IP protokol {raw_ramec[23]}")
        except Exception as err:
            print(err)

    return next_protocol

def print_IPv4_addresses(raw_ramec, protocol):
    # IPcky
    # zoznam IP adries vsetkych odosielajucich uzlov
    global ip_counter
    if protocol == "TCP" or protocol == "IPv4":
        source_ip, destination_ip = find_IP(raw_ramec)

        if protocol == "IPv4":
            if ip_counter[source_ip] == 0:
                ip_counter[source_ip] = 1
            elif ip_counter[source_ip] > 0:
                ip_counter[source_ip] += 1

        print(f"zdrojová IP adresa: {source_ip}")
        print(f"cieľová IP adresa: {destination_ip}")

    pass

# analyze ARP, TCP, UDP, ICMP
def analyze_next_protocol(raw_ramec, next_protocol, protocols_dict):

    TCP = False
    UDP = False
    ICMP = False

    next_next_protocol = None
    tftp_porty = []
    rip = 0

    # treba zistiť off_set pre IP adresu

    if next_protocol == "TCP":
        # bude pokracovat vypisom TCP
        TCP = True
    if next_protocol == "UDP":
        # bude pokracovat vypisom UDP
        UDP = True
    if next_protocol == "ICMP":
        # bude pokracovat vypisom ICMP
        ICMP = True

    if TCP or UDP:

        # zistenie portov pre TCP, UDP
        raw_ramec = raw_ramec.hex()
        source_port = int(raw_ramec[34*2:36*2], 16)
        destination_port = int(raw_ramec[36*2:38*2], 16)

        protocol_by_port = min(source_port, destination_port)

        try:
            temp_str = "TCP" if TCP else "UDP"
            next_next_protocol = protocols_dict[temp_str, protocol_by_port]
        except KeyError:
            print("Neznámy port pre určenie protokolu")

        if next_next_protocol != None:
            print(next_next_protocol)

        print(f"zdrojový port: {source_port}")
        print(f"cieľový port: {destination_port}")

        # sem este nejaky vypis podla portov ci co to

    return

# vypisky k ulohe 4
def ramec_info4(ramec, ramec_number):

    print(f"rámec: {ramec_number}")
    raw_ramec = analyze_bajty(ramec)

    print_ramec_len(raw_ramec)

    ramec_type = analyze_ramec_type(raw_ramec)
    print(ramec_type)

    print_MAC_address(raw_ramec)

    # vnoreny protokol
    protocols_dict = creat_protocols_dict()
    protocol = find_nested_protocol(raw_ramec, ramec_type, protocols_dict)
    print(protocol)

    # alalyze IPv4, IPcky a pocty uzlov
    print_IPv4_addresses(raw_ramec, protocol)

    # hlbsia analyza protokolov
    next_protocol = find_next_protocol(raw_ramec, ramec_type, protocol, protocols_dict)
    if next_protocol != None:
        print(next_protocol)

    # analyze ARP, TCP, UDP, ICMP
    if protocol == "IPv4":
        analyze_next_protocol(raw_ramec, next_protocol, protocols_dict)
    elif protocol == "ARP":
        # analyze_ARP()
        pass

    # hexdump(raw_ramec)
    print("\n", end="")
    pass


# potrebne globalne premenne:
ip_counter = Counter()

def main():

    # odchytenie vystupu do variable
    origOutput = sys.stdout

    pcap_file_for_use = useFiles()

    # main loop
    global ip_counter
    while pcap_file_for_use != None:

        print("Actual file: " + pcap_file_for_use + "\n")

        # open and read the pcap file
        ramce = None
        try:
            ramce = rdpcap(pcap_file_for_use)
        except Exception as err:
            print(err)
            print()
            main()

        # ak mam nacitane ramce z pcap file
        if ramce != None:

            i = 1
            for ramec in ramce:
                ramec_number = i
                ramec_info4(ramec, ramec_number)
                i += 1

        # zoznam odosielajúcich uzlov
        print("IP adresy vysielajúcich uzlov:")
        for i in ip_counter:
            print(i)

        # najpocetnejsi odoslany
        print("Adresa uzla s najväčším počtom odoslaných paketov:")
        print(f"{ip_counter.most_common(1)[0][0]}\t{ip_counter.most_common(1)[0][1]} paketov \n")
        reset_counter()

        pcap_file_for_use = useFiles()

def reset_counter():
    global ip_counter
    ip_counter = Counter()

if __name__ == '__main__':
    print('** PyCharm starting.. **')
    main()
# end of program