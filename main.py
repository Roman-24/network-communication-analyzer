
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

    for iterator, line in enumerate(pcap_files_paths, 1):
        print("{:03}: {}".format(iterator, line), end="")

    while True:
        print("Pre ukoncenie programu napis: e")
        print("Pre vlastnu cestu k suboru zadaj: 0")
        print(f"Pre vyber cisla suboru od 1 do {len(pcap_files_paths) - 1}(vratane)")

        user_input = input()

        if (user_input == "e"):
            print("Exit..")
            exit()

        user_input = int(user_input) # sem este treba osetrit trycache

        if (user_input == 0):
            print("Zadaj relativnu cestu k suboru: ")
            user_path = input()
            return os.path.join(os.path.dirname(__file__), user_path)

        if (user_input > 0 and user_input < len(pcap_files_paths)):
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
def print_ramec_type(raw_ramec):

    print("Typ rámca: ", end="")

    if raw_ramec[12] < 0x06:
        if raw_ramec[14] == 0xFF:
            remec_type = "Novell 802.3 RAW"
        elif raw_ramec[14] == 0xAA:
            remec_type = "IEEE 802.3 LLC + SNAP"
        else:
            remec_type = "IEEE 802.3 LLC"
    else:
        remec_type = "Ethernet II"

    print(remec_type)
    return remec_type
    pass

# uloha 1d
def print_MAC_address(raw_ramec):
    raw_ramec = raw_ramec.hex()
    print("Zdrojová MAC adresa: " + raw_ramec[12:14] + ":" + raw_ramec[14:16] + ":" + raw_ramec[16:18] + ":" + raw_ramec[18:20] + ":" + raw_ramec[20:22] + ":" + raw_ramec[22:24])
    print("Cieľová MAC adresa: " + raw_ramec[0:2] + ":" + raw_ramec[2:4] + ":" + raw_ramec[4:6] + ":" + raw_ramec[6:8] + ":" + raw_ramec[8:10] + ":" + raw_ramec[10:12])

# uloha 2
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
    protocol_from_ramec = raw_ramec[(12 * 2):(14 * 2)].hex()

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
            # nested_protocol += "DSAP "
            nested_protocol = protocols_dict['SAPs', raw_ramec[14]]
            # nested_protocol += "SSAP "
            nested_protocol += protocols_dict['SAPs', raw_ramec[15]]
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

# vypisky k ulohe 1
def ramec_info(ramec, ramec_number):

    print(f"rámec: {ramec_number}")
    raw_ramec = analyze_bajty(ramec)

    print_ramec_len(raw_ramec)

    ramec_type = print_ramec_type(raw_ramec)

    print_MAC_address(raw_ramec)

    # vnoreny protokol
    protocols_dict = creat_protocols_dict()
    protocol = find_nested_protocol(raw_ramec, ramec_type, protocols_dict)
    print(protocol)

    hexdump(raw_ramec)
    print("\n", end="")
    pass

def main():

    # odchytenie vystupu do variable
    origOutput = sys.stdout

    pcap_file_for_use = useFiles()

    # main loop
    while pcap_file_for_use != None:

        print("Actual file: " + pcap_file_for_use)

        # open and read the pcap file
        ramce = None
        try:
            ramce = rdpcap(pcap_file_for_use)
        except Exception as err:
            print(err)

        # ak mam nacitane ramce z pcap file
        if(ramce != None):

            i = 1

            for ramec in ramce:
                ramec_number = i
                ramec_info(ramec, ramec_number)
                i += 1


        pcap_file_for_use = useFiles()


if __name__ == '__main__':
    print('** PyCharm starting.. **')
    main()
# end of program
