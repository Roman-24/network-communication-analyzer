
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

        user_input = int(user_input) # sem ešte treba ošetriť trycache

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
            print("Novell 802.3 RAW")
        elif raw_ramec[14] == 0xAA:
            print("IEEE 802.3 LLC + SNAP")
        else:
            print("IEEE 802.3 LLC")
    else:
        print("Ethernet II")
    pass

# uloha 1d
def print_MAC_address(raw_ramec):
    raw_ramec = raw_ramec.hex()
    print("Zdrojová MAC adresa: " + raw_ramec[12:14] + ":" + raw_ramec[14:16] + ":" + raw_ramec[16:18] + ":" + raw_ramec[18:20] + ":" + raw_ramec[20:22] + ":" + raw_ramec[22:24])
    print("Cieľová MAC adresa: " + raw_ramec[0:2] + ":" + raw_ramec[2:4] + ":" + raw_ramec[4:6] + ":" + raw_ramec[6:8] + ":" + raw_ramec[8:10] + ":" + raw_ramec[10:12])

# uloha 2
def find_nested_protocol(raw_ramec):

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

    print(protocol_dict)
    pass

# vypisky k ulohe 1
def ramec_info(ramec, ramec_number):
    print(f"rámec: {ramec_number}")
    raw_ramec = analyze_bajty(ramec)
    # print(raw_ramec)
    print_ramec_len(raw_ramec)
    print_ramec_type(raw_ramec)
    print_MAC_address(raw_ramec)

    # sem este vypis protocolu
    # IPv4, ARP, DTP, IPv6
    protocol = find_nested_protocol(raw_ramec)
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
