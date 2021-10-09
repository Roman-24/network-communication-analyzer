
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

def creat_protocols_dict():

    protocols_dict = {} # create a Dictionary
    with open(PROTOCOLS_LIST, 'r') as protocol_file:
        while True:
            line = protocol_file.readline()

            if line.startswith("#"):
                protocol_name = line.split()[0][1:]
            elif not line:
                break
            else:
                key, value = line.split(" ", 1)  # splitujem to cez medzeru a iba jedna vec potom nasleduje lebo nazov je jeden ks
                protocols_dict[protocol_name, int(key, 16)] = value[:-1]

    return protocols_dict


# potrebne globalne premenne:
protocols_dict = creat_protocols_dict()
ip_counter = Counter()

RAW = False
SNAP = False
LLC = False
ETH2 = False

IP = False
IPv4 = False
ARP = False

ICMP = False
TCP = False
UDP = False

HTTP = False
HTTPs = False
TELNET = False
SSH = False
FTPr = False
FTPd = False
TFTP = False

# vsetky_ramce_danej_komunikacie[ [prislusny ramec], [cislo prislusneho ramca] ]
# arp_ramce = [[], []]
arp_ramce = []
icmp_ramce = [[], []]
http_ramce = [[], []]
https_ramce = [[], []]
telnet_ramce = [[], []]
ssh_ramce = [[], []]
ftp_control_ramce = [[], []]
ftp_data_ramce = [[], []]
tftp_ramce = [[], []]

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
# najdenie key podla value
def search_protocol_name(my_value):
    try:
        return [key for key, value in protocols_dict.items() if value == my_value]
    except Exception:
        return None

def analyze_bajty(ramec):
    return raw(ramec)

def ramec_len(raw_ramec):

    len_of_raw_ramec = len(raw_ramec)
    len_of_raw_ramec_4 = None

    if (len_of_raw_ramec <= 60):
        len_of_raw_ramec_4 = 64
    else:
        len_of_raw_ramec_4 = len_of_raw_ramec + 4

    return len_of_raw_ramec, len_of_raw_ramec_4

def print_ramec_len(len_of_raw_ramec, len_of_raw_ramec_4):
    mess_1 = f"dĺžka rámca poskytnutá pcap API - {len_of_raw_ramec} B" + "\n"
    mess_2 = f"dĺžka rámca prenášaného po médiu - {len_of_raw_ramec_4} B"
    return mess_1 + mess_2

def analyze_ramec_type(raw_ramec):

    global ETH2
    # kontrolny vypisok
    '''
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
    '''

    if raw_ramec[12] < 0x06:
        ramec_type = protocols_dict.get(("frameType", raw_ramec[14]), "IEEE 802.3 LLC")
    else:
        ramec_type = "Ethernet II"
        ETH2 = True

    return ramec_type

def MAC_address(raw_ramec):
    raw_ramec = raw_ramec.hex()
    source_mac = raw_ramec[12:14] + ":" + raw_ramec[14:16] + ":" + raw_ramec[16:18] + ":" + raw_ramec[18:20] + ":" + raw_ramec[20:22] + ":" + raw_ramec[22:24]
    target_mac = raw_ramec[0:2] + ":" + raw_ramec[2:4] + ":" + raw_ramec[4:6] + ":" + raw_ramec[6:8] + ":" + raw_ramec[8:10] + ":" + raw_ramec[10:12]
    return source_mac, target_mac

def print_MAC_address(source_mac, target_mac):
    mess_1 = "Zdrojová MAC adresa: " + source_mac + "\n"
    mess_2 = "Cieľová MAC adresa: " + target_mac
    return mess_1 + mess_2

# k ulohe 2
def find_nested_protocol(raw_ramec, ramec_type):
    global RAW
    global SNAP
    global LLC
    nested_protocol = ""

    if ramec_type == "Novell 802.3 RAW":
        RAW = True
        nested_protocol = "IPX"

    elif ramec_type == "IEEE 802.3 LLC + SNAP":
        SNAP = True
        num2021 = 256 * raw_ramec[20] + raw_ramec[21]
        try:
            nested_protocol = protocols_dict['Ethertypes', num2021]
        except KeyError:
            nested_protocol = "Neznámy Ethertype 0x{:04x}".format(num2021)

    elif ramec_type == "IEEE 802.3 LLC":
        LLC = True
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


# vypisky k ulohe 3
def ramec_info3(ramec, ramec_number):

    mess_info = f"rámec: {ramec_number}"
    raw_ramec = analyze_bajty(ramec)

    len_of_raw_ramec, len_of_raw_ramec_4 = ramec_len(raw_ramec)
    mess_info += print_ramec_len(len_of_raw_ramec, len_of_raw_ramec_4) + "\n"

    ramec_type = analyze_ramec_type(raw_ramec)
    mess = "Typ rámca: " + ramec_type + "\n"

    source_mac, target_mac = MAC_address(raw_ramec)
    mess_info += print_MAC_address(source_mac, target_mac) + "\n"

    # vnoreny protokol
    protocol = find_nested_protocol(raw_ramec, ramec_type)
    mess_info += protocol + "\n"

    # IPcky
    # zoznam IP adries vsetkych odosielajucich uzlov
    global ip_counter
    if protocol == "TCP" or protocol == "IPv4":
        source_ip, destination_ip = find_IP(raw_ramec)

        # ip counter
        if protocol == "IPv4":
            if ip_counter[source_ip] == 0:
                ip_counter[source_ip] = 1
            elif ip_counter[source_ip] > 0:
                ip_counter[source_ip] += 1

        mess_info += f"zdrojová IP adresa: {source_ip}" + "\n"
        mess_info += f"cieľová IP adresa: {destination_ip}"

    print(mess_info)
    # hexdump(raw_ramec)
    print("\n", end="")
    pass

# pomocne funkcie k ulohe 4
def find_next_protocol(raw_ramec, ramec_type, protocol):

    # zistujem co je v IP alebo co je v ARP

    eth_2 = False
    next_protocol = None

    if ramec_type == "Ethernet II":
        eth_2 = True

    # ak mam ethernet 2 tak dalej hladam ARP alebo IPv4
    if eth_2:

        num1213 = 256 * raw_ramec[12] + raw_ramec[13]

        try:
            if protocols_dict['Ethertypes', num1213] == "ARP":
                try:
                    next_protocol = protocols_dict['ARP', raw_ramec[21]]
                except KeyError:
                    next_protocol = f"Neznáma ARP operácia {raw_ramec[21]}\n"

            # v IPv4 hladam dalej TCP, UDP, ICMP
            if protocols_dict['Ethertypes', num1213] == "IPv4":
                IPv4 = True

                try:
                    next_protocol = protocols_dict['IP', raw_ramec[23]]
                except KeyError:
                    next_protocol = f"Neznamy IP protokol {raw_ramec[23]}"
        except Exception as err:
            next_protocol = err

    return next_protocol

def print_IPv4_addresses(raw_ramec, protocol):
    # IPcky
    # zoznam IP adries vsetkych odosielajucich uzlov
    global ip_counter
    mess = ""
    if protocol == "TCP" or protocol == "IPv4":
        source_ip, destination_ip = find_IP(raw_ramec)

        # ip counter
        if protocol == "IPv4":
            if ip_counter[source_ip] == 0:
                ip_counter[source_ip] = 1
            elif ip_counter[source_ip] > 0:
                ip_counter[source_ip] += 1

        mess = f"zdrojová IP adresa: {source_ip}" + "\n"
        mess += f"cieľová IP adresa: {destination_ip}"

    return mess

# hlbsie analyzuje TCP, UDP, ICMP
def analyze_next_protocol(raw_ramec, next_protocol, ramec_number, mess):

    global TCP
    global UDP
    global ICMP
    next_next_protocol = None

    if next_protocol == "TCP":
        # bude pokracovat vypisom TCP
        TCP = True
    if next_protocol == "UDP":
        # bude pokracovat vypisom UDP
        UDP = True
    if next_protocol == "ICMP":
        # bude pokracovat vypisom ICMP
        ICMP = True


    if UDP:
        analyze_TFTP(raw_ramec)
        pass

    if TCP or UDP:

        # zistenie portov pre TCP, UDP
        raw_ramec = raw_ramec.hex()
        source_port = int(raw_ramec[34*2:36*2], 16)
        destination_port = int(raw_ramec[36*2:38*2], 16)

        protocol_by_port = min(source_port, destination_port)

        try:
            temp_str = "TCP" if TCP else "UDP"
            next_next_protocol = protocols_dict[temp_str, protocol_by_port]
            mess += f"zdrojový port: {source_port}" + "\n"
            mess += f"cieľový port: {destination_port}"
        except KeyError:
            mess += "Neznámy port pre určenie protokolu" + "\n"

        if next_next_protocol != None:

            if next_next_protocol == "HTTP":
                http_ramce[0].append(mess)
                http_ramce[1].append(ramec_number)

            elif next_next_protocol == "HTTPS":
                https_ramce[0].append(mess)
                https_ramce[1].append(ramec_number)

            elif next_next_protocol == "TELNET":
                telnet_ramce[0].append(mess)
                telnet_ramce[1].append(ramec_number)

            elif next_next_protocol == "SSH":
                ssh_ramce[0].append(mess)
                ssh_ramce[1].append(ramec_number)

            elif next_next_protocol == "FTP CONTROL":
                ftp_control_ramce[0].append(mess)
                ftp_control_ramce[1].append(ramec_number)

            elif next_next_protocol == "FTP DATA":
                ftp_data_ramce[0].append(mess)
                ftp_data_ramce[1].append(ramec_number)

    return mess

def analyze_ICMP(raw_ramec):
    index = 14 + (raw_ramec[14] % 16) * 4
    return protocols_dict.get( ("ICMP", raw_ramec[index]), "Nerozpoznaný typ\n")

def analyze_TFTP(raw_ramec):

    tftp_comunication = []
    tftp_ports = []
    index = 14 + (raw_ramec[14] % 16) * 4
    source_port = raw_ramec[index] * 256 + raw_ramec[index + 1]
    destination_port = raw_ramec[index + 2] * 256 + raw_ramec[index + 3]

    porty = [source_port, destination_port]

    sixnine = 0x45
    if destination_port == sixnine:
        tftp_ports.append(porty)
    else:
        for temp in tftp_ports:
            if temp[0] != destination_port and temp[1] == source_port:
                if destination_port == temp[0] and temp[1] == 0x45:
                    temp[1] = sixnine
                elif temp[0] == 0x45:
                    temp[0] = sixnine
                temp.sort()

    mess = ""
    try:
        mess += "{}\n".format(protocols_dict['UDP', min(source_port, destination_port)])
    except KeyError:
        if porty in tftp_ports:
            mess += "TFTP\n"
        else:
            mess += "Nerozpoznaný port\n"

    mess += "zdrojový port: {}\n".format(source_port)
    mess += "cieľový port: {}\n".format(destination_port)

    # print(mess)
    pass

def collect_ARP(raw_ramec, ramec_number, ramec_type, protocol):
    raw_ramec_hex = raw_ramec.hex()
    global arp_ramce
    arp_ramce.append({
        "ramec_number": ramec_number,
        "operation": int(raw_ramec_hex[20*2:22*2]),
        "source_hardware_address": raw_ramec_hex[22*2:23*2] + ":" + raw_ramec_hex[23*2:24*2] + ":" + raw_ramec_hex[24*2:25*2] + ":" + raw_ramec_hex[25*2:26*2] + ":" + raw_ramec_hex[26*2:27*2] + ":" + raw_ramec_hex[27*2:28*2],
        "source_protocol_address": str(int(raw_ramec_hex[28*2:29*2], 16)) + "." + str(int(raw_ramec_hex[29*2:30*2], 16)) + "." + str(int(raw_ramec_hex[30*2:31*2], 16)) + "." + str(int(raw_ramec_hex[31*2:32*2], 16)),
        "target_hardware_address": raw_ramec_hex[32*2:33*2] + ":" + raw_ramec_hex[33*2:34*2] + ":" + raw_ramec_hex[34*2:35*2] + ":" + raw_ramec_hex[35*2:36*2] + ":" + raw_ramec_hex[36*2:37*2] + ":" + raw_ramec_hex[37*2:38*2],
        "target_protocol_address": str(int(raw_ramec_hex[38*2:39*2], 16)) + "." + str(int(raw_ramec_hex[39*2:40*2], 16)) + "." + str(int(raw_ramec_hex[40*2:41*2], 16)) + "." + str(int(raw_ramec_hex[41*2:42*2], 16)),
        "ramec_type": ramec_type,
        "protocol": protocol,
    })
    pass

def analyze_ARP():

    global arp_ramce
    flag_new = True
    communications = []

    for arp_ramec in arp_ramce:

        for iterator_com in communications:

            # request
            # ak je to request tak hladam v one_communication ci som nemal nieco co davalo odpoved
            if arp_ramec["operation"] == 1 and arp_ramec["target_protocol_address"] == iterator_com[0]["target_protocol_address"] and arp_ramec["source_protocol_address"] == iterator_com[0]["source_protocol_address"] and arp_ramec["source_hardware_address"] == iterator_com[0]["source_hardware_address"]:
                    iterator_com[1].append(arp_ramec["ramec_number"])
                    flag_new = False
                    break
                    pass

            # reply
            elif arp_ramec["operation"] == 2 and arp_ramec["source_protocol_address"] == iterator_com[0]["target_protocol_address"] and arp_ramec["target_protocol_address"] == iterator_com[0]["source_protocol_address"] and arp_ramec["source_hardware_address"] == iterator_com[0]["target_hardware_address"]:
                    iterator_com[2].append(arp_ramec["ramec_number"])
                    flag_new = False
                    break
                    pass

            else:
                flag_new = True

        # vytvorenie novej komunikacie
        if flag_new:

            # arp_ramec, requests, replies
            one_communication = [[], [], []]

            # request
            if arp_ramec["operation"] == 1:
                one_communication[0] = arp_ramec
                one_communication[1].append(arp_ramec["ramec_number"])
                communications.append(one_communication)
                pass

            # reply
            if arp_ramec["operation"] == 2:
                one_communication[0] = arp_ramec
                one_communication[2].append(arp_ramec["ramec_number"])
                communications.append(one_communication)
                pass

            pass

    return communications

def print_ARP_communications(communications):

    print("***** Analýza ARP *****")
    for communication in communications:

        if(len(communication[1]) > 0):
            mess = "ARP-request," + "IP adresa: " + communication[0]["target_protocol_address"] + ", MAC adresa: ???" + "\n"
            mess += "Zdrojová IP: " + communication[0]["source_protocol_address"] + ", Cieľová IP: " + communication[0]["target_protocol_address"] + "\n"
            mess += "rámec " + str(communication[0]["ramec_number"]) + "\n"
            mess += communication[0]["ramec_type"] + "\n"
            mess += communication[0]["protocol"] + "\n"
            mess += "Zdrojová MAC adresa: " + communication[0]["source_hardware_address"] + "\n"
            mess += "Cieľová MAC adresa: " + communication[0]["target_hardware_address"] + "\n"

            print(mess)
            mess = ""

        if (len(communication[2]) > 0):
            mess = "ARP-reply," + "IP adresa: " + communication[0]["target_protocol_address"] + ", MAC adresa: " + communication[0]["target_hardware_address"] + "\n"
            mess += "Zdrojová IP: " + communication[0]["source_protocol_address"] + ", Cieľová IP: " + communication[0]["target_protocol_address"] + "\n"
            mess += "rámec " + str(communication[0]["ramec_number"]) + "\n"
            mess += communication[0]["ramec_type"] + "\n"
            mess += communication[0]["protocol"] + "\n"
            mess += "Zdrojová MAC adresa: " + communication[0]["source_hardware_address"] + "\n"
            mess += "Cieľová MAC adresa: " + communication[0]["target_hardware_address"] + "\n"

            print(mess)
            mess = ""

    pass

# vypisky k ulohe 4
def ramec_info4(ramec, ramec_number):

    mess_info = f"rámec: {ramec_number}"
    raw_ramec = analyze_bajty(ramec)

    len_of_raw_ramec, len_of_raw_ramec_4 = ramec_len(raw_ramec)
    mess_info += print_ramec_len(len_of_raw_ramec, len_of_raw_ramec_4) + "\n"

    ramec_type = analyze_ramec_type(raw_ramec)
    mess_info += "Typ rámca: " + ramec_type + "\n"

    source_mac, target_mac = MAC_address(raw_ramec)
    mess_info += print_MAC_address(source_mac, target_mac) + "\n"

    # zatial mam toto
    '''
    Novell 802.3 RAW
    IEEE 802.3 LLC + SNAP
    IEEE 802.3 LLC
    Ethernet II
    '''
    # a v tom idem hladat dalej

    # vnoreny protokol pre Ethernet II
    protocol = find_nested_protocol(raw_ramec, ramec_type)
    mess_info += protocol + "\n"
    # IP (IPv4 alebo IPv6)
    # ARP

    # analyze ARP, TCP, UDP, ICMP
    if protocol == "ARP":
        collect_ARP(raw_ramec, ramec_number, ramec_type, protocol)
        pass

    if protocol == "IPv4":
        # alalyze IPv4, IPcky a pocty uzlov
        mess_info += print_IPv4_addresses(raw_ramec, protocol) + "\n"

    # hlbsia analyza protokolov
    # moze byt: ICMP, TCP, UDP
    next_protocol = find_next_protocol(raw_ramec, ramec_type, protocol)
    mess_info += next_protocol + "\n"

    if next_protocol != None:

        if next_protocol == "ICMP":
            # Echo request, Echo reply, Time exceeded, a pod.
            icmp_ramce[0].append(mess_info)
            icmp_ramce[1].append(ramec_number)
            mess_info += analyze_ICMP(raw_ramec) + "\n"
            pass
        elif next_protocol == "TCP":
            # hladaj dalej
            # HTTP, HTTPS, TELNET, SSH, FTPr, FTPd
            mess_info = analyze_next_protocol(raw_ramec, next_protocol, ramec_number, mess_info)
            pass
        elif next_protocol == "UDP":
            # hladaj dalej
            # TFTP
            mess_info = analyze_next_protocol(raw_ramec, next_protocol, ramec_number, mess_info)
            pass

    print(mess_info)
    # hexdump(raw_ramec)
    # print("\n", end="")
    pass


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

        # Analyzovanie ARP komunikacie
        '''
        for analyze_ARP_temp in analyze_ARP():
            print(analyze_ARP_temp)
        print()
        '''

        if arp_ramce:
            print_ARP_communications(analyze_ARP())

        # zoznam odosielajúcich uzlov
        print("IP adresy vysielajúcich uzlov:")
        for i in ip_counter:
            print(i)

        # najpocetnejsi odoslany
        print("Adresa uzla s najväčším počtom odoslaných paketov:")
        print(f"{ip_counter.most_common(1)[0][0]}\t{ip_counter.most_common(1)[0][1]} paketov \n")
        reset_counter()

        print("Aké rámce si praješ vypísať? \n" +
              "1. ARP\n" +
              "2. ICMP\n" +
              "3. HTTP\n" +
              "4. HTTPS\n" +
              "5. TELNET\n" +
              "6. SSH\n" +
              "7. FTP CONTROL\n" +
              "8. FTP DATA\n" +
              "9. TFTP\n" +
              "e žiadne")

        user_input = input()

        if (user_input == "e"):
            print("Tak možno nabudúce..")

        try:
            user_input = int(user_input)

            if user_input == 1:
                print(arp_ramce)
            elif user_input == 2:
                print(icmp_ramce)
            elif user_input == 3:
                print(http_ramce)
            elif user_input == 4:
                print(https_ramce)
            elif user_input == 5:
                print(telnet_ramce)
            elif user_input == 6:
                print(ssh_ramce)
            elif user_input == 7:
                print(ftp_control_ramce)
            elif user_input == 8:
                print(ftp_data_ramce)
            elif user_input == 9:
                print(tftp_ramce)

        except ValueError:
            print("The input was not a valid integer")

        arp_ramce.clear()
        icmp_ramce.clear()
        http_ramce.clear()
        https_ramce.clear()
        telnet_ramce.clear()
        ssh_ramce.clear()
        ftp_control_ramce.clear()
        ftp_data_ramce.clear()
        tftp_ramce.clear()

        '''
        for i in range(len(arp_ramce)):
            print(arp_ramce[i])
        '''
        pcap_file_for_use = useFiles()

def reset_counter():
    global ip_counter
    ip_counter = Counter()

if __name__ == '__main__':
    print('** PyCharm starting.. **')
    main()
# end of program