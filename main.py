
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

'''
funkcia nacita externy subor obsahuju prokoly a hodnoty a vytvori zneho slovnik
'''
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

arp_ramce = []
icmp_ramce = []
tftp_ramce = []

# vzot slovnik na parsovanie komunikacii
com_info_dict = {
    "source_ip": None,
    "target_ip": None,
    "source_port": None,
    "target_port": None,
    "flags": [],
}

# vsetky_ramce_danej_komunikacie[ poradove cislo, [prislusny ramec, dict_info, mess_info] ]
http_ramce = []
https_ramce = []
telnet_ramce = []
ssh_ramce = []
ftp_control_ramce = []
ftp_data_ramce = []

# citanie ciest k suborom z pomocneho suboru PCAP_FILES_LIST
def useFiles( output_printer, output_file):

    sys.stdout = output_printer
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
        sys.stdout = output_printer
        print("Pre ukoncenie programu napis: e")
        print("Pre vlastnu cestu k suboru zadaj: 0")
        print(f"Pre vyber cisla suboru od 1 do {len(pcap_files_paths)}(vratane)")
        sys.stdout = output_file
        user_input = input()

        if (user_input == "e"):
            print("Exit..")
            output_file.close()
            sys.stdout = output_printer
            print("Exit..")
            exit()

        sys.stdout = output_printer
        try:
            user_input = int(user_input)
        except ValueError:
            print("The input was not a valid integer")
            main()


        if (user_input == 0):

            print("Zadaj relativnu cestu k suboru: ")
            user_path = input()
            return os.path.join(os.path.dirname(__file__), user_path)

        elif (user_input > 0 and user_input <= len(pcap_files_paths)):
            sys.stdout = output_file
            return os.path.join(os.path.dirname(__file__), (pcap_files_paths[user_input - 1])[:-1])

        print("Zly vstup, zadaj znova..")
        sys.stdout = output_file

'''
***** Funkcie pre analýzu a rozbor komunikácie *****
'''

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

    '''
    if item[12] < 0x06:
        if item[14] == 0xFF:
            print("Novell 802.3 RAW")
            elif item[14] == 0xAA:
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
        temp_decimal_value = 256 * raw_ramec[20] + raw_ramec[21]
        nested_protocol = protocols_dict.get(('Ethertypes', temp_decimal_value), "Neznámy Ethertype 0x{:04x}".format(temp_decimal_value))


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
        temp_decimal_value = 256 * raw_ramec[12] + raw_ramec[13]
        nested_protocol = protocols_dict.get(('Ethertypes', temp_decimal_value), "Neznámy Ethertype 0x{:04x}".format(temp_decimal_value))

    return nested_protocol

# potebne k ulohe 3, uloha 3
def find_IP(raw_ramec):
    source_ip = str(int(raw_ramec[26:27].hex(), 16)) + "." + str(int(raw_ramec[27:28].hex(), 16)) + "." + str(int(raw_ramec[28:29].hex(), 16)) + "." + str(int(raw_ramec[29:30].hex(), 16))
    destination_ip = str(int(raw_ramec[30:31].hex(), 16)) + "." + str(int(raw_ramec[31:32].hex(), 16)) + "." + str(int(raw_ramec[32:33].hex(), 16)) + "." + str(int(raw_ramec[33:34].hex(), 16))
    return source_ip, destination_ip


# pomocne funkcie k ulohe 4
def find_next_protocol(raw_ramec, ramec_type, protocol):

    # zistujem co je v IP alebo co je v ARP
    next_protocol = ""

    # ak mam ethernet 2 tak dalej hladam ARP alebo IPv4
    if ramec_type == "Ethernet II":

        temp_decimal_value = 256 * raw_ramec[12] + raw_ramec[13]

        try:
            if protocols_dict['Ethertypes', temp_decimal_value] == "ARP":
                try:
                    next_protocol = protocols_dict['ARP', raw_ramec[21]]
                except KeyError:
                    next_protocol = f"Neznáma ARP operácia {raw_ramec[21]}\n"

            # v IPv4 hladam dalej TCP, UDP, ICMP
            if protocols_dict['Ethertypes', temp_decimal_value] == "IPv4":
                IPv4 = True

                try:
                    next_protocol = protocols_dict['IP', raw_ramec[23]]
                except KeyError:
                    next_protocol = f"Neznamy IP protokol {raw_ramec[23]}"
        except Exception as err:
            next_protocol = ""

    return str(next_protocol)

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
def analyze_next_protocol(raw_ramec, next_protocol, ramec_number, mess, tcp_flags):

    global TCP
    global UDP
    global ICMP
    next_next_protocol = None

    if next_protocol == "TCP":
        TCP = True
    if next_protocol == "UDP":
        UDP = True
    if next_protocol == "ICMP":
        ICMP = True

    if TCP or UDP:

        # zistenie portov pre TCP, UDP
        source_port = int(raw_ramec[34:36].hex(), 16)
        destination_port = int(raw_ramec[36:38].hex(), 16)
        protocol_by_port = min(source_port, destination_port)

        try:
            temp_str = "TCP" if TCP else "UDP"
            next_next_protocol = protocols_dict.get((temp_str, protocol_by_port), "Neznámy port pre určenie protokolu")
            mess += next_next_protocol + "\n"
            mess += f"zdrojový port: {source_port}" + "\n"
            mess += f"cieľový port: {destination_port}"
        except KeyError as err:
            print(err)

        if UDP:
            analyze_TFTP(raw_ramec, ramec_number, source_port, destination_port)
            tftp_ramce.append([ ramec_number, source_port, destination_port, mess, raw_ramec])
            pass

        if next_next_protocol != None:

            source_ip, target_ip = find_IP(raw_ramec)
            ramec_dict_info = {
                "source_ip": source_ip,
                "target_ip": target_ip,
                "source_port": source_port,
                "target_port": destination_port,
                "flags": tcp_flags,
            }

            if next_next_protocol == "HTTP":
                http_ramce.append([raw_ramec, ramec_dict_info, mess])

            elif next_next_protocol == "HTTPS":
                https_ramce.append([raw_ramec, ramec_dict_info, mess])

            elif next_next_protocol == "TELNET":
                telnet_ramce.append([raw_ramec, ramec_dict_info, mess])

            elif next_next_protocol == "SSH":
                ssh_ramce.append([raw_ramec, ramec_dict_info, mess])

            elif next_next_protocol == "FTP CONTROL":
                ftp_control_ramce.append([raw_ramec, ramec_dict_info, mess])

            elif next_next_protocol == "FTP DATA":
                ftp_data_ramce.append([raw_ramec, ramec_dict_info, mess])

    return mess

def analyze_ICMP(raw_ramec):
    index = 14 + (raw_ramec[14] % 16) * 4
    return protocols_dict.get(("ICMP", raw_ramec[index]), "Nerozpoznaný typ\n")

tftp_ports = []
def analyze_TFTP(raw_ramec, ramec_number, source_port, destination_port):

    sixnine = int("0x45", 16)
    global tftp_ports
    porty = [source_port, destination_port]
    porty.sort()

    if destination_port == sixnine:
        tftp_ports.append(porty)
    else:
        for item in tftp_ports:
            if item != None:
                if destination_port in item:
                    if not source_port in item:
                        if destination_port == item[0] and item[1] == sixnine:
                            item[1] = source_port
                        elif item[0] == sixnine:
                            item[0] = source_port
                        item.sort()

    pass

def print_tftp_communication():
    global tftp_ramce
    global tftp_ports
    fsadfdssdf = tftp_ramce
    count = 1
    print("***** Výpis TFTP *****\n")
    if len(tftp_ports) > 0:
        for temp_ports in tftp_ports:

            print("Komunikácia č. ", count)
            # tftp_ramce -> [ ramec_number, source_port, destination_port, mess, raw_ramec ]
            for ramec in tftp_ramce:
                if ramec[1] in temp_ports or ramec[2] in temp_ports:
                    print(ramec[3])
                    print_ramec(ramec[4])
                    print()
                    tftp_ramce.remove(ramec)
                    pass

            count += 1
    else:
        print("Žiadne TFTP komunikácie\n")
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
        "raw_ramec": raw_ramec,
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
                    iterator_com[2].append(1)
                    flag_new = False
                    break
                    pass

            # reply
            elif arp_ramec["operation"] == 2 and arp_ramec["source_protocol_address"] == iterator_com[0]["target_protocol_address"] and arp_ramec["target_protocol_address"] == iterator_com[0]["source_protocol_address"] and arp_ramec["target_hardware_address"] == iterator_com[0]["source_hardware_address"]:
                    iterator_com[1].append(arp_ramec["ramec_number"])
                    iterator_com[2].append(2)
                    flag_new = False
                    break
                    pass

            else:
                flag_new = True

        # vytvorenie novej komunikacie
        if flag_new:

            # dict, cisla ramcov, operation
            one_communication = [ {}, [], [] ]

            # request
            if arp_ramec["operation"] == 1:
                one_communication[0] = arp_ramec
                one_communication[1].append(arp_ramec["ramec_number"])
                one_communication[2].append(1)
                communications.append(one_communication)
                pass

            # reply
            # nemalo by nikdy nastat
            if arp_ramec["operation"] == 2:
                one_communication[0] = arp_ramec
                one_communication[1].append(arp_ramec["ramec_number"])
                one_communication[2].append(2)
                communications.append(one_communication)
                pass

    return communications

def print_ARP_communications(communications):

    count = 1
    for communication in communications:

        if(len(communication[1]) > 0):

            print("Komunikácia č. ", count)
            index = 0

            for i in communication[2]:
                if i == 1:
                    for i_temp in arp_ramce:
                        if i_temp["ramec_number"] == communication[1][index]:
                            my_ramec = i_temp["raw_ramec"]

                    mess = "ARP-request," + "IP adresa: " + communication[0]["target_protocol_address"] + ", MAC adresa: ???" + "\n"
                    mess += "Zdrojová IP: " + communication[0]["source_protocol_address"] + ", Cieľová IP: " + communication[0]["target_protocol_address"] + "\n"
                    mess += "rámec " + str(communication[1][index]) + "\n"
                    mess += communication[0]["ramec_type"] + "\n"
                    mess += communication[0]["protocol"] + "\n"
                    mess += "Zdrojová MAC adresa: " + communication[0]["source_hardware_address"] + "\n"
                    mess += "Cieľová MAC adresa: " + communication[0]["target_hardware_address"]
                    print(mess)
                    print_ramec(my_ramec)
                    print()
                index += 1

            index = 0
            for i in communication[2]:
                if i == 2:
                    for i_temp in arp_ramce:
                        if i_temp["ramec_number"] == communication[1][index]:
                            my_ramec = i_temp["raw_ramec"]

                    mess_late = "ARP-reply," + "IP adresa: " + communication[0]["target_protocol_address"] + ", MAC adresa: " + communication[0]["target_hardware_address"] + "\n"
                    mess_late += "Zdrojová IP: " + communication[0]["target_protocol_address"] + ", Cieľová IP: " + communication[0]["source_protocol_address"] + "\n"
                    mess_late += "rámec " + str(communication[1][index]) + "\n"
                    mess_late += communication[0]["ramec_type"] + "\n"
                    mess_late += communication[0]["protocol"] + "\n"
                    mess_late += "Zdrojová MAC adresa: " + communication[0]["target_hardware_address"] + "\n"
                    mess_late += "Cieľová MAC adresa: " + communication[0]["source_hardware_address"]
                    print(mess_late)
                    print_ramec(my_ramec)
                    print()
                index += 1

            count += 1
    pass


def analyze_flags(raw_ramec):

    info = []

    ack = int(raw_ramec[42:46].hex(), 16)
    sn = int(raw_ramec[38:42].hex(), 16)

    raw_ramec_temp = raw_ramec.hex()
    # IP_total_length - IP_header_length - TCP_header_length
    length = int(raw_ramec_temp[16 * 2:18 * 2], 16) - int(raw_ramec_temp[(14 * 2) + 1:15 * 2], 16) * 4 - int(raw_ramec_temp[46 * 2:(47 * 2) - 1], 16) * 4

    info.append(ack)
    info.append(sn)
    info.append(length)

    #flags decimalne
    FIN = 1
    SYN = 2
    RST = 4
    PSH = 8
    ACK = 16

    flags = []
    flag = int(raw_ramec[46+1:48].hex(), 16)

    if flag & ACK:
        flags.append('ACK')
    if flag & PSH:
        flags.append('PSH')
    if flag & RST:
        flags.append('RST')
    if flag & SYN:
        flags.append('SYN')
    if flag & FIN:
        flags.append('FIN')
    if (len(flags) == 0):
        flags.append('OTHERS')

    return flags

# vypisky k ulohe 4
def ramec_info4(ramec, ramec_number):

    mess_info = f"rámec: {ramec_number}\n"
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

    if protocol == "IPv4":
        # alalyze IPv4, IPcky a pocty uzlov
        mess_info += print_IPv4_addresses(raw_ramec, protocol) + "\n"

    # hlbsia analyza protokolov
    # moze byt: ICMP, TCP, UDP
    if ETH2:
        next_protocol = find_next_protocol(raw_ramec, ramec_type, protocol)
        mess_info += next_protocol + "\n"

        if next_protocol != None:

            if next_protocol == "ICMP":
                # Echo request, Echo reply, a pod.
                mess_info += analyze_ICMP(raw_ramec)
                icmp_ramce.append(mess_info)
                pass
            elif next_protocol == "TCP":
                # hladaj dalej
                # HTTP, HTTPS, TELNET, SSH, FTPr, FTPd

                tcp_flags = analyze_flags(raw_ramec)

                mess_info = analyze_next_protocol(raw_ramec, next_protocol, ramec_number, mess_info, tcp_flags)
                pass
            elif next_protocol == "UDP":
                # hladaj dalej
                # TFTP
                mess_info = analyze_next_protocol(raw_ramec, next_protocol, ramec_number, mess_info, None)
                pass

    print(mess_info)
    print_ramec(raw_ramec)
    print("\n", end="")
    pass

def print_communication_list(communication):
    print("***** Výpis ICMP *****\n")
    for i in communication:
        print(i + "\n")
    pass


def parse_tcp_communications(ramce):

    my_communications = []
    new = True

    for ramec in ramce:

        for com in my_communications:

            if com[0][1]["source_ip"] == ramec[1]["target_ip"] and com[0][1]["source_port"] == ramec[1]["target_port"]:
                com.append(ramec)
                new = False
                break
            else:
                new = True

        if new:
            my_communications.append([ramec])

    return my_communications

def print_tcp_communications(my_communications):

    # najdi komunikaciu
    my_communications = parse_tcp_communications(my_communications)

    # najst zaciatok komunikacie

    search_in_progress = False

    for com in my_communications:

        # handshake start
        if "SYN" in com[0][1]["flags"] and not search_in_progress:
            search_in_progress = True
            pass

        # handshake start check
        if "SYN" in com[1]["flags"] and "ACK" in com[1]["flags"] and not search_in_progress:
            
            pass
        # existuje zaciatok ? existuje koniec ?

        # nasla sa kompletna komunikacia

        # neexistuje zaciatok nehladaj koniec

    # nasla sa kompletna alebo nekompletna komunikacia


    print("***** Komunikacia kompletna *****")

    print("***** Komunikacia nekompletna *****")

    pass

def main():

    # odchytenie vystupu do variable
    output_printer = sys.stdout
    output_file = open("vystup.txt", 'w')

    pcap_file_for_use = useFiles( output_printer, output_file)

    # main loop
    global ip_counter
    while pcap_file_for_use != None:

        print("Actual file: " + pcap_file_for_use + "\n")
        sys.stdout = output_file

        # open and read the pcap file
        ramce = None
        try:
            ramce = rdpcap(pcap_file_for_use)
        except Exception as err:
            sys.stdout = output_printer
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
        print("\nIP adresy vysielajúcich uzlov:")
        for i in ip_counter:
            print(i)

        # najpocetnejsi odoslany
        print("Adresa uzla s najväčším počtom odoslaných paketov:")
        print(f"{ip_counter.most_common(1)[0][0]}\t{ip_counter.most_common(1)[0][1]} paketov \n")
        reset_counter()

        sys.stdout = output_printer
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
              "e žiadne\n")
        sys.stdout = output_file
        user_input = input()

        if (user_input == "e"):
            print("Tak možno nabudúce..")

        try:
            user_input = int(user_input)

            if user_input == 1:
                print("***** Analýza ARP *****\n")
                number = 0
                temp_arp_comms = analyze_ARP()
                if len(temp_arp_comms) > 0:
                    print_ARP_communications(temp_arp_comms)
                else:
                    print("Žiadne ARP komunikácie\n")
            elif user_input == 2:
                print_communication_list(icmp_ramce)

            elif user_input == 3:
                print_tcp_communications(http_ramce)
            elif user_input == 4:
                print_tcp_communications(https_ramce)
            elif user_input == 5:
                print_tcp_communications(telnet_ramce)
            elif user_input == 6:
                print_tcp_communications(ssh_ramce)
            elif user_input == 7:
                print_tcp_communications(ftp_control_ramce)
            elif user_input == 8:
                print_tcp_communications(ftp_data_ramce)

            elif user_input == 9:
                print_tftp_communication()

        except ValueError:
            sys.stdout = output_printer
            print("The input was not a valid integer")
            sys.stdout = output_file

        arp_ramce.clear()
        icmp_ramce.clear()
        http_ramce.clear()
        https_ramce.clear()
        telnet_ramce.clear()
        ssh_ramce.clear()
        ftp_control_ramce.clear()
        ftp_data_ramce.clear()
        tftp_ramce.clear()

        pcap_file_for_use = useFiles(output_printer, output_file)

def reset_counter():
    global ip_counter
    ip_counter = Counter()

def print_ramec(raw_ramec):
    raw_ramec = raw_ramec.hex()
    n = 0
    for iter in range(len(raw_ramec)):
        n += 1
        if n % 32 == 0:
            print(raw_ramec[iter])
        else:
            if n % 16 == 0:
                print(raw_ramec[iter], end="  ")
            elif n % 2 == 0:
                print(raw_ramec[iter], end=" ")
            else:
                print(raw_ramec[iter], end="")
    print()

if __name__ == '__main__':
    print('** PyCharm starting.. **')
    main()
# end of program