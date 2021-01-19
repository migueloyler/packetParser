import struct
# COMPSCI 365
# Spring 2020
# YOUR NAME HERE
# Assignment 4: Extraction from Network Traffic

# Complete the relevant functions.
# Make sure to test your implementations.
# You can import any standard library.
# You can define any new function you want.

def extract_passwords(inputFile, N=6):
    """
    Description: Read the given input file and extract valid
    ASCII strings that are at least N characters in length and
    contain no spaces (0x20) from any TCP data segments in the
    packet capture.

    Resources:
    - https://wiki.wireshark.org/Development/LibpcapFileFormat#Packet_Data
    - http://www.deic.uab.es/material/25977-ethernet.pdf
    - https://en.wikipedia.org/wiki/EtherType
    - https://en.wikipedia.org/wiki/IPv4#Header
    - https://en.wikipedia.org/wiki/IPv6_packet#Fixed_header
    - https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
    - https://www.freesoft.org/CIE/Course/Section4/8.htm

    1. The input file will be a packet capture in the libpcap format.
    2. The first 24 bytes will correspond to the PCAP Global Header.
    3.a. The remainder of the bytes will contain packets, segmented
    into packet headers and packet data.
    3.b. Each of these packets will be of the structure:

    PCAP Packet Header (16 bytes)
    OSI Layer 2 - Ethernet Header (14 bytes)
    OSI Layer 3 - IPv4 Header (20 to 60 bytes) OR IPv6 Header (40 bytes)
    OSI Layer 4 - Protocol Header and Data (variable length)

    4. If the protocol extracted from the IP Header is the TCP
    protocol, then read the data offset from the TCP header. If
    the data offset does not go out of bounds of the packet, then
    the TCP packet has data. Extract this data and keep it in a
    running ByteArray object that contains all data you extract. NOTE
    that the data offset is from the start of the TCP header.

    5. After you've extracted all TCP data from the packet capture,
    parse the bytes to extract any and all ASCII-printable strings
    that are >= N characters in length and contain no spaces (0x20).
    Keep these strings in an "extracted passwords" list. Note that
    these strings can be split across multiple TCP packets.

    6. Return this list, or an empty list if you could extract
    no strings.

    It is guaranteed that the Data Link Type (in Global Header) will
    always be Ethernet (0x1) (i.e. Layer 2 will always be Ethernet)
    and the Layer 3 protocol will always be IPv4 or IPv6 (i.e. the
    EtherType in the Ethernet header always 0x0800 or 0x86DD). There
    are no other guarantees.

    Input: string inputFile, int N
    Output: list of strings

    Example 1: extract_passwords("samples/capture1.pcap", N=6) returns:
    Extracted Passwords: ['&&4gk+K`&6', 'RP3jf_', ']B7<nb', 'etcfoS', 'N`t|x!', 'joanclarke', 'p)TE~o', '*a_`(yOh']

    Example 2: extract_passwords("samples/capture2.pcap", N=6) returns:
    Extracted Passwords: ['>ukSo1', '07.N&R', 'y,;!,{}N', "Nw>4<]'", 'A9ka]{', "27*Cru'", 'gracehopper']
    """
    with open(inputFile, 'rb') as inFile:
        pcap = inFile.read()
        CAPLEN = len(pcap)
        if len(pcap) > 24:
            global_head = pcap[:24]
        else:
            return
        magic_num = pcap[:4]
        e = ""
        if magic_num[0] == 161 and magic_num[-1] == 212: #endianness check
            e = "<"
        else:
            e = ">"
        snaplen = struct.unpack( e + "I" , pcap[16:20])[0]
        #if snaplen == 0:
        #    return []
        data = bytearray()

        head_start = 24
        head_end = 40    
        while head_end < len(pcap):
            pac_head = pcap[head_start: head_end]
            watch = pac_head[8:12]
            incl_len = struct.unpack("I", pac_head[8:12])[0]

            packet_end = head_end + incl_len

            packet = pcap[head_end : incl_len +  head_end]
            ethernet_head = packet[:14]


            version = packet[14] >> 4
            pass
            if version == 4:
                #IPv4
                ihl = packet[14] & 15
                ip_headlen = (32 * ihl) / 8
                ip_header_end = 14 + ip_headlen
                protocol = packet[23] #6 is TCP
                if protocol == 6: #check if we have a TCP protocol
                    tcp_data = packet[int(ip_header_end) : incl_len]

                    data_offset = tcp_data[12] >> 4
                    data_offset = int((data_offset * 32) / 8)
                    if data_offset + ip_header_end > incl_len:
                        #invalid data_offset
                        new_start = head_end + incl_len
                        new_end = new_start + 16
                        head_start = new_start
                        head_end = new_end 
                        continue                   
                        
                    else:
                        data.extend(bytes(tcp_data[data_offset:]))
                        new_start = head_end + incl_len
                        new_end = new_start + 16
                        head_start = new_start
                        head_end = new_end 
                        continue
                else:
                    #invalid protocol
                    new_start = head_end + incl_len
                    new_end = new_start + 16
                    head_start = new_start
                    head_end = new_end
                    continue


            if version == 6:
                #IPv6
                protocol = packet[20]
                #x = ""
                if protocol == 6: #check if we have a TCP protocol
                    tcp_data = packet[54 : incl_len]

                    data_offset = tcp_data[12] >> 4
                    data_offset = int((data_offset * 32) / 8)
                    x = len(tcp_data)
                    if data_offset + 54 > incl_len:
                        #invalid data_offset
                        new_start = head_end + incl_len
                        new_end = new_start + 16
                        head_start = new_start
                        head_end = new_end
                        continue
                    else:
                        a = tcp_data[data_offset:]
                        data.extend(bytes(tcp_data[data_offset:]))
                        new_start = head_end + incl_len
                        new_end = new_start + 16
                        head_start = new_start
                        head_end = new_end 
                        continue
                else:
                    #invalid protocol
                    new_start = head_end + incl_len
                    new_end = new_start + 16
                    head_start = new_start
                    head_end = new_end
                    continue
    if N == 6:
        output = parse_bytes(bytes(data), 6)
    else:
        output = parse_bytes(bytes(data), N)

    return output

def parse_bytes(byte_str, N=6):
    passwords = []
    if N == 0 :
        N = 1
    output = ""
    for c in byte_str:
        if c >= 32 and c <= 127:
            if chr(c) == '.':
                output += 'ø'
                continue
            output += chr(c)
        else:
            output += "."
    candidate = ""
    i = 0
    while i < len(output):
        if output[i] != "." and output[i] != " ":
            if output[i] == 'ø':
                candidate += '.'
            else:
                candidate += output[i]
            if len(candidate) >= N:
                #keep looking ahead
                j = i + 1
                while j < len(output):
                    if output[j] != "." and output[j] != ' ': #we see that there are more characters to add
                        if output[j] == 'ø':
                            candidate += '.'
                        else:
                            candidate += output[j]
                        j+=1
                    else:
                        passwords.append(candidate) #no more characters to be added
                        candidate = ""
                        i = j
                        break
                    i = j
            i += 1
        else:
            candidate = ""
            i += 1
    return passwords





#print(extract_passwords("samples/capture1.pcap", N=1))