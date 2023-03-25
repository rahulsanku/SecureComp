
import socket
import struct
import binascii
import time
import sys
import textwrap




#constants
TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket. htons(0x0800))

def unpack_mac(data):
    #unpack headers
    ethernet_header = data[:14]
    dest_mac, src_mac, protocol = struct.unpack("! 6s 6s H", ethernet_header) #dest mac, source mac, protocol(type)
    return format_mac(dest_mac), format_mac(src_mac) , socket.htons(protocol), data[14:]

#makes MAC address readable in AA:BB:CC:XX:YY:ZZ format
def format_mac(byte):
    addr = map('{:02x}'.format, byte)
    return ':'.join(addr).upper()

#unpacks the ip data from the ip packet
def unpack_ip(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, protocol, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20]) #time to live, protocol, source ip, destination ip
    return version, header_length, ttl, protocol, format_ip(src), format_ip(target), data[header_length:]

#makes IP address properly formatted (IPv4)
def format_ip(byte):
    return '.'.join(map(str, byte))

def format_data(data):

    return 'data'
#Unpacks ICMP packet
def icmp(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

def tcp(data):
    (src_port, dest_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = (offset_reserved_flags & 1)
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

def udp(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


def format_multi_line(prefix, string, size=80):
    size -=len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size%2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

#Unpacks TCP packet

def main():
    count = 0
    while True:
        if count == 10:
            break
        if s.recvfrom(65536):
            packet_data, address = s.recvfrom(65536)

            dest_mac, src_mac, protocol, data = unpack_mac(packet_data)
            test = data
            print('\nPacket Data: ')
            print(TAB_1 + 'Destination MAC: {}, Source MAC: {}, Protocol: {}'.format(dest_mac, src_mac, protocol))

            #check if IPv4
            if protocol == 8:
                (version, header_length, ttl, ip_protocol, src, target, data) = unpack_ip(data)
                print(TAB_1 + 'IPv4 Packet: ')
                print(TAB_2 + 'Version: {}, Header length: {}, TTL: {}'.format(version, header_length, ttl))
                print(TAB_2 + 'Protocol:{}, Source: {}, Target: {}'.format(ip_protocol, src, target))

                #ICMP Protocol
                if ip_protocol == 1:
                    icmp_type, code, checksum, data = icmp(data)
                    print(TAB_1 + 'ICMP Packet:')
                    print(TAB_2 + 'Type:{}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                    print(TAB_2 +  'Data:')
                    print(format_multi_line(TAB_3, data))



                #TCP Protocol
                elif ip_protocol == 6:
                    src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp(data)
                    print(TAB_1 + 'TCP Packet:')
                    print(TAB_2 + 'Source Port:{}, Destination Port: {}, Sequence: {}, Acknowledgement: {}'.format(src_port, dest_port, sequence, acknowledgement))
                    print(TAB_2 + 'Flags:')
                    print(TAB_3 + 'ACK:{}, FIN:{}, PSH:{}, RST:{}, SYN:{}, URG:{}'.format(flag_ack, flag_fin, flag_psh, flag_rst, flag_syn, flag_urg))
                    print(TAB_2 +  'Data:')
                    print(format_multi_line(TAB_3, format_data(data)))




                #UDP Protocol
                elif ip_protocol == 17:
                    src_port, dest_port, size, data = udp(data)
                    print(TAB_1 + 'UDP Packet:')
                    print(TAB_2 + 'Source Port:{}, Destination Port: {}, Size: {}'.format(src_port, dest_port, size))
                    print(TAB_2 +  'Data:')
                    print(format_multi_line(TAB_3, format_data(data)))


                else:
                    print(TAB_1 +  'Data:')
                    print(format_multi_line(TAB_2, format_data(data)))

            else:
                print('Data:')
                print(format_multi_line(TAB_1, data))
            count = count + 1





main()
