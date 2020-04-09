import socket
import binascii
import operator
import struct


class IpPacket(object):
    """
    Represents the *required* data to be extracted from an IP packet.
    """

    def __init__(self, protocol, ihl, source_address, destination_address, payload):
        self.protocol = protocol
        self.ihl = ihl
        self.source_address = source_address
        self.destination_address = destination_address
        self.payload = payload


class TcpPacket(object):
    """
    Represents the *required* data to be extracted from a TCP packet.
    """

    def __init__(self, src_port, dst_port, data_offset, payload):
        self.src_port = src_port
        self.dst_port = dst_port
        # As far as I know, this field doesn't appear in Wireshark for some reason.
        self.data_offset = data_offset
        self.payload = payload


class StealerSocket(object):
    """
    Contains sokcet logic
    """

    def __init__(self, iface_name='lo', buffer_size=65535):
        self.iface_name = iface_name
        self.buffer_size = buffer_size
        self.setup_socket()

    def setup_socket(self):
        # IPPROTO_TCP to recieve only tcp sockets
        self.socket = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

        # To limit the trafic
        self.socket.setsockopt(
            socket.SOL_SOCKET, socket.SO_BINDTODEVICE, bytes(self.iface_name, "ASCII"))
        
    def steal(self):        
        return self.socket.recv(self.buffer_size)


def parse_raw_ip_addr(raw_ip_addr: bytes) -> str:
    # Converts a byte-array IP address to a string
    # the input is on the form b'\xaa\xab'... a byte array

    # ! indecates network byte order, I for unsinged int => 4 bytes
    ip_addr, = struct.unpack('!I', raw_ip_addr)

    # Get the content of each of the 4 bytes and join them by '.'
    return '.'.join(map(lambda n: str(ip_addr >> n & 0xFF), [24, 16, 8, 0]))


def parse_application_layer_packet(ip_packet_payload: bytes) -> TcpPacket:
    # Parses raw bytes of a TCP packet
    # That's a byte literal (~byte array) check resources section

    # Unpacking the source and destination ports
    source_port, = struct.unpack('!H', ip_packet_payload[:2])
    dest_port, = struct.unpack('!H', ip_packet_payload[2:4])

    # Unpack data_offset byte (it contains other fields as well!)
    data_offset_byte, = struct.unpack('!B', ip_packet_payload[12:13])

    # Get the data offset (first 4 bits) of the byte
    data_offset_mask = 0xF0
    data_offset_shift_by = 4  # bits
    data_offset = (data_offset_byte & data_offset_mask) >> data_offset_shift_by

    # data offset is the number of 32 bits in the TCP header
    header_size = data_offset * 4  # in Bytes

    # Retrun the parsed Tcp packet
    return TcpPacket(source_port, dest_port, data_offset, ip_packet_payload[header_size:])


def parse_network_layer_packet(ip_packet: bytes) -> IpPacket:
    # Parses raw bytes of an IPv4 packet
    # That's a byte literal (~byte array) check resources section
    # fields to parse : protocol, ihl, source_address, destination_address, payload

    # header size wihtout options (destination address end)
    DEFAULT_HEADER_SIZE = 20

    # Unpack first byte it contains both version (4 bits) and IHL or header length (4 bits)
    version_IHL, = struct.unpack('!B', ip_packet[:1])

    # Get the second 4 bits of the byte (IHL)
    IHL_mask = 0x0F
    IHL = version_IHL & IHL_mask

    # IHL is the number of 32 bits in the header
    header_size = IHL * 4  # in Bytes

    # Unpack the protocol number it should be always equal to 6 as we just accepting tcp packets
    protocol, = struct.unpack('!B', ip_packet[9:10])

    # Parse source and destination addresses
    source_address = parse_raw_ip_addr(ip_packet[12:16])
    dest_address = parse_raw_ip_addr(ip_packet[16:DEFAULT_HEADER_SIZE])

    # Getting the payload
    payload = ip_packet[header_size:]

    # Return the parsed packet
    return IpPacket(protocol, IHL, source_address, dest_address, payload)


def main():

    # initialize stealer socket
    stealer = StealerSocket()

    while True:

        # recv tcp packets
        raw_data = stealer.steal()
        
        # parse network layer packet
        ip_packet = parse_network_layer_packet(raw_data)
        
        # parse application layer packet
        tcp_packet = parse_application_layer_packet(ip_packet.payload)
    
        try:
            tcp_packet.payload.decode("utf-8")
            print(tcp_packet.payload)
        except:
            continue


if __name__ == "__main__":
    main()
