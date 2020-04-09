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


def parse_raw_ip_addr(raw_ip_addr: bytes) -> str:
    # Converts a byte-array IP address to a string
    # the input is on the form b'\xaa\xab'... a byte array
    ip_addr, = struct.unpack('!I', raw_ip_addr)
    return ".".join(map(lambda n: str(ip_addr>>n & 0xFF), [24,16,8,0]))


def parse_application_layer_packet(ip_packet_payload: bytes) -> TcpPacket:
    # Parses raw bytes of a TCP packet
    # That's a byte literal (~byte array) check resources section
    data_offset_mask = 0xF0
    data_offset_shift_by = 4 #bits

    source_port, = struct.unpack('!H', ip_packet_payload[:2] )

    dest_port, = struct.unpack('!H', ip_packet_payload[2:4])

    data_offset_byte, = struct.unpack('!B', ip_packet_payload[12:13])
    data_offset = (data_offset_byte & data_offset_mask) >> data_offset_shift_by

    header_size = data_offset * 4

    return TcpPacket(source_port, dest_port, data_offset, ip_packet_payload[header_size:])


def parse_network_layer_packet(ip_packet: bytes) -> IpPacket:
    # Parses raw bytes of an IPv4 packet
    # That's a byte literal (~byte array) check resources section
    # fields to parse : protocol, ihl, source_address, destination_address, payload
    packet = ip_packet
    IHL_mask = 0x0F
    DEFAULT_HEADER_SIZE = 20 #bytes

    #version(4-bits)#IHL(4-bits)#
    version_IHL, = struct.unpack('!B', packet[:1])
    IHL = version_IHL & IHL_mask
    header_size = IHL * 4 #in Bytes

    protocol, = struct.unpack('!B', packet[9:10])

    #source_address, = struct.unpack('!I', packet[12:16])
    source_address = parse_raw_ip_addr(packet[12:16])

    #dest_address, = struct.unpack('!I', packet[16:DEFAULT_HEADER_SIZE])
    dest_address = parse_raw_ip_addr(packet[16:DEFAULT_HEADER_SIZE])

    payload = packet[header_size:]
    #print((protocol, IHL, source_address, dest_address, payload))
    return IpPacket(protocol, IHL, source_address, dest_address, payload)


def main():
    # Un-comment this line if you're getting too much noisy traffic.
    # to bind to an interface on your PC. (or you can simply disconnect from the internet)

    # iface_name = "lo"
    # stealer.setsockopt(socket.SOL_SOCKET,
    #                    socket.SO_BINDTODEVICE, bytes(iface_name, "ASCII"))
    #while True:

        stealer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        raw_data =  stealer.recvfrom(4096)
        #parse_network_layer_packet(raw_data)



if __name__ == "__main__":
    main()
