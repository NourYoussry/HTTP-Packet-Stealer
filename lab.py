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
    return "0.0.0.0"


def parse_application_layer_packet(ip_packet_payload: bytes) -> TcpPacket:
    # Parses raw bytes of a TCP packet
    # That's a byte literal (~byte array) check resources section
    return TcpPacket(-1, -1, -1, b'')

def Int2IP(ipnum):
    o1 = int(ipnum / 16777216) % 256
    o2 = int(ipnum / 65536) % 256
    o3 = int(ipnum / 256) % 256
    o4 = int(ipnum) % 256
    return '%(o1)s.%(o2)s.%(o3)s.%(o4)s' % locals()

def to_string(ip):
  "Convert 32-bit integer to dotted IPv4 address."
  return ".".join(map(lambda n: str(ip>>n & 0xFF), [24,16,8,0]))

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
    print(protocol)

    source_address, = struct.unpack('!I', packet[12:16])
    source_address = to_string(source_address)

    dest_address, = struct.unpack('!I', packet[16:DEFAULT_HEADER_SIZE])
    dest_address = to_string(dest_address)

    payload = packet[header_size:]
    print((protocol, IHL, source_address, dest_address, payload))
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
        #print(binascii.hexlify(raw_data[0]))
        parse_network_layer_packet(raw_data)



if __name__ == "__main__":
    main()
