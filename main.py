import socket
import struct
import time

def decode(msg):
    mac_dst = struct.unpack('!BBBBBB', msg[0:6])
    mac_dst = ":".join([hex(part)[2:].zfill(2) for part in mac_dst])
    mac_src = struct.unpack('!BBBBBB', msg[6:12])
    mac_src = ":".join([hex(part)[2:].zfill(2) for part in mac_src])
    ether_type = struct.unpack('!H', msg[12:14])
    ether_type = ":".join([hex(part)[2:].zfill(4) for part in ether_type])

    if ether_type == '0800':
        enteteip = struct.unpack('!B', msg[23:24])
        enteteip = ":".join([hex(part)[2:].zfill(4) for part in enteteip])

        if enteteip == '0006':
            port_source = struct.unpack('!H', msg[34:36])[0]
            port_dest = struct.unpack('!H', msg[36:38])[0]
            offset = struct.unpack('!H', msg[46:48])
            offset = offset[0]
            offset = bin(offset)[2:].zfill(16)[:4]
            offset = int(offset, base=2)
            offset = 34 + (offset * 4)

            if port_dest == 80 or port_source == 80:
                http_request = msg[offset:].decode(errors='ignore')
                                          
                print(
                f"{time.time()}: DST_MAC: {mac_dst} - "
                f"SRC_MAC: {mac_src} - "
                f"ETHER_TYPE: {ether_type} - "
                f"ENTETE_IP: {enteteip} - "
                f"PORT_SOURCE: {port_source} - "
                f"PORT_DEST: {port_dest} - "
                f"OFFSET: {offset} - "
                f"HTTP_REQUEST: {http_request}"
                )



def main():
    s = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.htons(3),
    )

    s.bind(("enp0s3", 3))

    try:
        print("Sniffer started")
        while True:
            msg = s.recv(1024)
            decode(msg)
    except KeyboardInterrupt:
        print("Sniffer stopped")


if __name__ == "__main__":
    main()
