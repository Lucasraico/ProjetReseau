import json
import socket
import struct
import time
import re
import requests

from influxdb import InfluxDBClient


def decode(msg):
    mac_dst = struct.unpack('!BBBBBB', msg[0:6])
    mac_dst = ":".join([hex(part)[2:].zfill(2) for part in mac_dst])
    mac_src = struct.unpack('!BBBBBB', msg[6:12])
    mac_src = ":".join([hex(part)[2:].zfill(2) for part in mac_src])
    ether_type = struct.unpack('!H', msg[12:14])
    ether_type = ":".join([hex(part)[2:].zfill(4) for part in ether_type])
    
    client = InfluxDBClient('localhost', 8086, 'root', 'root', 'example')
    client.create_database('example')

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
                urls = re.search(r"(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]+\.[^\s]{2,})", http_request)
              
                if urls:
                    urls = urls.group(1)
                    try:
                        r = requests.get(urls)
                        # print(urls)          
                        json_body = [ 
                                    { "measurement": "cpu_load_short",
                                    "fields": {
                                        "ether_type": ether_type, 
                                        "enteteip": enteteip, 
                                        "url": urls,
                                        "http-code": r.status_code
                                        }
                                    }
                        ]
                        print("[HTTP CODE : " + str(r.status_code) + "] > " + urls)

                        client.write_points(json_body)
                        # print('insert reussi---')s
                        result = client.query('SELECT url FROM cpu_load_short')
                        # print("Result: {0}".format(result), '---')
                        #print("list database =",client.get_list_database(),'---')  
                    except requests.exceptions.ConnectionError:
                        print("ConnectionError lors de la requête")
                    
              


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
