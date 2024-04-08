import sys
import os
import struct
import socket
import hashlib
import argparse
import select

Magic = 17942
my_ip = "127.0.0.1"
my_port = 4242
server_ip = "127.0.0.1"
server_port = 4243
BUF_SIZE = 1400
HEADER_FORMAT = "HHHHII"
HEADER_LEN = struct.calcsize(HEADER_FORMAT)


# |2byte magic     |2byte type       |
# |2byte header len|2byte payload len|
# |           4byte SEQ              |
# |           4byte ACK              |
# |            Payload               |

def start_download(sock):
    global file_to_download

    # step0: convert str to byte
    file_byte = file_to_download.encode()

    # step1: build Request pkt header:
    req_header = struct.pack(HEADER_FORMAT, socket.htons(Magic),socket.htons(0), socket.htons(HEADER_LEN), socket.htons(len(file_byte)), socket.htonl(0), socket.htonl(0))

    # step2: concatenate header with payload:
    req_pkt = req_header + file_byte

    # step3: send the pkt to server:
    sock.sendto(req_pkt, (server_ip, server_port))


def process_inbound_udp(sock):
    global file_to_download
    global download_path
    global file_hash
    global downloaded

    # Receive pkt
    pkt, from_addr = sock.recvfrom(BUF_SIZE)
    print(pkt)
    Magic, Type, hlen, plen, Seq, Ack= struct.unpack(HEADER_FORMAT, pkt[:HEADER_LEN])
    payload = pkt[HEADER_LEN:]

    Type = socket.ntohs(Type)
    Seq = socket.ntohl(Seq)
    Ack = socket.ntohl(Ack)
    
    print(f"{Magic}, {Type}")
    if Type == 1:
        # received an Response pkt
        # load the hash value of file
        file_hash_byte = payload[:20]

        # send back GET pkt
        get_header = struct.pack(HEADER_FORMAT, socket.htons(Magic),socket.htons(2), socket.htons(HEADER_LEN), socket.htons(len(file_hash_byte)), socket.htonl(0), socket.htonl(0))
        get_pkt = get_header+file_hash_byte
        sock.sendto(get_pkt, from_addr)
    elif Type == 3:
        ######### Design you RDT here ###########

        # receiving a DATA pkt
        
        # step0: load payload from the pkt


        # step1: send back ACK pkt
       
        
        # step2: check if downloading finished

        # step3: if finished, decode and save the file to download_path
        
        pass

def run():
    my_addr = (my_ip, my_port)
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    my_socket.bind(my_addr)
    print(f"RDT client started on {my_addr}")

    start_download(my_socket)

    try:
        while True:
            ready = select.select([my_socket],[],[], 0.1)
            read_ready = ready[0]
            if len(read_ready) > 0:
                if my_socket in read_ready:
                    process_inbound_udp(my_socket)
            else:
                # No pkt arrives during this period 
                pass
    except KeyboardInterrupt:
        pass
    finally:
        my_socket.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', type=str, help='File to download', required=True)
    parser.add_argument('-p', type=str, help='Path to store the downloaded file', default="client_download.txt")
    args = parser.parse_args()

    file_to_download = args.d
    download_path = args.p
    file_hash = ""
    downloaded = bytes()
    
    run()
