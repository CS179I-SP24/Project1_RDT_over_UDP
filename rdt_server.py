import sys
import os
import struct
import socket
import hashlib
import argparse
import select

Magic = 17942
my_ip = "127.0.0.1"
my_port = 4243

BUF_SIZE = 1400
HEADER_FORMAT = "HHHHII"
HEADER_LEN = struct.calcsize(HEADER_FORMAT)


# |2byte magic     |2byte type       |
# |2byte header len|2byte payload len|
# |           4byte SEQ              |
# |           4byte ACK              |
# |            Payload               |

def file2hash(file_byte):
    sha1 = hashlib.sha1()
    sha1.update(file_byte)
    return sha1.hexdigest()

def process_inbound_udp(sock):
    global server_hash
    global server_files

    # Receive pkt
    pkt, from_addr = sock.recvfrom(BUF_SIZE)
    Magic, Type, hlen, plen, Seq, Ack= struct.unpack(HEADER_FORMAT, pkt[:HEADER_LEN])
    payload = pkt[HEADER_LEN:]

    Type = socket.ntohs(Type)
    Seq = socket.ntohl(Seq)
    Ack = socket.ntohl(Ack)

    if Type == 0:
        # received an Request pkt
        # load the name of file requested
        file_name = payload.decode()

        # check if the server has the file
        if file_name in server_hash:
            file_hash_byte = bytes.fromhex(server_hash[file_name])

            # send back Response pkt

            resp_header = struct.pack(HEADER_FORMAT, socket.htons(Magic),socket.htons(1), socket.htons(HEADER_LEN), socket.htons(len(file_hash_byte)), socket.htonl(0), socket.htonl(0))
            resp_pkt = resp_header+file_hash_byte
            sock.sendto(resp_pkt, from_addr)

    elif Type == 2:
        ##### receiving GET packet. start your RDT!########
        pass

    elif Type == 4:
        ######### Design you RDT here ###########
        # receiving ACK
        
        pass

def run():
    my_addr = (my_ip, my_port)
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    my_socket.bind(my_addr)
    print(f"RDT server started, listening on {my_addr}")

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
    parser.add_argument('-f', type=str, help='file the server has', required=True)
    args = parser.parse_args()

    server_file_name = args.f

    # load the server file
    with open(os.path.join("server", server_file_name), "r") as f:
        file = f.read()

    # add the encoded file (in bytes) to server files
    server_files = {server_file_name: file.encode()}

    # add the hash value of the file to server hash
    server_hash = {server_file_name: file2hash(file)}
    
    run()
