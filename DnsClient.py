import sys
import socket
import bitstring
import random

client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def str_to_hex(string):
    result = "".join([hex(ord(char))[2:] for char in string])
    return "0x" + result

def create_query(port, timeout, request_type, server_name, host_name):
    random.seed()

    '''
    Specifies formats for all entries
    Will append to list as we assemble query
    '''
    DNS_QUERY_FORMAT = [
        "hex=id", 
        "bin=flags", 
        "uintbe:16=qdcount", 
        "uintbe:16=ancount", 
        "uintbe:16=nscount", 
        "uintbe:16=arcount"
        ]

    '''
    Our query represented as a dictionary
    Will add on to dictionary as we assemble query
    '''
    DNS_QUERY = {
        "id": hex(random.randint(0, 256)),
        "flags": "0b0000000100000000",
        "qdcount": 1,
        "ancount": 0,
        "nscount": 0,
        "arcount": 0
        }

    host_name = host_name.split('.')

    i = 0

    '''
    Create all qname entries and corresponding formats
    will parse host_name one label at a time and convert len/label 
    to hex
    '''
    for label in host_name:
        
        label = label.strip()
        DNS_QUERY_FORMAT.append("hex=" + "qname" + str(i))
        DNS_QUERY["qname" + str(i)] = hex(len(label))
        
        i += 1
        DNS_QUERY_FORMAT.append("hex=" + "qname" + str(i))
        DNS_QUERY["qname" + str(i)] = str_to_hex(label)

        i += 1

    # Add a terminating byte.
    DNS_QUERY_FORMAT.append("hex=qname" + str(i))
    DNS_QUERY["qname" + str(i)] = hex(0)

    # construct qtype for A, MX, NS
    # return if not one of them
    DNS_QUERY_FORMAT.apppend("uintbe:16=qtype") 
    qtype = 0
    if request_type == 'A':
        qtype = 1
    elif request_type == 'MX':
        qtype = 15
    elif request_type == 'NS':
        qtype = 2
    if qtype == 0:
        return
    DNS_QUERY["qtype"] = qtype

    # qclass of 0x0001 for IN
    DNS_QUERY_FORMAT.append("hex=qclass")
    DNS_QUERY["qclass"] = "0x0001"

    # convert data to bits
    data = bitstring.pack(",".join(DNS_QUERY_FORMAT), **DNS_QUERY)

    DNS_IP = server_name
    DNS_PORT = port

    address = (DNS_IP, DNS_PORT)

    # send request
    client_socket.sendto(data.tobytes(), address)

    # return data and address to be used in recv
    return (data, address)

    

if __name__ == "__main__":
    timeout = 5
    max_retries = 3
    port_number = 53
    request_type = "A"
    server_name = ""
    host_name = ""
    if len(sys.argv) < 2:
        print("Error")
    elif len(sys.argv) >= 2:
        if "-t" in sys.argv:
            i = sys.argv.index("-t")
            timeout = sys.argv[i+1]
        if "-r" in sys.argv:
            i = sys.argv.index("-r")
            max_retries = sys.argv[i+1]
        if "-p" in sys.argv:
            i = sys.argv.index("-p")
            port_number = sys.argv[i+1]
        if "-mx" in sys.argv:
            request_type = "MX"
        elif "-ns" in sys.argv:
            request_type = "NS"
    server_name = sys.argv[-2]
    host_name = sys.argv[-1]
