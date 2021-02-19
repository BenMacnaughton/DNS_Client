import sys
import socket
import bitstring
import random
import codecs


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

    read = 1024

    data, address = client_socket.recvfrom(read)

    data = bitstring.BitArray(bytes=data)

    host_name_received = []

    i = 96
    j = 104

    for label in host_name:
        inc = (int(str(data[i:j].hex), 16) * 8)
        i = j
        j += inc
        host_name_received.append(codecs.decode(
            data[i:j].hex, "hex_codec").decode())
        i = j
        j += 8

    r_code = str(data[28:32].hex)

    result = {'host': None, 'ip': None}

    # Error check
    if r_code == "0":
        result['host'] = ".".join(host_name_received)
        result['ip_address'] = ".".join([
            str(data[-32:-24].uintbe)
            ,str(data[-24:-16].uintbe)
            ,str(data[-16:-8].uintbe)
            ,str(data[-8:].uintbe)
        ])
    elif r_code == "1":
        print("ERROR\tFormat error: the name server was unable to interpret the query")
    elif r_code == "2":
        print("ERROR\tServer failure: the name server was unable to process this query due to a problem with the name server")
    elif r_code == "3":
        print("ERROR\tName error: meaningful only for responses from an authoritative name server, this code signiﬁes that the domain name referenced in the query does not exist")
    elif r_code == "4":
        print("ERROR\tNot implemented: the name server does not support the requested kind of query")
    elif r_code == "5":
        print("ERROR\tRefused: the name server refuses to perform the requested operation for policy reasons")
    return result

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
