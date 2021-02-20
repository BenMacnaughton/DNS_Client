import sys
import socket
import bitstring
import random



client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def to_hex(string):
    result = "0"
    if string.__class__.__name__ == "int" and string >= 0:
        result = hex(string)
        result = result[2:]
        if string < 16:
            result = "0" + result
    elif string.__class__.__name__ == "str":
        result = "".join([hex(ord(char))[2:] for char in string])
    return str(result)


def create_query(port, request_type, server_name, host_name):
    random.seed()
    ID = to_hex(random.randint(0, 65535))
    data = ""
    data += ID #Add randomized ID
    data += "0100" #Flags
    data += "0001" #QDCOUNT
    data += "0000" #ANCOUNT
    data += "0000" #NSCOUNT
    data += "0000" #ARCOUNT

    #QNAME
    host_name = host_name.split(".")
    for j, _ in enumerate(host_name):
        data += to_hex(len(host_name[j])) #Add length byte
        data += to_hex(host_name[j]) #Char byte

    # Add a terminating byte.
    data += "00"
    qtype = ""
    if request_type == 'A':
        qtype = "0001"
    elif request_type == 'MX':
        qtype = "000f"
    elif request_type == 'NS':
        qtype = "0002"
    #Add QTYPE
    data+= qtype
    #Add QCLASS
    data += "0001"

    DNS_IP = server_name
    DNS_PORT = port

    address = (DNS_IP, DNS_PORT)

    # send request
    data = bytes.fromhex(data)
    client_socket.sendto(data, address)

    read = 1024

    data, address = client_socket.recvfrom(read)

    data = bitstring.BitArray(bytes=data)

    #Flags
    QR = data[16] == 1
    AA = data[21] == 1
    #Response Code
    r_code = data[28:32]
    #Answer count
    an_count = data[48:64]
    #Additional records count
    ar_count = data[80:96]

    #Go through name
    x = 96
    y = 104
    next_byte = data[x:y]
    while next_byte != "0x00":
        x += 8
        y += 8
        next_byte = data[x:y]
    i = y + 1

    request_type_received = ""

    result = None #Dict to return to main
    if request_type_received == "A":
        result = {'num_answers': None, 'ip': None, 'scc': None, 'auth': None, 'error': None}
    elif request_type_received == "CNAME" or request_type_received == "NS":
        result = {'num_answers': None, 'alias': None, 'scc': None, 'auth': None, 'error': None}
    elif request_type_received == "MX":
        result = {'num_answers': None, 'alias': None, 'pref': None, 'scc': None, 'auth': None, 'error': None}

    # Error check
    if r_code == "0x1":
        result['error'] = "ERROR\tFormat error: the name server was unable to interpret the query"
    elif r_code == "0x2":
        result['error'] = "ERROR\tServer failure: the name server was unable to process this query due to a problem with the name server"
    elif r_code == "0x3":
        result['error'] = "ERROR\tName error: meaningful only for responses from an authoritative name server, this code signiﬁes that the domain name referenced in the query does not exist"
    elif r_code == "0x4":
        result['error'] = "ERROR\tNot implemented: the name server does not support the requested kind of query"
    elif r_code == "0x5":
        result['error'] = "ERROR\tRefused: the name server refuses to perform the requested operation for policy reasons"


    return 0

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
    server_name = sys.argv[-2].strip('@')
    host_name = sys.argv[-1]

    print("DnsClient Sending request for " + host_name)
    print("Server: " + server_name)
    print("Request type: " + request_type)

    r = create_query(port_number, request_type, server_name, host_name)
    i = 1
    while  r != 0 and i < max_retries:
        r = create_query(port_number, request_type, server_name, host_name)
        i += 1

    print("Response received after " + str(0) + " seconds (" + str(i-1) + " retries)")