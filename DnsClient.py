import sys
import socket
import bitstring
import random
import re
import time
import codecs


client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def skip_name(i, data):
    # look for name pointer
    while data[i:i+2] != "0b11" and data[i:i+8] != "0x00":
        i += 8
    # if name pointer found, skip over offest
    if data[i:i+2] == "0b11":
        i += 16
    # skip over 0x00 if not offset
    else:
        i += 8
    return i


def print_record(response, auth):
    if response['type'] == "A":
        print("IP\t" + str(response['ip']) + "\t" +
            str(response['scc']) + '\t' + auth + "\n")
    elif response['type'] == "CNAME":
        print("CNAME\t" + str(response['alias']) + "\t" + "\t" +
              str(response['scc']) + '\t' + auth + "\n")
    elif response['type'] == "MX":
        print("MX\t" + str(response['alias']) + "\t" + str(response['pref']) +
              "\t" + str(response['scc']) + '\t' + auth + "\n")
    elif response['type'] == "NS":
        print("NS\t" + str(response['alias']) + "\t" + "\t" +
              str(response['scc']) + '\t' + auth + "\n")

def resolve_record(i, data):
    #Skip name
    i = skip_name(i, data)
    #Get the request type
    request_type_received = data[i:i+16]
    #Continue to Class
    i += 16
    #Check response class
    response_class = data[i:i+16]
    if response_class != '0x0001':
        print("ERROR\tClass error, expected 0x0001 and received " + str(response_class))
        exit(1)

    result = None
    if request_type_received == "0x0001":  # A record
        result = {
            'type': "A",
            'ip': None,
            'scc': None
        }
    elif request_type_received == "0x0005":  # CNAME
        result = {
            'type': "CNAME",
            'alias': None,
            'scc': None
        }
    elif request_type_received == "0x0002":  # NS
        result = {
            'type': "NS",
            'alias': None,
            'scc': None
        }
    elif request_type_received == "0x000f":  # MX
        result = {
            'type': "MX",
            'alias': None,
            'pref': None,
            'scc': None
        }
    else:
        print("ERROR\tUnexpected type: " + str(request_type_received))
        exit(1)

    i += 16  # Continue to seconds can cache
    result['scc'] = int(str(data[i:i+32]), 0)

    i += 48
    if request_type_received == "0x0001":  # A record
        result['ip'] = str(int(str(data[i:i+8]), 0)) + '.' + \
            str(int(str(data[i+8:i+16]), 0)) + '.' + \
            str(int(str(data[i+16:i+24]), 0)) + '.' + \
            str(int(str(data[i+24:i+32]), 0))

    elif request_type_received == "0x0002" or request_type_received == "0x0005":  # CNAME or NS
        k = i
        string = []
        while data[k:k+8] != '0x00':
            if data[k:k+2] == "0b11":
                i = k + 16
                ptr = data[k+2:k+16]
                k = int(str(ptr), 0) * 8
            j = k + 8
            increment = (int(str(data[k:j].hex), 16) * 8)
            k = j
            j += increment
            string.append(codecs.decode(data[k:j].hex, "hex_codec").decode())
            k = j
            j += 8
        result['alias'] = ".".join(string)
        if k > i: i = k

    elif request_type_received == "0x000f":  # MX
        pref = data[i:i+16]
        result['pref'] = pref.uintbe
        i += 16
        k = i
        string = []
        while data[k:k+8] != '0x00':
            if data[k:k+2] == "0b11":
                i = k + 16
                ptr = data[k+2:k+16]
                k = int(str(ptr), 0) * 8
            j = k + 8
            increment = (int(str(data[k:j].hex), 16) * 8)
            k = j
            j += increment
            string.append(codecs.decode(data[k:j].hex, "hex_codec").decode())
            k = j
            j += 8
        result['alias'] = ".".join(string)
        if k > i: i = k
    return i, result


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
    ID = to_hex(random.randint(0, 255)) + to_hex(random.randint(0, 255))
    data = ""
    data += ID  # Add randomized ID
    data += "0100"  # Flags
    data += "0001"  # QDCOUNT
    data += "0000"  # ANCOUNT
    data += "0000"  # NSCOUNT
    data += "0000"  # ARCOUNT

    # QNAME
    host_name = host_name.split(".")
    for j, _ in enumerate(host_name):
        data += to_hex(len(host_name[j]))  # Add length byte
        data += to_hex(host_name[j])  # Char byte

    # Add a terminating byte.
    data += "00"
    qtype = ""
    if request_type == 'A':
        qtype = "0001"
    elif request_type == 'MX':
        qtype = "000f"
    elif request_type == 'NS':
        qtype = "0002"
    # Add QTYPE
    data += qtype
    # Add QCLASS
    data += "0001"

    DNS_IP = server_name
    DNS_PORT = port

    address = (DNS_IP, DNS_PORT)

    # send request
    data = bytes.fromhex(data)
    client_socket.sendto(data, address)

    read = 1024

    # Receive response
    try:
        data, address = client_socket.recvfrom(read)
        print("hello")
    except socket.timeout:
        print("ERROR\tTimeout reached")
        return

    # Convert to bit array
    data = bitstring.BitArray(bytes=data)
    return data



if __name__ == "__main__":
    timeout = 5
    max_retries = 3
    port_number = 53
    request_type = "A"
    server_name = ""
    host_name = ""
    if len(sys.argv) < 2:
        print("ERROR\tIncorrect usage")
    elif len(sys.argv) >= 2:
        if "-t" in sys.argv:
            i = sys.argv.index("-t")
            timeout = sys.argv[i+1]
        if "-r" in sys.argv:
            i = sys.argv.index("-r")
            max_retries = sys.argv[i+1]
        if "-p" in sys.argv:
            i = sys.argv.index("-p")
            port_number = int(sys.argv[i+1])
        if "-mx" in sys.argv:
            request_type = "MX"
        elif "-ns" in sys.argv:
            request_type = "NS"
    server_name = sys.argv[-2].strip('@')
    host_name = sys.argv[-1]

    # Check for valid IP
    val_address = re.search("^((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\\.(?!$)|$)){4}$", server_name)
    if not val_address:
        print("ERROR\tIncorrect input syntax: not an IP address")
        exit(1)

    print("DnsClient Sending request for " + host_name)
    print("Server: " + server_name)
    print("Request type: " + request_type + "\n")

    # Start time
    ti = time.time()
    tf = None
    #Error variable
    error = None

    ret = 0
    # Set timeout
    client_socket.settimeout(int(timeout))
    while True:
        data = create_query(port_number, request_type, server_name, host_name)
        if data:
            # End time
            tf = time.time()
            print("Response received after " + str(tf-ti) + " seconds (" + str(ret) + " retries)\n")
            # Flags
            QR = data[16] == 1
            AA = data[21] == 1
            auth = None
            if AA: auth = "auth"
            else: auth = "nonauth"
            # Response Code
            r_code = data[28:32]
            # Answer count
            an_count = data[48:64]
            an_count = an_count.uintbe
            #Auth records count
            ns_count = data[64:80]
            ns_count = ns_count.uintbe
            # Additional records count
            ar_count = data[80:96]
            ar_count = ar_count.uintbe

            i = 96
            #Skip question
            i = skip_name(i, data)
            i += 32

            # Check if response
            if not QR:
                error = "ERROR\tExpected a response"
            # Error check
            if r_code == "0x1":
                error = "ERROR\tFormat error: the name server was unable to interpret the query"
            elif r_code == "0x2":
                error = "ERROR\tServer failure: the name server was unable to process this query due to a problem with the name server"
            elif r_code == "0x3":
                error = "ERROR\tName error: meaningful only for responses from an authoritative name server, this code signiﬁes that the domain name referenced in the query does not exist"
            elif r_code == "0x4":
                error = "ERROR\tNot implemented: the name server does not support the requested kind of query"
            elif r_code == "0x5":
                error = "ERROR\tRefused: the name server refuses to perform the requested operation for policy reasons"
            print("***Answer Section (" + str(an_count) + " records)***\n")

            for an in range(an_count):
                i, response = resolve_record(i, data)
                if response is not None: print_record(response, auth)

            for ns in range(ns_count):
                i, response = resolve_record(i, data)

            print("***Additional Section (" + str(ar_count) + " records)***\n")

            for ns in range(ns_count):
                i, response = resolve_record(i, data)
                if response is not None: print_record(response, auth)

            if ns_count == 0: print("NOTFOUND\n")
            if error is not None: print(error)
            break
        
        ret += 1
        if ret == max_retries + 1:
            print("ERROR\tMaximum retries reached")
            exit(1)
