import sys
import socket
import bitstring
import random
import re
import time
import codecs


client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def skip_name(i, x, y, data):
    # Go through name
    next_byte = data[x:y]
    while next_byte != "0x00":
        x += 8
        y += 8
        next_byte = data[x:y]
    i += y + 32  # skip qtype qclass

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

def skip_record(i, data, request_type_received):
    i = skip_name(i,i,i+8,data)
    i += 64

def resolve_record(i, data, result, request_type_received):

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
            print(string)
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
            print(string)
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


def get_type(i, data):
    request_type_received = data[i:i+16]
    i += 16
    return i, request_type_received


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
    except socket.timeout:
        print("ERROR\tTimeout reached")
        return

    # Convert to bit array
    data = bitstring.BitArray(bytes=data)

    # Flags
    QR = data[16] == 1
    AA = data[21] == 1
    # Response Code
    r_code = data[28:32]
    # Answer count
    an_count = data[48:64]
    # Additional records count
    ar_count = data[80:96]

    #Skip name
    i = skip_name(0, 96, 104, data)

    #Get the request type
    i, request_type_received = get_type(i, data)

    result = {'answers': [], 'additionals':[]}  # Dict to return to main

    if request_type_received == "0x0001":  # A record
        result = {
            'type': "A",
            'num_answers': None,
            'num_additional': None,
            'ip': None,
            'scc': None,
            'auth': None,
            'error': None,
            'additional': []
        }
    elif request_type_received == "0x0005":  # CNAME
        result = {
            'type': "CNAME",
            'num_answers': None,
            'num_additional': None,
            'alias': None,
            'scc': None,
            'auth': None,
            'error': None,
            'additional': []
        }
    elif request_type_received == "0x0002":  # NS
        result = {
            'type': "NS",
            'num_answers': None,
            'num_additional': None,
            'alias': None,
            'scc': None,
            'auth': None,
            'error': None,
            'additional': []
        }
    elif request_type_received == "0x000f":  # MX
        result = {
            'type': "MX",
            'num_answers': None,
            'num_additional': None,
            'alias': None,
            'pref': None,
            'scc': None,
            'auth': None,
            'error': None,
            'additional': []
        }
    else:
        print("ERROR\tUnexpected type: " + str(request_type_received))
        exit(1)

    response_class = data[i:i+16]
    if response_class != '0x0001':
        result['error'] = "ERROR\tClass error, expected 0x0001 and received " + \
            str(response_class) + "\n"
        return

    # Set auth
    if AA:
        result['auth'] = "auth"
    else:
        result['auth'] = "nonauth"

    # Check if response
    if not QR:
        result['error'] = "ERROR\tExpected a response"
        return result

    # Check number of answers
    result['num_answers'] = an_count.uintbe
    if an_count == "0x0000":
        result['error'] = "ERROR\tExpected at least one answer"
        return result

    # Set number of additional records
    result['num_additional'] = ar_count.uintbe

    #Call resolve record on original answer
    i, result = resolve_record(i, data, result, request_type_received)

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

    return result


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
            port_number = sys.argv[i+1]
        if "-mx" in sys.argv:
            request_type = "MX"
        elif "-ns" in sys.argv:
            request_type = "NS"
    server_name = sys.argv[-2].strip('@')
    host_name = sys.argv[-1]

    # Check for valid IP
    val_address = re.search(
        "^((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])(\\.(?!$)|$)){4}$", server_name)
    if not val_address:
        print("ERROR\tIncorrect input syntax: not an IP address")
        exit(1)

    print("DnsClient Sending request for " + host_name)
    print("Server: " + server_name)
    print("Request type: " + request_type + "\n")

    # Start time
    ti = time.time()

    i = -1
    # Set timeout
    client_socket.settimeout(int(timeout))
    while True:
        response = create_query(port_number, request_type, server_name, host_name)
        i += 1
        if response:
            break
        if i == max_retries:
            print("ERROR\tMaximum retries reached")
            exit(1)

    # End time
    tf = time.time()

    print("Response received after " + str(tf-ti) +
          " seconds (" + str(i) + " retries)\n")
    if response is None:
        print("ERROR\tNo response was received")
        exit(1)
    print("***Answer Section (" +
          str(response['num_answers']) + " records)***\n")
    if response['type'] == "A":
        print("IP\t" + str(response['ip']) + "\t" +
              str(response['scc']) + '\t' + str(response['auth']) + "\n")
    elif response['type'] == "CNAME":
        print("CNAME\t" + str(response['alias']) + "\t" + "\t" +
              str(response['scc']) + '\t' + str(response['auth']) + "\n")
    elif response['type'] == "MX":
        print("MX\t" + str(response['alias']) + "\t" + str(response['pref']) +
              "\t" + str(response['scc']) + '\t' + str(response['auth']) + "\n")
    elif response['type'] == "NS":
        print("NS\t" + str(response['alias']) + "\t" + "\t" +
              str(response['scc']) + '\t' + str(response['auth']) + "\n")
    print("***Additional Section (" +
          str(response['num_additional']) + " records)***\n")
    if response['num_additional'] == 0:
        print("NOTFOUND\n")
    if response['error'] is not None:
        print(response['error'])
