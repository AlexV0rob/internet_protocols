import socket
import time
import struct
import argparse
import random

DNS_REQUEST_TYPE = {
    1: "A", 2: "NS", 3: "MD", 4: "MF", 5: "CNAME", 
    6: "SOA",  7: "MB", 8: "MG", 9: "MR", 
    10: "NULL", 11: "WKS", 12: "PTR", 13: "HINFO", 14: "MINFO", 
    15: "MX", 16: "TXT", 17: "RP", 18: "AFSDB", 19: "X25",
    20: "ISDN", 21: "RT", 22: "NSAP", 23: "NSAP-PTR", 24: "SIG", 
    25: "KEY", 26: "PX", 27: "GPOS", 28: "AAAA", 29: "LOC", 
    30: "NXT", 31: "EID", 32: "NIMLOC", 33: "SRV", 34: "ATMA", 
    35: "NAPTR", 36: "KX", 37: "CERT", 38: "A6", 39: "DNAME", 
    40: "SINK", 41: "OPT", 42: "APL", 43: "DS", 44: "SSHFP", 
    45: "IPSECKEY", 46: "PRSIG", 47: "NSEC", 48: "DNSKEY", 49: "DHCID", 
    50: "NSEC3", 51: "NSEC3PARAM", 52: "TLSA", 53: "SMIMEA", 
    55: "HIP", 56: "NINFO", 57: "RKEY", 58: "TALINK", 59: "CDS", 
    60: "CDNSKEY", 61: "OPENPGPKEY", 62: "CSYNC", 63: "ZONEMD", 64: "SVCB", 
    65: "HTTPS", 
    99: "SPF", 
    100: "UINFO", 101: "UID", 102: "GID", 103: "UNSPEC", 104: "NID", 
    105: "L32", 106: "L64", 107: "LP", 108: "EUI48", 109: "EUI64",
    249: "TKEY", 
    250: "TSIG", 251: "IXFR", 252: "AXFR", 253: "MAILB", 254: "MAILA", 
    255: "*", 256: "URI", 257: "CAA", 259: "DOA",
    32768: "TA", 32769: "DLV",
}
DNS_REQUESTS = {}
DNS_CACHE = {}


def encode_label(qname, index=12, labels_indexes=None):
    if labels_indexes == None:
        labels_indexes = {}
    if qname in labels_indexes:
        label = struct.pack("!H", (0b11 << 14) | labels_indexes[qname])
        return (label, labels_indexes, False)
    else:
        dot_index = qname.find('.')
        if dot_index >= 0:
            label = qname[:dot_index].encode()
            second_part = qname[dot_index + 1:]
            if len(label) > 63:
                raise ValueError("Too long name label")
            sec_part, labels_indexes, save = encode_label(second_part, 
                                               index + len(label), 
                                               labels_indexes)
            if save:
                labels_indexes[qname] = index
            return (struct.pack("!B", len(label)) + label + sec_part, 
                    labels_indexes, save)
        else:
            label = qname.encode()
        if len(label) > 63:
            raise ValueError("Too long name label")
        labels_indexes[qname] = index
        return (struct.pack("!B", len(label)) + label + struct.pack("!B", 0), 
                labels_indexes, True)

def create_dns_query(qname, qtype, index=12, labels_indexes=None, qclass=1):
    name, labels_indexes, _ = encode_label(qname, index, labels_indexes)
    query = name + struct.pack("!HH", qtype, qclass)
    return (query, labels_indexes)

def create_dns_response(name, type, ttl, data, index=12, 
                        labels_indexes=None, qclass=1):
    if labels_indexes == None:
        labels_indexes = {}
    query, labels_indexes = create_dns_query(name, type, index, labels_indexes, qclass)
    response = query + struct.pack("!IH", ttl, len(data)) + data
    return (response, labels_indexes)

def create_dns_header(id, qr, opcode, aa, rcode, 
                      qdcount, ancount, nscount, arcount, 
                      tc=0, rd=0, ra=1, z=0):
    third_octet = (qr << 7) | (opcode << 4) | (aa << 2) | (tc << 1) | rd
    fourth_octet = (ra << 7) | (z << 4) | rcode
    return struct.pack("!HBBHHHH", id, third_octet, fourth_octet, 
                       qdcount, ancount, nscount, arcount)

def clear_cache(address, type):
    if address in DNS_CACHE and type in DNS_CACHE[address]:
        dns_type = DNS_CACHE[address][type]
        current_time = int(time.time())
        index = 0
        for _ in range(len(dns_type)):
            record = dns_type[index]
            if current_time - record["time_cached"] >= record["ttl"]:
                dns_type.pop(index)
            else:
                index += 1
        if not dns_type:
            DNS_CACHE[address].pop(type)
            if not DNS_CACHE[address]:
                DNS_CACHE.pop(address)

def add_answers_to_cache(answers):
    global DNS_CACHE
    for answer in answers:
        clear_cache(answer["qname"], answer["qtype"])
        if answer["qname"] not in DNS_CACHE:
            DNS_CACHE[answer["qname"]] = {}
        if DNS_CACHE[answer["qname"]].get(answer["qtype"], None) is None:
            DNS_CACHE[answer["qname"]][answer["qtype"]] = []
        dns_type = DNS_CACHE[answer["qname"]][answer["qtype"]]
        value_cached = False
        current_time = int(time.time())
        for record in dns_type:
            value_cached = (record["data"] == answer["data"])
            if value_cached:
                break
        if not value_cached:
            dns_type.append({
                "data": answer["data"],
                "ttl": answer["ttl"],
                "time_cached": current_time
            })

def ask_forwarder(forwarder, port, query_data):
    try:
        sock = DNS_REQUESTS.get(
            (query_data["qname"], query_data["qtype"]), None)
        if sock is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            DNS_REQUESTS[(query_data["qname"], query_data["qtype"])] = sock
            sock.settimeout(10)
            sock.connect((forwarder, port))
            dns_packet_header = create_dns_header(
                random.randint(0, 65535), 0, query_data["opcode"], 
                0, 0, 1, 0, 0, 0, rd=1
            )
            dns_packet_data, _ = create_dns_query(
                query_data["qname"], query_data["qtype"]
            )
            dns_packet = dns_packet_header + dns_packet_data
            sock.send(dns_packet)
        forwarder_response = sock.recv(1024)
        packet = parse_dns_packet(forwarder_response)
        add_answers_to_cache(packet["answers"])
        add_answers_to_cache(packet["authoritatives"])
        add_answers_to_cache(packet["additionals"])
        DNS_REQUESTS.pop((query_data["qname"], query_data["qtype"]))
    finally:
        sock.close()

def get_server_name(response, queries_len, data_len):
    name_index = 12
    for _ in range(queries_len):
        __, name_index = parse_next_dns_question(response, name_index)
    __, name_index = parse_next_dns_answer(response, name_index)
    name_index -= data_len
    return parse_name(response, name_index)[0]

def recursive_search(query_data):
    parts = query_data["qname"].split('.')
    parts_len = len(parts)
    server = "a.root-servers.net"
    name = ''
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(10)
        for i in range(parts_len + 1):
            if i < parts_len:
                if name:
                    name = '.' + name
                name = parts[parts_len - i - 1] + name
            dns_packet_header = create_dns_header(
                random.randint(0, 65535), 0, query_data["opcode"], 
                0, 0, 1, 0, 0, 0
            )
            dns_packet_data, _ = create_dns_query(
                name, query_data["qtype"]
            )
            dns_packet = dns_packet_header + dns_packet_data
            sock.sendto(dns_packet, (server, 53))
            forwarder_response = sock.recv(1024)
            packet = parse_dns_packet(forwarder_response)
            add_answers_to_cache(packet["answers"])
            add_answers_to_cache(packet["authoritatives"])
            add_answers_to_cache(packet["additionals"])
            if packet["answers"] or not packet["authoritatives"]:
                break
            server = get_server_name(
                forwarder_response, 
                packet["qdcount"], 
                len(packet["authoritatives"][0]["data"])
            )
    finally:
        sock.close()

def check_cache(address, type):
    global DNS_CACHE
    clear_cache(address, type)
    if address in DNS_CACHE and type in DNS_CACHE[address]:
        return DNS_CACHE[address][type]
    return []

def create_queries(queries_data, index=12, labels_indexes=None):
    if labels_indexes == None:
        labels_indexes = {}
    queries = []
    for query_data in queries_data:
        query, labels_indexes = create_dns_query(
            query_data["qname"], query_data["qtype"], index, labels_indexes
        )
        index += len(query)
        queries.append(query)
    return (queries, index, labels_indexes)

def not_in_cache(forwarder, port, query_data, recursion=True):
    rcode = 2
    address_info = []
    if recursion:
        try:
            if forwarder != None and port != None:
                ask_forwarder(forwarder, port, query_data)
            else:
                recursive_search(query_data)
            address_info = check_cache(query_data["qname"], query_data["qtype"])
            if address_info:
                rcode = 0
        except (socket.error, OSError):
            pass
    return (address_info, rcode)

def create_responses(queries_data, forwarder, port, 
                     index=12, labels_indexes=None, recursion=True):
    if labels_indexes == None:
        labels_indexes = {}
    new_labels_indexes = dict(labels_indexes)
    new_index = index
    responses = []
    cached_list = []
    rcode = 0
    for query_data in queries_data:
        address_info = check_cache(query_data["qname"], query_data["qtype"])
        cached = bool(address_info)
        if not cached:
            address_info, rcode = not_in_cache(
                forwarder, port, query_data, recursion
            )
            if rcode == 2:
                responses.clear()
                break
        current_time = int(time.time())
        for record in address_info:
            time_difference = current_time - record["time_cached"]
            new_ttl = record["ttl"] - time_difference
            if new_ttl <= 0:
                return create_responses(queries_data, forwarder, port,
                                        index, labels_indexes, recursion)
            response, new_labels_indexes = create_dns_response(
                query_data["qname"], query_data["qtype"], new_ttl, 
                record["data"], new_index, new_labels_indexes
            )
            new_index += len(response)
            if response != b'':
                responses.append(response)
        cached_list.append(cached)
    return (responses, new_index, labels_indexes, rcode, cached_list)

def create_dns_response_packet(forwarder, port, queries_data):
    dns_id = queries_data[0]["id"]
    opcode = queries_data[0]["opcode"]
    rd_code = queries_data[0]["rd"]
    index = 12
    labels_indexes = {}
    queries, index, labels_indexes = create_queries(
        queries_data, index, labels_indexes
    )
    recursion = (rd_code != 0)
    responses, index, labels_indexes, rcode, cached_list = create_responses(
        queries_data, forwarder, port, index, labels_indexes, recursion
    )
    records_part = b''
    for query in queries:
        records_part += query
    if rcode == 0:
        for response in responses:
            records_part += response
    tc_code = 0
    if 12 + len(records_part) > 512:
        tc_code = 1
    packet = create_dns_header(
        dns_id, 1, opcode, 0, rcode, 
        len(queries), len(responses), 0, 0, 
        tc=tc_code, rd=rd_code
    ) + records_part
    return (packet, cached_list)

def parse_name(query_bytes, index):
    name_parts = []
    while query_bytes[index] != 0x00:
        if query_bytes[index] >> 6 == 0b00:
            name = ''
            for _ in range(query_bytes[index] & ((1 << 6) - 1)):
                index += 1
                name += chr(query_bytes[index])
            name_parts.append(name)
        elif query_bytes[index] >> 6 == 0b11:
            new_index = (((query_bytes[index] & ((1 << 6) - 1)) << 8)
                         | query_bytes[index + 1])
            index += 1
            name, new_index = parse_name(query_bytes, new_index)
            name_parts.append(name)
            break
        else:
            raise ValueError("Invalid packet structure")
        index += 1
    return ('.'.join(name_parts), index + 1)

def parse_next_dns_question(query_bytes, index):
    qname, index = parse_name(query_bytes, index)
    qtype = struct.unpack("!H", query_bytes[index:index + 2])[0]
    index += 2
    qclass = struct.unpack("!H", query_bytes[index:index + 2])[0]
    query = {
        "qname": qname,
        "qtype": qtype,
        "qclass": qclass
    }
    return (query, index + 2)

def parse_next_dns_answer(response_bytes, index):
    query, index = parse_next_dns_question(response_bytes, index)
    ttl = struct.unpack("!I", response_bytes[index:index + 4])[0]
    index += 4
    data_length = struct.unpack("!H", response_bytes[index:index + 2])[0]
    index += 2
    data = response_bytes[index:index + data_length]
    response = query | {
        "ttl": ttl,
        "data_length": data_length,
        "data": data
    }
    return (response, index + data_length)

def parse_dns_packet(packet_bytes):
    packet = {}
    query_header = packet_bytes[:12]
    header_parts = struct.unpack("!HBBHHHH", query_header)
    packet["id"] = header_parts[0]
    packet["qr"] = header_parts[1] >> 7
    packet["opcode"] = (header_parts[1] >> 3) & ((1 << 4) - 1)
    packet["aa"] = (header_parts[1] >> 2) & 1
    packet["tc"] = (header_parts[1] >> 1) & 1
    packet["rd"] = header_parts[1] & 1
    packet["ra"] = header_parts[2] >> 7
    packet["z"] = (header_parts[2] >> 4) & ((1 << 3) - 1)
    packet["rcode"] = header_parts[2] & ((1 << 4) - 1)
    packet["qdcount"] = header_parts[3]
    packet["ancount"] = header_parts[4]
    packet["nscount"] = header_parts[5]
    packet["arcount"] = header_parts[6]
    packet["questions"] = []
    packet["answers"] = []
    packet["authoritatives"] = []
    packet["additionals"] = []
    index = 12
    for _ in range(packet["qdcount"]):
        query, index = parse_next_dns_question(packet_bytes, index)
        packet["questions"].append(query)
    for _ in range(packet["ancount"]):
        query, index = parse_next_dns_answer(packet_bytes, index)
        packet["answers"].append(query)
    for _ in range(packet["nscount"]):
        query, index = parse_next_dns_answer(packet_bytes, index)
        packet["authoritatives"].append(query)
    for _ in range(packet["arcount"]):
        query, index = parse_next_dns_answer(packet_bytes, index)
        packet["additionals"].append(query)
    return packet

def flatten_queries(packet):
    queries = []
    for question in packet["questions"]:
        general_info = dict(packet)
        general_info.pop("questions")
        general_info.pop("answers")
        general_info.pop("authoritatives")
        general_info.pop("additionals")
        queries.append(general_info | dict(question))
    return queries

def start_server(port, forwarder, forwarder_port):
    global DNS_REQUEST_TYPES
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        my_ip = socket.gethostbyname(socket.gethostname())
        if forwarder == my_ip and forwarder_port == port:
            raise Exception("Can't use the same server as forwarder")
        server_address = (socket.gethostbyname(socket.gethostname()), port)
        sock.bind(server_address)
        print(f"Server started on {server_address}")
        while True:
            print("Waiting...")
            try:
                data, address = sock.recvfrom(1024)
                packet = parse_dns_packet(data)
                queries = flatten_queries(packet)
                response, cached_list = create_dns_response_packet(
                    forwarder, forwarder_port, queries
                )
                client = f"{address[0]}:{address[1]}"
                for i in range(len(queries)):
                    if i >= len(cached_list):
                        cached = "no response"
                    elif cached_list[i]:
                        cached = "cache"
                    else:
                        cached = "forwarder"
                    dns_type = DNS_REQUEST_TYPE.get(queries[i]["qtype"], "UNKNOWN")
                    dns_name = queries[i]["qname"]
                    print(client, dns_type, dns_name, cached, sep=', ')
                sock.sendto(response, address)
            except (socket.error, OSError):
                pass
    finally:
        sock.close()

def server_port(string):
    server_info = string.split(":")
    ip = (server_info[0] if len(server_info) == 1 
          else ':'.join(server_info[:-1]))
    port = 53
    if len(server_info) > 1:
        port = int(server_info[-1])
    if port < 1 or port > 65535:
        raise Exception("Invalid port")
    return (ip, port)

def main():
    parser = argparse.ArgumentParser(
        prog="dns_cache", 
        description="DNS caching server"
    )
    parser.add_argument("-p", "--port", type=int, default=53,
                        help="UDP port to listen")
    parser.add_argument("-f", "--forwarder", type=str,
                        help="Server's forwarder (ip[:port])")
    args = parser.parse_args()
    try:
        if args.forwarder != None:
            forwarder, forwarder_port = server_port(args.forwarder)
        else:
            forwarder = forwarder_port = None
        start_server(args.port, forwarder, forwarder_port)
    except PermissionError:
        print("Permission error, run this script as root (Administrator)")
    except socket.error as e:
        print("Error during data transfer: ", e)
    except Exception as e:
        print(e)

if __name__ == "__main__":
    main()