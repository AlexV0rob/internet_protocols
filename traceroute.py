import struct
import ipwhois
import socket
import os
import argparse

START_PORT = 33434


def checksum(data):
    words = [(data[i] << 8) | data[i + 1] for i in range(0, len(data), 2)]
    check = sum(words)
    while check > 0xffff:
        check = (check & 0xffff) | (check >> 16)
    return check ^ 0xffff

def formICMP(icmp_type, icmp_code, data):
    icmp = struct.pack("BBH", icmp_type, icmp_code, 0) + data
    check = socket.htons(checksum(icmp))
    return struct.pack("BBH", icmp_type, icmp_code, check) + data

def formIP(src_ip, dest_ip, ttl, protocol, data):
    src = socket.inet_aton(src_ip)
    dest = socket.inet_aton(dest_ip)
    version_and_ihl = 0x45
    dscp_and_esn = 0
    length = socket.htons(20 + len(data))
    identification = 0
    flags_and_offset = 0
    header = struct.pack("BBHHHBBH", 
                         version_and_ihl, dscp_and_esn, length,
                         identification, flags_and_offset, 
                         ttl, protocol, 0) + src + dest
    check = socket.htons(checksum(header))
    header = struct.pack("BBHHHBBH", 
                         version_and_ihl, dscp_and_esn, length,
                         identification, flags_and_offset, 
                         ttl, protocol, check) + src + dest
    return header + data

def unpack_ip(packet):
    return struct.unpack("!BBHHHBBHII", packet[:20]) + (packet[20:],)

def unpack_icmp(packet):
    return struct.unpack("!BBHI", packet[:8]) + (packet[8:],)

def find_best_packet(res):
    index = -1
    if res[1] and res[2] and res[1][0] == res[2][0]:
        index = 1
    elif res[0]:
        index = 0
    elif res[2]:
        index = 2
    return index

def traceroute_response(timeout):
    try:
        sock = socket.socket(socket.AF_INET, 
                             socket.SOCK_RAW, 
                             socket.IPPROTO_ICMP)
        sock.settimeout(timeout)
        sock.bind(("", 0))
        try:
            response = sock.recvfrom(1024)
        except socket.timeout:
            response = ()
    finally:
        sock.close()
    return response

def icmp_traceroute_request(dest_ip, ttl, timeout):
    response = []
    try:
        sock = socket.socket(socket.AF_INET,
                             socket.SOCK_RAW,
                             socket.IPPROTO_ICMP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        my_ip = socket.gethostbyname(socket.gethostname())
        for _ in range(3):
            icmp = formICMP(8, 0, struct.pack("HH", 
                                              socket.htons(os.getpid() & 0xffff), 
                                              socket.htons(1)))
            packet = formIP(my_ip, dest_ip, ttl, 1, icmp)
            sock.sendto(packet, (dest_ip, START_PORT + ttl))
            response.append(traceroute_response(timeout))
    finally:
        sock.close()
    return response

def icmp_traceroute_request_auto(dest_ip, ttl, timeout):
    response = []
    try:
        sock = socket.socket(socket.AF_INET,
                             socket.SOCK_RAW,
                             socket.IPPROTO_ICMP)
        for _ in range(3):
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            packet = formICMP(8, 0, struct.pack("HH", 
                                                socket.htons(os.getpid() & 0xffff),
                                                socket.htons(1)))
            sock.sendto(packet, (dest_ip, START_PORT + ttl))
            response.append(traceroute_response(timeout))
    finally:
        sock.close()
    return response

def create_info_string(res_address):
    try:
        info = ipwhois.IPWhois(res_address).lookup_rdap(depth=1)
        network = info["network"]
        network_name = None
        if network != None:
            network_name = network["name"]
        asn = info["asn"]
        country = info["asn_country_code"]
        parts = []
        if network_name:
            parts.append(network_name)
        if asn:
            parts.append(asn)
        if country:
            parts.append(country)
    except ipwhois.IPDefinedError:
        return "local"
    return ", ".join(parts)

def traceroute(dest, timeout, max_ttl, assemble):
    try:
        dest_ip = socket.gethostbyname(dest)
        print(f"Tracerouting to {dest} ({dest_ip}):\n")
        ttl = 0
        working = True
        if assemble:
            request = icmp_traceroute_request
        else:
            request = icmp_traceroute_request_auto
        while ttl < max_ttl and working:
            ttl += 1
            res = request(dest_ip, ttl, timeout)
            index = find_best_packet(res)
            print(f"{ttl}.", end=' ')
            if index < 0:
                print(end="*\r\n")
            else:
                res_icmp = unpack_icmp(unpack_ip(res[index][0])[-1])
                res_type = res_icmp[0]
                res_code = res_icmp[1]
                res_address = res[index][1][0]
                print(res_address, end="\r\n")
                info_string = create_info_string(res_address)
                if info_string:
                    print(info_string, end="\r\n")
                if res_type == 0 and res_code == 0:
                    working = False
            print(end="\r\n")
        if working:
            print(f"Tracerouting to {dest} ({dest_ip}) failed!"
                   "Reached max hops limit: {max_ttl}")
        else:
            print(f"Tracerouting to {dest} ({dest_ip}) finished successfully")
    except socket.gaierror:
        print(f"{dest} is invalid")
    except PermissionError:
        print(f"Permission error, run this script as root (Administrator)")

def main():
    parser = argparse.ArgumentParser(prog="traceroute", 
                                     description="Tracerouting to hostname")
    parser.add_argument("hostname")
    parser.add_argument("-t", "--timeout", type=float, default=3, 
                        help="Timeout for each packet in seconds (default 3s)")
    parser.add_argument("-m", "--maxhops", type=int, default=30, 
                        help="Max time to live value (default 30)")
    parser.add_argument("-a", "--assemble", action="store_true",
                        help="Manual packet assembly (may not work "
                        "with certain network cards)")
    args = parser.parse_args()
    traceroute(args.hostname, args.timeout, args.maxhops, args.assemble)

if __name__ == "__main__":
    main()