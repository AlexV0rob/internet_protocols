import socket
import argparse
import struct
import concurrent.futures


def check_ntp(sock):
    sock.send(struct.pack("!QQQQQQ", (0x23 << 56), 0, 0, 0, 0, 0))
    try:
        if sock.recv(1024):
            return True
        return False
    except (socket.timeout, OSError):
        return False
    
def check_dns(sock):
    sock.send(struct.pack("!HHQBHH", 1, 0x0100, (1 << 48), 0, 1, 1))
    try:
        if sock.recv(1024)[:2] == struct.pack("!H", 1):
            return True
        return False
    except (socket.timeout, OSError):
        return False
    
def check_smtp(sock):
    old_timeout = sock.gettimeout()
    sock.settimeout(10)
    try:
        response = sock.recv(1024).decode("utf-8").strip().upper()
        is_smtp = (response.startswith("220") or "SMTP" in response)
    except socket.timeout:
        sock.send(b"NOOP\r\n")
        try:
            response = sock.recv(1024).decode("utf-8").strip().upper()
            is_smtp = response.startswith("250 OK")
        except (socket.timeout, OSError):
            is_smtp = False
    except OSError:
        is_smtp = False
    finally:
        sock.settimeout(old_timeout)
    return is_smtp

def check_pop3(sock):
    old_timeout = sock.gettimeout()
    sock.settimeout(10)
    try:
        response = sock.recv(1024).decode("utf-8").strip().upper()
        is_pop3 = (response.startswith("+OK") or "POP3" in response)
    except socket.timeout:
        sock.send(b"NOOP\r\n")
        try:
            response = sock.recv(1024).decode("utf-8").strip().upper()
            is_pop3 = response.startswith("-ERR")
        except (socket.timeout, OSError):
            is_pop3 = False
    except OSError:
        is_pop3 = False
    finally:
        sock.settimeout(old_timeout)
    return is_pop3

def check_imap(sock):
    old_timeout = sock.gettimeout()
    sock.settimeout(10)
    try:
        response = sock.recv(1024).decode("utf-8").strip().upper()
        is_imap = (response.startswith("* OK") or "IMAP" in response)
    except socket.timeout:
        sock.send(b"A1 NOOP\r\n")
        try:
            response = sock.recv(1024).decode("utf-8").strip().upper()
            is_imap = response.startswith("A1 OK NOOP")
        except (socket.timeout, OSError):
            is_imap = False
    except OSError:
        is_imap = False
    finally:
        sock.settimeout(old_timeout)
    return is_imap

def check_http(sock):
    old_timeout = sock.gettimeout()
    sock.settimeout(10)
    sock.send(b"GET / HTTP/1.0\r\n\r\n")
    try:
        response = sock.recv(1024).decode("utf-8").strip().upper()
        is_http = (response.startswith("HTTP/"))
    except (socket.timeout, OSError):
        is_http = False
    finally:
        sock.settimeout(old_timeout)
    return is_http

def check_service_tcp(sock):
    if check_http(sock):
        return "HTTP"
    if check_smtp(sock):
        return "SMTP"
    if check_pop3(sock):
        return "POP3"
    if check_imap(sock):
        return "IMAP"
    if check_dns(sock):
        return "DNS"
    return ""

def check_service_udp(sock):
    if check_dns(sock):
        return "DNS"
    if check_ntp(sock):
        return "NTP"
    return ""

def check_tcp_port(address, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((address, port))
        return ("TCP", port, check_service_tcp(sock))
    except (socket.timeout, OSError):
        return None
    finally:
        sock.close

def check_udp_port(address, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        sock.connect((address, port))
        sock.send(b"")
        sock.recv(1024)
    except socket.timeout:
        return ("UDP", port, check_service_udp(sock))
    except OSError:
        return None
    finally:
        sock.close

def scanner(scanner_func, address, ports_range):
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=400) as executor:
        futures = [executor.submit(scanner_func, address, port)
                   for port in range(*ports_range)]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                results.append(result)
    return results

def portscan(hostname, scan_tcp, scan_udp, strong_udp, ports_range):
    results = []
    target = socket.gethostbyname(hostname)
    if scan_tcp:
        tcp_results = scanner(check_tcp_port, target, ports_range)
        results += tcp_results
    if scan_udp:
        udp_results = scanner(check_udp_port, target, ports_range)
        if strong_udp:
            udp_results = [x for x in udp_results if x[2]]
        results += udp_results
    for result in sorted(results, key=lambda x: (x[0], x[1])):
        print(*result)

def main():
    parser = argparse.ArgumentParser(prog="portscan", 
                                     description="Portscanning hostname")
    parser.add_argument("hostname", help="Hostname of target")
    parser.add_argument("-t", "--tcp", action="store_true",
                        help="Scan TCP ports")
    parser.add_argument("-u", "--udp", action="store_true",
                        help="Scan UDP ports")
    parser.add_argument("-s", "--strong-udp", action="store_true",
                        help="Shows UDP results only determined service")
    parser.add_argument("-p", "--ports", nargs=2, type=int, 
                        default=(1, 65535), 
                        help="Ports range to scan")
    args = parser.parse_args()
    if (args.ports[0] < 1 or args.ports[1] > 65535 
        or args.ports[0] > args.ports[1]):
        print("Invalid ports numbers")
    else:
        ports = (args.ports[0], args.ports[1] + 1)
        scan_tcp = args.tcp
        if not args.udp:
            scan_tcp = True
        try:
            portscan(args.hostname, scan_tcp, args.udp, args.strong_udp, ports)
        except PermissionError:
            print("Permission error, run this script as root (Administrator)"
                  "or use only TCP scanning (-t or --tcp flag)")

if __name__ == "__main__":
    main()