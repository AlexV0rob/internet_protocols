import socket
import struct
import threading
import datetime
import math
import argparse

SNTP_VERSION = 4
UNIX_START = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
NTP_START = datetime.datetime(1900, 1, 1, tzinfo=datetime.timezone.utc)
NTP_SHIFT = (UNIX_START - NTP_START).total_seconds()

def get_current_time():
    now = datetime.datetime.now(datetime.timezone.utc).timestamp()
    return now + NTP_SHIFT

def convert_date_to_ntp(date):
    integer = math.floor(date) & ((1 << 32) - 1)
    decimal = math.floor((date % 1) * (2**32)) & ((1 << 32) - 1)
    return (integer << 32) | decimal

def convert_ntp_to_date(date):
    integer = date >> 32
    decimal = date & ((1 << 32) - 1)
    return float(f"{integer}.{decimal}") - NTP_SHIFT

# def unpack_udp(packet):
#     return struct.unpack("!HHHH", packet[:8]) + (packet[8:],)

def unpack_ntp(packet):
    return struct.unpack("!BBBBIIIQQQQ", packet)

def ask_ntp_server(ntp_server, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((socket.gethostbyname(ntp_server), port))
        sock.settimeout(10)
        sock.send(formNTPrequest())
        response = sock.recv(1024)
        recv_time = get_current_time()
        data = unpack_ntp(response[:48]) + (recv_time,)
    except socket.timeout:
        data = ()
    finally:
        sock.close()
    return data

def formNTPrequest():
    li_vn_mode = 0b00100011
    stratum = interval = accuracy = 0
    delay = dispersion = ref_id = 0
    upd_time = start_time = recv_time = 0
    send_time = convert_date_to_ntp(get_current_time())
    sntp = struct.pack("!BBBBIIIQQQQ", 
                       li_vn_mode, stratum, interval, accuracy,
                       delay, dispersion, ref_id, upd_time,
                       start_time, recv_time, send_time)
    return sntp

def calculate_time_shift(cli_send_time, ser_recv_time, 
                         ser_send_time, cli_recv_time):
    return ((ser_recv_time - cli_send_time)
             + (ser_send_time - cli_recv_time)) / 2

def formSNTP(li, vn, stratum, interval, accuracy, 
             delay, dispersion, ref_id, upd_time, 
             cli_time, time_recv, time_send):
    li_vn_mode = (li << 6) | (vn << 3) | 4
    sntp = struct.pack("!BBBBIIIQQQQIQQ", 
                       li_vn_mode, stratum, interval, accuracy,
                       delay, dispersion, ref_id, upd_time,
                       cli_time, time_recv, time_send, 0, 0, 0)
    return sntp

def process_client(sock, data, delay, shift, upd_time):
    packet = data[0]
    client_info = data[1]
    print(f"Client {client_info[0]}:{client_info[1]} has connected")
    recv_time = convert_date_to_ntp(get_current_time() + shift + delay)
    cli_info = unpack_ntp(packet[:(12 * 8)])
    my_ip = 0
    send_time = convert_date_to_ntp(get_current_time() + shift + delay)
    sntp = formSNTP(cli_info[0] >> 6, SNTP_VERSION, 15, 4, 
                    cli_info[3], cli_info[4], cli_info[5], 
                    my_ip, convert_date_to_ntp(upd_time),
                    cli_info[-1], recv_time, send_time)
    sock.sendto(sntp, client_info)

def start_server(delay, port):
    ntp_info = ask_ntp_server("ntp.sstf.nsk.ru", 123)
    if ntp_info:
        me_send = convert_ntp_to_date(ntp_info[8])
        se_recv = convert_ntp_to_date(ntp_info[9])
        se_send = convert_ntp_to_date(ntp_info[10])
        me_recv = ntp_info[-1]
        shift = calculate_time_shift(me_send, se_recv, 
                                     se_send, me_recv - NTP_SHIFT)
    else:
        shift = 0
        me_recv = convert_date_to_ntp(get_current_time())
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        host = socket.gethostbyname(socket.gethostname()) 
        sock.bind((host, port))
        print(f"SNTP server {host}:{port} started")
        while True:
            try:
                data = sock.recvfrom(1024)
                client = threading.Thread(
                    target=process_client, 
                    args=(sock, data, delay, shift, me_recv)
                )
                client.start()
            except ConnectionResetError:
                pass
    except PermissionError:
        print("Permission error, run this script as root (Administrator) "
              "or change port via -p option")
    finally:
        sock.close()

def main():
    parser = argparse.ArgumentParser(
        prog="sntp server", 
        description="SNTP server that can lie to its clients"
    )
    parser.add_argument("-d", "--delay", type=float, default=0, 
                        help="Delay (shift) from real time")
    parser.add_argument("-p", "--port", type=int, default=123, 
                        help="Port which socket liten as server")
    args = parser.parse_args()
    start_server(args.delay, args.port)

if __name__ == "__main__":
    main()