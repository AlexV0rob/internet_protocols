import socket
import ssl
import base64
import getpass
import argparse
import pathlib

IMAGE_EXTENSIONS_TO_MIME = {
    ".gif": "gif",
    ".jpeg": "jpeg",
    ".jpg": "jpeg",
    ".jfif": "jpeg",
    ".jpe": "jpeg",
    ".png": "png",
    ".svg": "svg+xml",
    ".svgz": "svg+xml",
    ".tig": "tiff",
    ".tiff": "tiff",
    ".ico": "vnd.microsoft.icon",
    ".wbmp": "vnd.wap.wbmp",
    ".webp": "webp",
    ".hif": "heif",
    ".heif": "heif",
    ".heifs": "heif",
    ".avci": "heif",
    ".avcs": "heif",
    ".heic": "heic",
    ".heics": "heic",
    ".avif": "avif"
}


def parse_response(response):
    lines = response.split("\r\n")
    full_code = lines[0].split()[0]
    if '-' in full_code:
        code_parts = full_code.split('-')
    else:
        code_parts = full_code.split()
    smtp_code = code_parts[0]
    serv_code = ''
    if len(code_parts) > 1:
        serv_code = code_parts[1]
    message_lines = []
    for line in lines:
        message_lines.append(line[4:])
    return (smtp_code, serv_code, message_lines)

def glue_message_lines(serv_code, lines):
    message = lines[0]
    serv_code_len = len(serv_code)
    for line in lines[1:]:
        message += ' ' + line[serv_code_len:]
    message.replace("  ", ' ')
    return message

def create_header(from_who, to, subject):
    from_encoded = base64.b64encode(from_who.encode())
    to_encoded = base64.b64encode(to.encode())
    subj_encoded = base64.b64encode(subject.encode())
    f_line = b"From: =?UTF-8?B?"
    t_line = b"?=\r\nTo: =?UTF-8?B?"
    s_line = b"?=\r\nSubject: =?UTF-8?B?"
    m_line = b"?=\r\nMIME-Version: 1.0\r\n"
    return (f_line + from_encoded + t_line + to_encoded
            + s_line + subj_encoded + m_line)

def create_body(filenames):
    boundary = "happy_pictures_mail"
    header_type = f'Content-Type: multipart/mixed; boundary="{boundary}"'
    body_type = f"Content-Type: text/plain"
    header = f"{header_type}\r\n\r\n--{boundary}\r\n{body_type}\r\n".encode()
    attachments = [b'']
    for filename in filenames:
        attachment = create_attachement(filename)
        attachments.append(attachment)
    main_part = f"\r\n\r\n--{boundary}\r\n".encode().join(attachments)
    return header + main_part + f"\r\n--{boundary}--\r\n".encode()

def create_attachement(filename):
    type = f"Content-Type: image/{IMAGE_EXTENSIONS_TO_MIME[filename.suffix]}"
    disp = f'Content-Disposition: attachment; filename="{filename.name}"'
    encoding = f"Content-Transfer-Encoding: base64"
    header = f"{type}\r\n{disp}\r\n{encoding}\r\n\r\n"
    with open(pathlib.Path(filename), mode="br") as f:
        data = base64.b64encode(f.read())
        return header.encode() + data + "\r\n".encode()

def authenticate(sock, verbose):
    try:
        socket_send(sock, "AUTH LOGIN".encode(), 
                               print_request=verbose, print_answer=verbose)
        login = input("Login: ")
        socket_send(sock, base64.b64encode(login.encode()), 
                    print_request=verbose, print_answer=verbose)
        password = getpass.getpass("Password: ")
        socket_send(sock, base64.b64encode(password.encode()), 
                               print_request=False, print_answer=verbose)
        return login
    except TypeError as e:
        raise TypeError(f"Couldn't authenticate: {e}")

def send_mail(sock, sender, from_who, to, subject, 
              filenames, verbose, size, num=0):
    mail = create_header(from_who, to, subject) + create_body(filenames)
    fragmented = False
    if size >= 0:
        limit = len(filenames)
        while len(mail) > size and limit > 0:
            limit //= 2
            fragmented = True
            mail = (create_header(from_who, to, subject) 
                    + create_body(filenames[:limit]))
        if limit == 0:
            raise Exception(f"Can't send {filenames[0]} (too large)")
        if fragmented:
            print("Fragmented mail to several smaller ones due to mail size")
        mail_message = f"MAIL FROM: <{sender}> SIZE={len(mail)}"
    else:
        mail_message = f"MAIL FROM: <{sender}>"
    socket_send(sock, mail_message.encode(), 
                print_request=verbose, print_answer=verbose)
    socket_send(sock, f"RCPT TO: <{to}>".encode(), 
                print_request=verbose, print_answer=verbose)
    socket_send(sock, "DATA".encode(), 
                print_request=verbose, print_answer=verbose)
    if fragmented or num:
        print(f"Sending mail #{num}...")
    else:
        print(f"Sending mail...")
    socket_send(sock, mail, 
                wait_response=False, print_request=False, print_answer=False)
    socket_send(sock, '.'.encode(), 
                print_request=False, print_answer=verbose)
    if fragmented or num:
        print(f"Mail #{num} sent")
    else:
        print(f"Mail sent")
    if fragmented:
        send_mail(sock, from_who, to, subject, 
                  filenames[limit:], verbose, size, num + 1)

def socket_send(sock, string, wait_response=True, 
                print_request=True, print_answer=True):
    sock.sendall(string + "\r\n".encode())
    if print_request:
        print(f"Client (you): {string.decode()}")
    if wait_response:
        response = parse_response(sock.recv(1024).decode())
        message = glue_message_lines(response[1], response[2])
        if response[0].startswith('5'):
            raise Exception(f"Got error code from server: {message}")
        if print_answer:
            print(f"Server: {message}")
        return response
    return ()

def get_files(directory):
    return [
        x for x in pathlib.Path(directory).iterdir() if x.is_file()
        and x.suffix in IMAGE_EXTENSIONS_TO_MIME
    ]

def create_ssl(sock, server, port):
    try:
        context = ssl.create_default_context()
        sock = context.wrap_socket(sock, server_hostname=server)
        return (sock, True)
    except socket.error:
        try:
            context.check_hostname = False
            sock = context.wrap_socket(sock, server_hostname=None)
            return (sock, True)
        except:
            sock = create_connection(server, port)
    return (sock, False)

def send_helo(sock, verbose):
    esmtp_features = []
    try:
        response = socket_send(sock, f"EHLO localhost".encode(), 
                               print_request=verbose, print_answer=verbose)
        esmtp_features = response[2]
    except socket.timeout:
        socket_send(sock, f"HELO localhost".encode(), 
                    print_request=verbose, print_answer=verbose)
    return esmtp_features

def create_connection(server, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((server, port))
    sock.settimeout(10)
    return sock

def get_size(features):
    size = -1
    for feature in features:
        if "SIZE" in feature.upper():
            size = int(feature.split()[-1])
            break
    return size    

def send_pics(open_ssl, server, port, to, from_who, 
              subject, auth, verbose, directory):
    files = get_files(directory)
    if files:
        try:
            try:
                sock = create_connection(server, port)
            except socket.error as e:
                print("Couldn't connect to server: ", e)
                return
            if open_ssl:
                sock, ssl_connected = create_ssl(sock, server, port)
            response = sock.recv(1024)
            if not response:
                raise TypeError("Couldn't obtain response from the server. "
                                "Try to use SSL connection (--ssl flag)")
            hello_message = parse_response(response.decode())
            if verbose:
                print(f"Server: {hello_message[1]}")
            features = send_helo(sock, verbose)
            if open_ssl and not ssl_connected:
                response = socket_send(sock, "STARTTLS".encode(), 
                                       print_request=verbose, 
                                       print_answer=verbose)
                if response[0].startswith('2'):
                    sock, ssl_connected = create_ssl(sock, server, port)
                    features = send_helo(sock, verbose)
            if open_ssl and not ssl_connected:
                print("Couldn't create SSL/TLS connection")
            sender = from_who
            if auth:
                sender = authenticate(sock, verbose)
            size = get_size(features)
            send_mail(sock, sender, from_who, to, subject, files, verbose, size)
            socket_send(sock, "QUIT".encode(), 
                        print_request=verbose, print_answer=verbose)
        finally:
            sock.close()
    else:
        print("No images in directory")

def server_port(string):
    server_info = string.split(":")
    ip = (server_info[0] if len(server_info) == 1 
          else ':'.join(server_info[:-1]))
    port = 25
    if len(server_info) > 1:
        port = int(server_info[-1])
    if port < 1 or port > 65535:
        raise Exception("Invalid port")
    return (ip, port)

def main():
    parser = argparse.ArgumentParser(
        prog="smtp_mime", 
        description="Send images from directory to email"
    )
    parser.add_argument("--ssl", action="store_true", default=False,
                        help="Use SSL connection")
    parser.add_argument("-s", "--server", type=str, required=True,
                        help="Server and port which connect to (ip[:port])")
    parser.add_argument("-t", "--to", type=str, required=True,
                        help="Reciever of mail")
    parser.add_argument("-f", "--from", type=str, default='', dest="from_who",
                        help="Sender of mail")
    parser.add_argument("--subject", type=str, default="Happy Pictures",
                        help="Subject of mail")
    parser.add_argument("--auth", action="store_true", default=False,
                        help="Do authenticate")
    parser.add_argument("-v", "--verbose", action="store_true", default=False,
                        help="Verbose sending process")
    parser.add_argument("-d", "--directory", type=str, default=pathlib.Path().cwd(),
                        help="Directory where take images from")
    args = parser.parse_args()
    try:
        ip, port = server_port(args.server)
        send_pics(args.ssl, ip, port, args.to, 
                  args.from_who, args.subject, 
                  args.auth, args.verbose, args.directory)
    except PermissionError:
        print("Permission error, run this script as root (Administrator)")
    except socket.error as e:
        print("Error during data transfer: ", e)
    except Exception as e:
        print(e)

if __name__ == "__main__":
    main()