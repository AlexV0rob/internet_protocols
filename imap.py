import socket
import ssl
import base64
import quopri
import getpass
import argparse

CODE = 1


def parse_response(response, code=None):
    lines = response.split("\r\n")
    if code != None:
        answer = None
        for i in range(len(lines)):
            line = lines[i]
            if line.startswith(code):
                answer = line.split()
                lines[i] = ' '.join(answer[2:])
                break
        if answer:
            success_code = answer[1]
            return (code, success_code, lines)
    return ('', '', lines)

def glue_message_lines(lines):
    message = ''
    for line in lines:
        string = line
        if line.startswith("* "):
            string = line[2:]
        if string:
            message += ' ' + string
    return message

def decode_header(header):
    header_parts = header.split()
    decoded_header = []
    for header_part in header_parts:
        if header_part[0] == '=' and header_part[-1] == '=':
            charset, encoding, text = header_part.split('?')[1:4]
            if encoding.upper() == 'B':
                decoded_text = base64.b64decode(text).decode(charset)
            elif encoding.upper() == 'Q':
                decoded_text = quopri.decodestring(text).decode(charset)
            else:
                decoded_text = header_part
            if len(decoded_header):
                decoded_header[-1] += decoded_text
            else:
                decoded_header.append(decoded_text)
        else:
            decoded_header.append(header_part)
    return ' '.join(decoded_header)

def parse_header(lines):
    parse_results = {"from": '', "to": '', "subject": '', "date": ''}
    text = head = ''
    assembling = False
    for line in lines:
        if assembling:
            if line.startswith(' '):
                text += line
            else:
                content = text.split()
                if content[-1]:
                    header_content = ' '.join(content[1:])
                else:
                    header_content = ' '.join(content[1:-1])
                parse_results[head] = decode_header(header_content)
                text = ''
                assembling = False
        if (line.startswith("From:") or line.startswith("To:")
            or line.startswith("Date:") or line.startswith("Subject:")):
            text += line
            head = line[:line.index(':')].lower()
            assembling = True
    return parse_results

def parse_size(lines):
    for line in lines:
        upper_line = line.upper()
        if "RFC822.SIZE" in upper_line:
            no_brackets_line = upper_line.replace('(', '').replace(')', '')
            parts = no_brackets_line.split()
            return int(parts[parts.index("RFC822.SIZE") + 1])

def open_brackets_structure(line, index):
    structure = []
    text = ''
    line_len = len(line)
    while index < line_len:
        if line[index] == '(':
            if text:
                structure.append(text)
            text = ''
            enclosure, index = open_brackets_structure(line, index + 1)
            structure.append(enclosure)
        elif line[index] == ')':
            if text:
                structure.append(text)
            return structure, index
        elif line[index] == ' ':
            if text:
                structure.append(text)
            text = ''
        else:
            text += line[index]
        index += 1
    if text:
        structure.append(text)
    return structure, index + 1

def check_part_for_attachment(part_structure):
    disposition_index = 8
    if part_structure[0] == '"TEXT"':
        disposition_index = 9
    if disposition_index < len(part_structure):
        disposition = part_structure[disposition_index]
        if (isinstance(disposition, list)
            and len(disposition) > 0
            and disposition[0].upper() == '"ATTACHMENT"'):
            attachment = {"size": int(part_structure[6])}
            disp_params = disposition[1]
            params = part_structure[2]
            if isinstance(disp_params, list):
                disp_params_len = len(disp_params)
                for i in range(disp_params_len):
                    if (disp_params[i].upper() == '"FILENAME"' 
                        and i + 1 < disp_params_len):
                        attachment["name"] = disp_params[i + 1]
            elif isinstance(params, list):
                params_len = len(disp_params)
                for i in range(params_len):
                    if (params[i].upper() == '"NAME"' 
                        and i + 1 < params_len):
                        attachment["name"] = params[i + 1]
            return attachment
    return {}

def parse_attachments(lines):
    bodystructure = []
    for line in lines:
        upper_line = line.upper()
        if "BODYSTRUCTURE" in upper_line:
            bodystructure, _ = open_brackets_structure(upper_line, 0)
            break
    if not bodystructure:
        return ()
    attachments = []
    for elem in bodystructure:
        if (isinstance(elem, list) and len(elem) > 1
            and elem[0].upper() == "BODYSTRUCTURE"):
            for body_part in elem[1]:
                if isinstance(body_part, list) and len(body_part) >= 7:
                    attachment = check_part_for_attachment(body_part)
                    if attachment:
                        attachments.append(attachment)
            break
    return attachments

def get_mail(sock, number):
    header_request = (f"FETCH {number} BODY.PEEK["
                      f"HEADER.FIELDS (FROM TO SUBJECT DATE)]")
    response = socket_send(sock, header_request.encode())
    if response[1] != "OK":
        raise TypeError(f"Couldn't select mailbox: {response[2]}")
    mail_info = parse_header(response[2])
    response = socket_send(sock, f"FETCH {number} RFC822.SIZE".encode())
    if response[1] != "OK":
        raise TypeError(f"Couldn't select mailbox: {response[2]}")
    mail_info["size"] = parse_size(response[2])
    response = socket_send(sock, f"FETCH {number} BODYSTRUCTURE".encode())
    if response[1] != "OK":
        raise TypeError(f"Couldn't select mailbox: {response[2]}")
    mail_info["attachments"] = parse_attachments(response[2])
    mail_info["attachments_count"] = len(mail_info["attachments"])
    return mail_info

def mail_exists(lines):
    for line in lines:
        if "EXISTS" in line.upper():
            return int(line.split()[1])

def get_mailbox(sock, mail_range):
    response = socket_send(sock, "SELECT INBOX".encode())
    mail_count = 0
    if response[1] != "OK":
        raise TypeError(f"Couldn't select mailbox: "
                        f"{glue_message_lines(response[2])}")
    else:
        mail_count = mail_exists(response[2])
    print(f"You have {mail_count} mails")
    if mail_range[0] > mail_count:
        raise TypeError(f"Couldn't fetch mails: starts with "
                        f"{mail_range[0]} but {mail_count} at all")
    if mail_range[1] == -1 or mail_range[1] > mail_count:
        mail_range = (mail_range[0], mail_count + 1)
    mails_info = []
    for number in range(*mail_range):
        mail_info = get_mail(sock, number)
        mail_info["number"] = number
        mails_info.append(mail_info)
    create_table(mails_info)

def longest_line(mails_info, key, additional_key=None):
    max_len = 0
    for string in mails_info:
        value = string[key]
        if isinstance(value, list):
            for substring in value:
                if isinstance(substring, dict):
                    sub_len = 0
                    if additional_key != None:
                        sub_len = len(str(substring[additional_key]))
                    else:
                        for subvalue in substring.values():
                            sub_len += len(str(subvalue))
                    max_len = max(max_len, sub_len)
                else:
                    max_len = max(max_len, len(str(subvalue)))
        else:
            max_len = max(max_len, len(str(value)))
    return max_len

def create_header(columns_order, headers, attachments_headers, 
                  main_lengths, attachments_lengths):
    sep = '-' * (sum(main_lengths.values()) + len(headers) + 1) + '\n'
    header = sep + "|"
    for column in columns_order:
        header += f"{headers[column]:>{main_lengths[column]}}|"
    header += "\n|"
    for column in columns_order:
        symbol = ' '
        if column == "attachments":
            symbol = '-'
        header += symbol * main_lengths[column] + '|'
    header += "\n|"
    for column in columns_order:
        if column == "attachments":
            header += f"{attachments_headers['name']
                         :>{attachments_lengths['name']}}|"
            header += f"{attachments_headers['size']
                         :>{attachments_lengths['size']}}|"
        else:
            header += ' ' * main_lengths[column] + '|'
    header += '\n' + sep
    return header

def create_body(columns_order, mails_info, main_lengths, attachments_lengths):
    body = ''
    sep = '-' * (sum(main_lengths.values()) + len(main_lengths) + 1) + "\n"
    empty_string = "|"
    for column in columns_order[:-1]:
        empty_string += ' ' * main_lengths[column] + '|'
    for mail in mails_info:
        body += '|'
        for column in columns_order[:-1]:
            body += f"{mail[column]:>{main_lengths[column]}}|"
        attachments = mail["attachments"]
        if not attachments:
            body += (' ' * attachments_lengths["name"] + '|'
                      + ' ' * attachments_lengths["size"] + "|\n")
        else:
            for attachment in attachments[:-1]:
                body += (f"{attachment['name']
                            :>{attachments_lengths['name']}}|"
                         f"{attachment['size']
                            :>{attachments_lengths['size']}}|\n")
                body += empty_string
            body += (f"{attachments[-1]['name']
                        :>{attachments_lengths['name']}}|"
                     f"{attachments[-1]['size']
                        :>{attachments_lengths['size']}}|\n")
        body += sep
    return body

def create_table(mails_info):
    columns_order = ["number", "from", "to", "subject", "date", 
                     "attachments_count", "attachments"]
    headers = {
        "number": "#",
        "from": "From",
        "to": "To",
        "subject": "Subject",
        "date": "Date",
        "attachments_count": "Count",
        "attachments": "Attachments"
    }
    attachment_headers = {
        "size": "Size",
        "name": "Filename"
    }
    main_lengths = {
        key: max(len(headers[key]), longest_line(mails_info, key)) 
        for key in headers
    }
    attachment_lengths = {
        key: max(len(attachment_headers[key]), 
                 longest_line(mails_info, "attachments", key)) 
        for key in attachment_headers
    }
    main_lengths["attachments"] = sum(attachment_lengths.values()) + 1
    header = create_header(columns_order, headers, attachment_headers, 
                           main_lengths, attachment_lengths)
    body = create_body(columns_order, mails_info, 
                       main_lengths, attachment_lengths)
    with open("C:\\Users\\aleks\\OneDrive\\Desktop\\python\\internet\\mail.txt", 'w', encoding="utf-16") as f:
        print(header, body, file=f, sep='')

def socket_send(sock, string, code=None):
    global CODE
    if code == None:
        code = f"A{CODE}"
    sock.sendall(code.encode() + b' ' + string + "\r\n".encode())
    byte_response = b''
    data = sock.recv(1024)
    try:
        sock.settimeout(2)
        while not data.startswith(code.encode()):
            byte_response += data
            data = sock.recv(1024)
        byte_response += data
    except socket.error:
        pass
    finally:
        sock.settimeout(10)
    response = parse_response(byte_response.decode(), code)
    CODE += 1
    return response

def is_login_disabled(sock):
    response = socket_send(sock, f"CAPABILITY".encode())
    message = glue_message_lines(response[2]).upper()
    return "LOGINDISABLED" in message

def authenticate(sock, username):
    login_disabled = is_login_disabled(sock)
    if login_disabled:
        raise("Couldn't authenticate: login disabled. "
              "Try to use SSL/TLS connection (--ssl flag)")
    else:
        password = getpass.getpass("Password: ")
        status = socket_send(sock, f"LOGIN {username} {password}".encode())
        if status[1] != "OK":
            raise TypeError(f"Couldn't authenticate: {glue_message_lines(status[2])}")

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

def create_connection(server, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((server, port))
    sock.settimeout(10)
    return sock

def fetch_mail(open_ssl, server, port, username, mail_range):
    try:
        try:
            sock = create_connection(server, port)
        except socket.error as e:
            print("Couldn't connect to server: ", e)
            return
        if open_ssl:
            sock, ssl_connected = create_ssl(sock, server, port)
        response = b''
        data = sock.recv(1024)
        try:
            sock.settimeout(2)
            while data:
                response += data
                data = sock.recv(1024)
        except socket.error:
            pass
        finally:
            sock.settimeout(10)
        if not response:
            raise TypeError("Couldn't obtain response from the server. "
                            "Try to use SSL connection (--ssl flag)")
        if open_ssl and not ssl_connected:
            response = socket_send(sock, "STARTTLS".encode(), "A0")
            if response[1] == "OK":
                sock, ssl_connected = create_ssl(sock, server, port)
        if open_ssl and not ssl_connected:
            print("Couldn't create SSL/TLS connection")
        authenticate(sock, username)
        get_mailbox(sock, mail_range)
        socket_send(sock, "LOGOUT".encode())
    finally:
        sock.close()

def server_port(string):
    server_info = string.split(":")
    ip = ":".join(server_info[:-1])
    port = 143
    if len(server_info) > 1:
        port = int(server_info[-1])
    if port < 1 or port > 65535:
        raise Exception("Invalid port")
    return (ip, port)

def normalize_mail_range(start_range):
    if len(start_range) > 2:
        raise Exception("Too much arguments for range (expected 2)")
    if start_range[0] < 1 or (len(start_range) == 2 
                             and start_range[1] >= 0 
                             and start_range[1] <= start_range[0]):
        raise Exception("Invalid range arguments")
    mail_range = start_range
    if len(start_range) == 1:
        mail_range = (start_range[0], -1)
    return mail_range

def main():
    parser = argparse.ArgumentParser(
        prog="imap", 
        description="Retrieve email from user mailbox"
    )
    parser.add_argument("--ssl", action="store_true", default=False,
                        help="Use SSL connection")
    parser.add_argument("-s", "--server", type=str, required=True,
                        help="Server and port which connect to (ip[:port])")
    parser.add_argument("-n", nargs='+', type=int, default=(1, -1), 
                        dest="mail_range",
                        help="Range of mail (N1 [N2])")
    parser.add_argument("-u", "--user", required=True,
                        help="Username")
    args = parser.parse_args()
    try:
        ip, port = server_port(args.server)
        mail_range = normalize_mail_range(args.mail_range)
        fetch_mail(args.ssl, ip, port, args.user, mail_range)
    except PermissionError:
        print("Permission error, run this script as root (Administrator)")
    except socket.error as e:
        print("Error during data transfer: ", e)
    except Exception as e:
        print(e)

if __name__ == "__main__":
    main()