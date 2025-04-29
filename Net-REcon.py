#!/usr/bin/env python3
#Author: Daniel Ishaku Ando
#Github: https://github.com/DanishKUTE/Net-Recon

print (
"""
 ..  ...  ..   ..   ..  ...  ...  
  ...  ...  ..   ..  ...  ...  ..   ..  ...  ...  ...  ..  ...  ...  ... :^^~~~~~~^^^:. ...  ..  ...
... ...  ...  ...  ...  ..  ...  ...  ...  ... ...  ...     .:^::.. .   :77~7!^^^^^^^~!!^....  ...  
.............................     .....................  ~J5G#####G?.....~!!7!~~~~~~^ ..~~..........
  ...  ... .... .... ... .. .:^~^:. ... ...  ... ....  .5&&&&&&&&P&&~ ..  .!!^^^^^^~7:   .. .... ...
...  ..  ...  ...  ...    .?G##BBPY~  ...  ..  ...  .. 7&&&&&&&&GJ#&^  ... ^~~~!!!!!^...  ...  ...  
  ...  ...  ..   ..   .^~!5&@&&BBBPP!   ...  ...  ...  Y&&&&&&&5~?#G ... ~~.:~7!!!~.~7^ ...  ..  ...
..   ..  ...  ...  .~YB&@@@&&&####GPP7~^.  ... ...  .. J&&&&&&&~:7#?   ....^^~!~~^:::...  ...  ...  
  ...  ...  ..   ..7&@@&B5&@#?J555YY555YJJ?7!~^.  ..   :YB&&&&&YJ#&! ...   7~~G~.  ~!.  ...  ..   ..
..   ..  ...  ...  Y@@@GPG@B~    .....::...:.   ..  ..   .:?&#GGPPG?.  .. ^B~7PP...   ..  ...  ...  
  ...  ...  ..   .~5###BG5?:   ..   ..  ...  ...  ..  ~JYYJYP5!!^^!YY!.  .G#J5#@!  ...  ...  ..  ...
...  ..  ...  ..^P@@#P#@Y   ...  ...  ...  ..  ...  .?PB#&&&#G7^!!!GB#5^ ~&#GB&@J ..  ..  ...  ...  
  ...  ... .... 5@@&JY#@J ...  ... .... ...  ...  ..?G&@@@@@&G?:^!:JG&@B!!B@@@@@Y  ...  ... .... ...
............... 7&&&##&Y. ........................ 7B&@@&&@@@&GJ^~!5B&@@&GP&@@@@! ..................
... ...  ...  .7B&#PP#P ..  ...  ...  ...  ... .. ^B@@B7&&&@@@@&G5G#&&&@@@B&@@@#:... ...  ...  ...  
  ...  ...  . !&@&7J?G#.  ...  ..   ..  ...  ..  ^B@@#^ Y@GGBB###P5##5!~G@@@@@@G.  ...  ...  ..  ...
...  ..  ...  ~&@@G5G&7 ..  ...  ...  ...  ..  ^Y&@@@7  .B@&BBGB5!~J!   .7#@@@@? ..   ..  ...  ...  
  ...  ...  .. !BB###G?.  ...  ..   ..  ...  !P&@@@@J  .:5@@&&#GPJJY ...  :J#@@~.  ...  ...  ..   ..
..   ..  ...   !#&@B?GPP^.  ...  ...  ..  :JG@@@@@@Y .~JGBGPYYY#&??5.  ...  :7?. ..   ..  ...  ...  
  ...  ...  .. J&&@#J55@J ...  ..   ....!?J&&@@@@@P^!YPBBBGY5##&Y!!?:...  ..   ..  ...  ...  ..   ..
...  ..  ...  .^P&@@@###5!^. ..  ..:~!~~~?JPP#@@@&B#&&&&&&&#BY5Y!!~!~  ...  ...  ..   ..  ...  ...  
  ...  ...  ... .?PB5G#&@#YJ~. .. .~7??!Y#YJB&@@&&&&&&&&&B5PJ7!!!7^~^...  ..  ...  ...  ...  ..  ...
................   ~P&&&@G?P55. ..:^!J~ 7@YJB&@&&&&&&&&#&&5?!^~~7!^!: ..............................
.................. :B#&&&@&&@#.     ::  :#YJB&&&&#GB###&@#5?~~!77~~Y?  .............................
  ...  ...  ... ... 7GB#&&&&BG57J?^.^!??Y&JY@&&#&&#G5#@@#Y7!!7J?!7Y@@Y.   ..  ...  ...  ...  ..  ...
...  ..  ...  ...  ..^JGB#BG#@&JYPPYJG@@@&5PPBBB&@@#B@@BJ7!!!7!~!77B&@P^.   ...  ..   ..  ...  ...  
  ...  ...  ..   ..   .:~7P&&&@@#&@&&@&&#####PG@@@BG@@B?!!7?7!!JBB^~5&&#BY7^   ..  ...  ...  ..   ..
..   ..  ...  ...  ...  . ~B&&##&&&@&#BB#&@&GPG#&#P&&#J77?7!!77Y&@Y?!?5YG#&&GJ~.  .   ..  ...  ...  
  ...  ...  ..   ..  ...  .?BB####&&B#&@@&##B&##GB#BGY77777J7~^~?PJ&&PJ!~~7JP#&G5!. ..  ...  ..   ..
...  ..  ...  ...  ...  :JB#&#B@&&&GG&@&&#BBB#&@@&#P??77?5#@GG&BBGPPB&@&BY~^^!?P#&#?. ..  ...  ...  
  ...  ...  ..  ...    !B@@#J??Y5&@&BPJ7?YPB&@&#57^:::.^~~?P5B#&@@BBBYJP#@PG! .~7?PBB~  ...  ..  ...
... .... ...  ...  . .Y@@@B?~^:!#&&B?:.^G@&BBP?~:.   ..  .^^^~!77YP5&&!:!J5&&?  .^!?#&J.  ...  ...  
................... :G@@BJ7:. 7&@#B7. :B@@&BJ~.  ........      ...:~?#G.  :JB@P.  :~~P&Y. ..........
  ...  ...  ... .. ^#@@57^.. !&@@#?. :G@@#P?  ..  ... .... ...  .. ~~Y&Y   .J#@Y.  .^7P&Y . .... ...
...  ..  ...  ... ~&@BY7:.  ~&@##?. .G@@&G~..  ...  ...  ...  ..   :7~B#:.  :YG#? .  ^7#&~ ..  ...  
  ...  ...  ..   ~&@#?~.  ..B@@&J.  J@@@BJ.  ...  ...  ..  ...  ....7^Y&7 .. ^5@#. ...!5BG.  ..  ...
..   ..  ...  ...B@B5!. .. 7@&&Y. .:#@@&P. ..   ..  ...  ...  ..   .!^J&Y   .:J##J    ^7B@!..  ...  
  ...  ...  ..  ?@#?~...  .G@&P^.  7@@&G^..  ...  ..   ..  ...  ... ~~?#5 ..  !5&B.....!5@5  ..   ..
..   ..  ...  .:&@Y!:   ..~&B#7  ..G@&#J   ..   ..  ...  ...  ..   .^~7&P.  ..^?&@7   .~7##:.  ...  
  ...  ...  .. ?@#J: ...  ?@BJ... ^&@@G. ..  ...  ...  ..  ...  ... :~?&P ..  :YG#5 .. :5#&^ ..  ...
...  ..  ...   5@B~...  . 5@#7.   7@@&J..  ..  ...  ...  ...  ... ..^?5@P   ...~5@B. ...#@&~   ...  
...............B@B. .... .G@B^ .. 7@@&? ........................... ^&@@Y .... ~5@#...  5@&^ .......
............. :#@J ..... .#@&^ .. ~@@&! ........................... ^&&@7 .... !@@#: .. 7@#: .......
...  ..  ...  :#@? ...  ..B@#:.   :#@&! .  ..  ...  ...  ...  ... ..:#@#:.  .. :#@#. .. !@B:.  ...  
  ...  ...  .. 7G!   ...  P@B. ..  5@@? ...  ...  ...  ..  ...  ... :&@?  ..   .#@G ..  !@G  ..  ...
..   ..  ...  ...  ...  . J@#:.  ..!@@J .  ..   ..  ...  ...  ..   .^&G...  ....#&~   . ?@? .  ...  
  ...  ...  ..   ..  ...  :B&^ ..   P@G ...  ...  ..   ..  ...  ...  ^:   ..   .?^ ...  !?.. ..   ..
..   ..  ...  ...  ...  .. .^..  .. :G&!   ..   ..  ...  ...  ..   ..  ...  ...  ... .::..:^.  ...                                              
                                            
"""
)

import socket
import argparse
import threading
import subprocess
import os
import sys
import time
import struct
import select
import urllib.request
import whois
from colorama import Fore, Style, init
from http.server import HTTPServer, SimpleHTTPRequestHandler

init(autoreset=True)  # Initialize colorama for auto-reset colors

class EliteNetCat:
    def __init__(self, args):
        self.args = args
        self.buffer = b""
        self.socket = None
        self.running = True

    def create_socket(self, af=socket.AF_INET, sock_type=socket.SOCK_STREAM):
        try:
            self.socket = socket.socket(af, sock_type)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            print(f"{Fore.BLUE}[+] Socket created successfully.{Style.RESET_ALL}")
        except socket.error as e:
            print(f"{Fore.RED}[-] Socket creation failed: {e}{Style.RESET_ALL}")
            sys.exit(1)

    def server_loop(self):
        self.create_socket()
        try:
            self.socket.bind((self.args.target, self.args.port))
            self.socket.listen(5)
            print(f"{Fore.GREEN}[+] Listening on {self.args.target}:{self.args.port}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Failed to bind/listen: {e}{Style.RESET_ALL}")
            sys.exit(1)

        while self.running:
            try:
                conn, addr = self.socket.accept()
                print(f"{Fore.CYAN}[+] Connection established from {addr}{Style.RESET_ALL}")
                if self.args.execute:
                    self.execute_command(conn)
                elif self.args.upload:
                    self.handle_file_upload(conn)
                elif self.args.command:
                    self.handle_interactive_shell(conn)
                else:
                    print(f"{Fore.YELLOW}[!] No action specified, closing connection.{Style.RESET_ALL}")
                    conn.close()
            except KeyboardInterrupt:
                print(f"\n{Fore.RED}[!] Server shutting down...{Style.RESET_ALL}")
                self.running = False
                self.socket.close()
                break
            except Exception as e:
                print(f"{Fore.RED}[-] Error during connection handling: {e}{Style.RESET_ALL}")

    def client_sender(self):
        self.create_socket()
        try:
            self.socket.connect((self.args.target, self.args.port))
            print(f"{Fore.GREEN}[+] Connected to {self.args.target}:{self.args.port}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Connection failed: {e}{Style.RESET_ALL}")
            sys.exit(1)

        if self.args.upload:
            self.handle_file_upload(self.socket)
        elif self.args.execute:
            self.execute_command(self.socket)
        elif self.args.command:
            self.handle_interactive_shell(self.socket)
        else:
            print(f"{Fore.YELLOW}[!] No action specified, closing connection.{Style.RESET_ALL}")
            self.socket.close()

    def handle_interactive_shell(self, conn):
        conn.send(b"EliteNetCat Interactive Shell\n")
        print(f"{Fore.BLUE}[+] Interactive shell started. Type 'exit' to quit.{Style.RESET_ALL}")
        while self.running:
            try:
                conn.send(b"shell> ")
                cmd = conn.recv(4096).decode().strip()
                if cmd.lower() == "exit":
                    print(f"{Fore.YELLOW}[!] Exit command received. Closing shell.{Style.RESET_ALL}")
                    self.running = False
                    break
                if not cmd:
                    continue
                print(f"{Fore.MAGENTA}[>] Executing command: {cmd}{Style.RESET_ALL}")
                output = subprocess.run(cmd, shell=True, capture_output=True)
                response = output.stdout + output.stderr
                if not response:
                    response = b"Command executed with no output.\n"
                conn.send(response)
            except Exception as e:
                error_msg = f"Shell error: {e}\n".encode()
                conn.send(error_msg)
        conn.close()

    def execute_command(self, conn):
        print(f"{Fore.MAGENTA}[>] Executing command: {self.args.execute}{Style.RESET_ALL}")
        try:
            output = subprocess.check_output(self.args.execute, shell=True, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            output = e.output
        except Exception as e:
            output = f"Execution failed: {e}".encode()
        conn.send(output)
        conn.close()
        print(f"{Fore.GREEN}[+] Command execution completed and connection closed.{Style.RESET_ALL}")

    def handle_file_upload(self, conn):
        if self.args.upload and self.args.listen:
            print(f"{Fore.BLUE}[+] Ready to receive file and save as: {self.args.upload}{Style.RESET_ALL}")
            with open(self.args.upload, "wb") as f:
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    f.write(data)
            print(f"{Fore.GREEN}[+] File saved to {self.args.upload}{Style.RESET_ALL}")
        elif self.args.upload and not self.args.listen:
            try:
                with open(self.args.upload, "rb") as f:
                    data = f.read()
                    conn.sendall(data)
                print(f"{Fore.GREEN}[+] File {self.args.upload} sent successfully.{Style.RESET_ALL}")
            except FileNotFoundError:
                print(f"{Fore.RED}[-] File {self.args.upload} not found.{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[-] Error sending file: {e}{Style.RESET_ALL}")

    def udp_handler(self):
        self.create_socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.socket.bind((self.args.target, self.args.port))
            print(f"{Fore.GREEN}[+] UDP listening on {self.args.target}:{self.args.port}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] UDP bind failed: {e}{Style.RESET_ALL}")
            sys.exit(1)

        def receiver():
            while self.running:
                try:
                    data, addr = self.socket.recvfrom(4096)
                    print(f"{Fore.MAGENTA}[UDP] Received from {addr}: {data.decode(errors='ignore')}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}[-] UDP receive error: {e}{Style.RESET_ALL}")

        def sender():
            while self.running:
                try:
                    data = input()
                    self.socket.sendto(data.encode(), (self.args.target, self.args.port))
                except KeyboardInterrupt:
                    print(f"\n{Fore.RED}[!] UDP sender interrupted by user.{Style.RESET_ALL}")
                    self.running = False
                    break
                except Exception as e:
                    print(f"{Fore.RED}[-] UDP send error: {e}{Style.RESET_ALL}")

        threading.Thread(target=receiver, daemon=True).start()
        threading.Thread(target=sender, daemon=True).start()

        try:
            while self.running:
                time.sleep(0.1)
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}[!] UDP handler shutting down...{Style.RESET_ALL}")
            self.running = False
            self.socket.close()

def port_scan(target, start_port, end_port):
    print(f"{Fore.YELLOW}[+] Starting port scan on {target} from {start_port} to {end_port}{Style.RESET_ALL}")
    open_ports = []
    try:
        for port in range(start_port, end_port + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target, port))
            if result == 0:
                print(f"{Fore.GREEN}[OPEN] Port {port}{Style.RESET_ALL}")
                open_ports.append(port)
            sock.close()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Port scan interrupted by user.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] Port scan error: {e}{Style.RESET_ALL}")

    if not open_ports:
        print(f"{Fore.RED}[!] No open ports found in the specified range.{Style.RESET_ALL}")
    else:
        print(f"{Fore.CYAN}[+] Open ports: {', '.join(map(str, open_ports))}{Style.RESET_ALL}")

def banner_grab(target, port):
    print(f"{Fore.YELLOW}[+] Grabbing banner from {target}:{port}{Style.RESET_ALL}")
    try:
        sock = socket.socket()
        sock.settimeout(3)
        sock.connect((target, port))
        sock.send(b"\r\n")
        banner = sock.recv(1024)
        print(f"{Fore.GREEN}[BANNER] {banner.decode(errors='ignore').strip()}{Style.RESET_ALL}")
        sock.close()
    except Exception as e:
        print(f"{Fore.RED}[-] Failed to grab banner: {e}{Style.RESET_ALL}")

def run_http_server(port):
    print(f"{Fore.YELLOW}[+] Starting simple HTTP server on port {port}{Style.RESET_ALL}")
    server_address = ('', port)
    httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)
    try:
        print(f"{python} ")
        print(f"{Fore.GREEN}[+] HTTP server running. Press Ctrl+C to stop.{Style.RESET_ALL}")
        httpd.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] HTTP server stopped by user.{Style.RESET_ALL}")
        httpd.server_close()
    except Exception as e:
        print(f"{Fore.RED}[-] HTTP server error: {e}{Style.RESET_ALL}")

def dns_lookup(domain):
    print(f"{Fore.YELLOW}[+] Resolving domain: {domain}{Style.RESET_ALL}")
    try:
        ip = socket.gethostbyname(domain)
        print(f"{Fore.GREEN}[DNS] {domain} resolved to {ip}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] DNS lookup failed: {e}{Style.RESET_ALL}")

def whois_lookup(domain):
    print(f"{Fore.YELLOW}[+] Performing WHOIS lookup for: {domain}{Style.RESET_ALL}")
    try:
        w = whois.whois(domain)
        print(f"{Fore.GREEN}[WHOIS]\n{w}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] WHOIS lookup failed: {e}{Style.RESET_ALL}")

def http_header_grab(url):
    print(f"{Fore.YELLOW}[+] Fetching HTTP headers from: {url}{Style.RESET_ALL}")
    try:
        with urllib.request.urlopen(url) as response:
            headers = response.getheaders()
            print(f"{Fore.CYAN}[HTTP HEADERS]{Style.RESET_ALL}")
            for header in headers:
                print(f"{Fore.GREEN}{header[0]}: {header[1]}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] Failed to fetch headers: {e}{Style.RESET_ALL}")

def tcp_proxy(local_host, local_port, remote_host, remote_port):
    print(f"{Fore.YELLOW}[+] Starting TCP proxy {local_host}:{local_port} -> {remote_host}:{remote_port}{Style.RESET_ALL}")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind((local_host, local_port))
        server.listen(5)
        print(f"{Fore.GREEN}[+] TCP proxy listening on {local_host}:{local_port}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] TCP proxy bind/listen failed: {e}{Style.RESET_ALL}")
        sys.exit(1)

    def handle_client(client_socket):
        try:
            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_socket.connect((remote_host, remote_port))
            print(f"{Fore.CYAN}[+] Connected to remote {remote_host}:{remote_port}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Remote connection failed: {e}{Style.RESET_ALL}")
            client_socket.close()
            return

        def forward(source, destination):
            while True:
                try:
                    data = source.recv(4096)
                    if not data:
                        break
                    destination.send(data)
                except Exception:
                    break

        t1 = threading.Thread(target=forward, args=(client_socket, remote_socket))
        t2 = threading.Thread(target=forward, args=(remote_socket, client_socket))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        client_socket.close()
        remote_socket.close()
        print(f"{Fore.YELLOW}[!] Connection closed.{Style.RESET_ALL}")

    try:
        while True:
            client_sock, addr = server.accept()
            print(f"{Fore.CYAN}[+] Incoming connection from {addr}{Style.RESET_ALL}")
            client_thread = threading.Thread(target=handle_client, args=(client_sock,))
            client_thread.start()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] TCP proxy stopped by user.{Style.RESET_ALL}")
        server.close()

def checksum(source_string):
    sum = 0
    countTo = (len(source_string) // 2) * 2
    count = 0
    while count < countTo:
        thisVal = source_string[count + 1] * 256 + source_string[count]
        sum = sum + thisVal
        sum = sum & 0xffffffff
        count = count + 2
    if countTo < len(source_string):
        sum = sum + source_string[len(source_string) - 1]
        sum = sum & 0xffffffff

    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def icmp_ping(host, count=4, timeout=1):
    print(f"{Fore.YELLOW}[+] Pinging {host} with {count} packets...{Style.RESET_ALL}")
    try:
        icmp = socket.getprotobyname("icmp")
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    except PermissionError:
        print(f"{Fore.RED}[-] ICMP messages can only be sent from processes running as root/administrator.{Style.RESET_ALL}")
        return
    except Exception as e:
        print(f"{Fore.RED}[-] Socket error: {e}{Style.RESET_ALL}")
        return

    packet_id = os.getpid() & 0xFFFF

    def create_packet(seq):
        header = struct.pack("bbHHh", 8, 0, 0, packet_id, seq)
        data = struct.pack("d", time.time())
        chksum = checksum(header + data)
        header = struct.pack("bbHHh", 8, 0, socket.htons(chksum), packet_id, seq)
        return header + data

    for seq in range(count):
        packet = create_packet(seq)
        try:
            sock.sendto(packet, (host, 1))
            start_time = time.time()
            while True:
                ready = select.select([sock], [], [], timeout)
                if ready[0] == []:  # Timeout
                    print(f"{Fore.RED}Request timed out.{Style.RESET_ALL}")
                    break
                recv_packet, addr = sock.recvfrom(1024)
                icmp_header = recv_packet[20:28]
                type, code, checksum_recv, p_id, sequence = struct.unpack("bbHHh", icmp_header)
                if p_id == packet_id and sequence == seq:
                    time_sent = struct.unpack("d", recv_packet[28:28 + 8])[0]
                    rtt = (time.time() - time_sent) * 1000
                    print(f"{Fore.GREEN}Reply from {addr[0]}: seq={seq} time={rtt:.2f} ms{Style.RESET_ALL}")
                    break
        except Exception as e:
            print(f"{Fore.RED}Ping failed: {e}{Style.RESET_ALL}")
        time.sleep(1)
    sock.close()

def main():
    parser = argparse.ArgumentParser(description="Net-Recon  Port Scanner, Banner Grabber, HTTP Server, DNS Lookup, Whois, HTTP Header Grabber, TCP Proxy, ICMP Ping")
    parser.add_argument("-t", "--target", help="Target IP address or domain (default: 0.0.0.0)", default="0.0.0.0")
    parser.add_argument("-p", "--port", type=int, help="Target port")
    parser.add_argument("-l", "--listen", action="store_true", help="Listen mode")
    parser.add_argument("-e", "--execute", help="Execute command upon connection")
    parser.add_argument("-u", "--upload", help="Upload file path")
    parser.add_argument("-c", "--command", action="store_true", help="Interactive command shell")
    parser.add_argument("-d", "--udp", action="store_true", help="Use UDP protocol")
    parser.add_argument("--scan", action="store_true", help="Port scan mode")
    parser.add_argument("--scan-start", type=int, default=1, help="Start port for scanning")
    parser.add_argument("--scan-end", type=int, default=1024, help="End port for scanning")
    parser.add_argument("--banner", action="store_true", help="Banner grab mode")
    parser.add_argument("--http", action="store_true", help="Run simple HTTP server")
    parser.add_argument("--dns", action="store_true", help="DNS lookup")
    parser.add_argument("--whois", action="store_true", help="WHOIS lookup")
    parser.add_argument("--http-headers", action="store_true", help="HTTP header grabber")
    parser.add_argument("--proxy", nargs=4, metavar=('LHOST', 'LPORT', 'RHOST', 'RPORT'), help="TCP proxy mode: local_host local_port remote_host remote_port")
    parser.add_argument("--ping", action="store_true", help="ICMP ping")
    parser.add_argument("--ping-count", type=int, default=4, help="Number of ping packets to send")
    args = parser.parse_args()

    # Validate required args for certain modes
    if args.scan or args.banner or args.dns or args.whois or args.http_headers or args.ping:
        if not args.target:
            parser.error("Target IP/domain is required for this mode")
    if args.banner and not args.port:
        parser.error("Port is required for banner grabbing")
    if args.http and not args.port:
        parser.error("Port is requiredfor HTTP server")
    if args.proxy:
        try:
            int(args.proxy[1])
            int(args.proxy[3])
        except ValueError:
            parser.error("Proxy ports must be integers")

    if args.scan:
        port_scan(args.target, args.scan_start, args.scan_end)
        return

    if args.banner:
        banner_grab(args.target, args.port)
        return

    if args.http:
        run_http_server(args.port)
        return

    if args.dns:
        dns_lookup(args.target)
        return

    if args.whois:
        whois_lookup(args.target)
        return

    if args.http_headers:
        url = args.target
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url
        http_header_grab(url)
        return

    if args.proxy:
        local_host = args.proxy[0]
        local_port = int(args.proxy[1])
        remote_host = args.proxy[2]
        remote_port = int(args.proxy[3])
        tcp_proxy(local_host, local_port, remote_host, remote_port)
        return

    if args.ping:
        icmp_ping(args.target, count=args.ping_count)
        return

    netcat = EliteNetCat(args)

    if args.udp:
        netcat.udp_handler()
    elif args.listen:
        netcat.server_loop()
    else:
        if not args.target or not args.port:
            parser.error("Target and port are required for client mode")
        netcat.client_sender()

if __name__ == "__main__":
    main()
