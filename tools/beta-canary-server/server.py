#!/usr/bin/env python3
import argparse
import hashlib
import ipaddress
import json
import os
import signal
import socket
import socketserver
import ssl
import struct
import threading
import time
import urllib.parse

SCHEMA = 1
MAX_REQUEST = 32768


def family_name(address):
    return "ipv6" if ipaddress.ip_address(address.split("%")[0]).version == 6 else "ipv4"


def observation(token, protocol, peer, local, instance, ingress_ifindex=None, fingerprint=None):
    result = {
        "schema": SCHEMA,
        "token": token,
        "protocol": protocol,
        "family": family_name(peer[0]),
        "observed_address": peer[0],
        "observed_port": peer[1],
        "local_destination": local[0],
        "server_instance": instance,
        "timestamp": int(time.time()),
    }
    if ingress_ifindex is not None:
        result["ingress_ifindex"] = ingress_ifindex
    if fingerprint:
        result["fingerprint"] = fingerprint
    return result


def socket_fingerprint(sock):
    facts = {}
    try:
        tcp_info = sock.getsockopt(socket.IPPROTO_TCP, getattr(socket, "TCP_INFO", 11), 256)
        facts["tcp_info_sha256"] = hashlib.sha256(tcp_info).hexdigest()
    except OSError:
        pass
    if isinstance(sock, ssl.SSLSocket):
        facts["tls_version"] = sock.version()
        facts["tls_cipher"] = (sock.cipher() or (None,))[0]
        facts["tls_alpn"] = sock.selected_alpn_protocol()
    return facts


class CanaryHttpHandler(socketserver.StreamRequestHandler):
    def handle(self):
        request_line = self.rfile.readline(MAX_REQUEST).decode("iso-8859-1").strip()
        if not request_line:
            return
        parts = request_line.split(" ")
        if len(parts) != 3:
            self.send_error(400, "bad request")
            return
        method, target, http_version = parts
        while True:
            line = self.rfile.readline(MAX_REQUEST)
            if line in (b"\r\n", b"\n", b""):
                break
        parsed = urllib.parse.urlsplit(target)
        params = urllib.parse.parse_qs(parsed.query)
        token = params.get("token", [""])[0]
        schema = params.get("schema", [""])[0]
        requested_family = params.get("family", [""])[0]
        if method != "GET" or parsed.path != "/v1/observe" or schema != str(SCHEMA) or not valid_token(token):
            self.send_error(400, "invalid canary request")
            return
        if requested_family != family_name(self.client_address[0]):
            self.send_error(409, "family mismatch")
            return
        protocol = "https" if isinstance(self.connection, ssl.SSLSocket) else "http"
        fingerprint = socket_fingerprint(self.connection)
        fingerprint["http_version"] = http_version
        body = json.dumps(
            observation(
                token,
                protocol,
                self.client_address,
                self.connection.getsockname(),
                self.server.instance,
                fingerprint=fingerprint,
            ),
            separators=(",", ":"),
        ).encode("utf-8")
        headers = (
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Cache-Control: no-store\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        self.wfile.write(headers + body)

    def send_error(self, code, message):
        body = json.dumps({"error": message}, separators=(",", ":")).encode("utf-8")
        self.wfile.write(
            f"HTTP/1.1 {code} Error\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode("ascii")
            + body
        )


class CanaryTcpHandler(socketserver.StreamRequestHandler):
    def handle(self):
        raw = self.rfile.readline(MAX_REQUEST)
        if len(raw) >= MAX_REQUEST:
            return
        try:
            request = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return
        token = request.get("token", "")
        if request.get("schema") != SCHEMA or not valid_token(token):
            return
        expected_family = family_name(self.client_address[0])
        if request.get("family") != expected_family:
            return
        reply = observation(
            token,
            "tcp",
            self.client_address,
            self.request.getsockname(),
            self.server.instance,
            fingerprint=socket_fingerprint(self.request),
        )
        self.wfile.write(json.dumps(reply, separators=(",", ":")).encode("utf-8") + b"\n")


class ThreadingTcpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, handler, instance, address_family, tls_context=None):
        self.address_family = address_family
        self.instance = instance
        self.tls_context = tls_context
        super().__init__(address, handler)

    def get_request(self):
        sock, address = super().get_request()
        if self.tls_context:
            try:
                sock = self.tls_context.wrap_socket(sock, server_side=True)
            except Exception:
                sock.close()
                raise
        return sock, address


class UdpCanaryThread(threading.Thread):
    def __init__(self, bind_address, port, instance, dns_zone=None):
        super().__init__(daemon=True)
        self.instance = instance
        self.dns_zone = dns_zone
        self.family = socket.AF_INET6 if ":" in bind_address else socket.AF_INET
        self.sock = socket.socket(self.family, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.pktinfo_type = None
        try:
            if self.family == socket.AF_INET:
                self.pktinfo_type = getattr(socket, "IP_PKTINFO", 8)
                self.sock.setsockopt(socket.IPPROTO_IP, self.pktinfo_type, 1)
            else:
                self.pktinfo_type = getattr(socket, "IPV6_PKTINFO", 50)
                recv_pktinfo = getattr(socket, "IPV6_RECVPKTINFO", 49)
                self.sock.setsockopt(socket.IPPROTO_IPV6, recv_pktinfo, 1)
        except OSError:
            self.pktinfo_type = None
        self.sock.bind((bind_address, port))
        self.stopped = threading.Event()

    def close(self):
        self.stopped.set()
        self.sock.close()

    def run(self):
        while not self.stopped.is_set():
            try:
                data, ancillary, _, peer = self.sock.recvmsg(MAX_REQUEST, 512)
            except OSError:
                return
            local, ifindex = self.read_pktinfo(ancillary)
            local = local or self.sock.getsockname()[0]
            try:
                if self.dns_zone:
                    response = dns_response(data, peer, local, self.instance, self.dns_zone)
                else:
                    request = json.loads(data)
                    token = request.get("token", "")
                    if request.get("schema") != SCHEMA or not valid_token(token):
                        continue
                    if request.get("family") != family_name(peer[0]):
                        continue
                    response = json.dumps(
                        observation(token, "udp", peer, (local, self.sock.getsockname()[1]), self.instance, ifindex),
                        separators=(",", ":"),
                    ).encode("utf-8")
                self.sock.sendto(response, peer)
            except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
                continue

    def read_pktinfo(self, ancillary):
        for level, kind, data in ancillary:
            if self.family == socket.AF_INET and level == socket.IPPROTO_IP and kind == self.pktinfo_type and len(data) >= 12:
                ifindex = struct.unpack("=I", data[:4])[0]
                return socket.inet_ntop(socket.AF_INET, data[8:12]), ifindex
            if self.family == socket.AF_INET6 and level == socket.IPPROTO_IPV6 and kind == self.pktinfo_type and len(data) >= 20:
                return socket.inet_ntop(socket.AF_INET6, data[:16]), struct.unpack("=I", data[16:20])[0]
        return None, None


def valid_token(token):
    return len(token) == 32 and all(ch in "0123456789abcdef" for ch in token)


def decode_dns_name(data, offset):
    labels = []
    while offset < len(data):
        length = data[offset]
        offset += 1
        if length == 0:
            return ".".join(labels).lower(), offset
        if length > 63 or offset + length > len(data):
            raise ValueError("bad DNS name")
        labels.append(data[offset:offset + length].decode("ascii"))
        offset += length
    raise ValueError("bad DNS name")


def dns_response(query, peer, local, instance, zone):
    if len(query) < 12:
        raise ValueError("short DNS query")
    query_id, flags, qdcount = struct.unpack("!HHH", query[:6])
    if qdcount != 1:
        raise ValueError("DNS query count")
    qname, offset = decode_dns_name(query, 12)
    if offset + 4 > len(query):
        raise ValueError("short DNS question")
    qtype, qclass = struct.unpack("!HH", query[offset:offset + 4])
    question_end = offset + 4
    suffix = "." + zone
    labels = qname.removesuffix(suffix).split(".") if qname.endswith(suffix) else []
    token = labels[-1] if len(labels) >= 2 else ""
    if qtype != 16 or qclass != 1 or not valid_token(token):
        return struct.pack("!HHHHHH", query_id, 0x8183, 1, 0, 0, 0) + query[12:question_end]
    text = f"v={SCHEMA};t={token};src={peer[0]};fam={family_name(peer[0])};srv={instance};ts={int(time.time())}"
    encoded = text.encode("utf-8")
    if len(encoded) > 255:
        raise ValueError("TXT response too large")
    header = struct.pack("!HHHHHH", query_id, 0x8180, 1, 1, 0, 0)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 0, len(encoded) + 1) + bytes([len(encoded)]) + encoded
    return header + query[12:question_end] + answer


def start_tcp(bind, port, handler, instance, tls_context=None):
    family = socket.AF_INET6 if ":" in bind else socket.AF_INET
    server = ThreadingTcpServer((bind, port), handler, instance, family, tls_context)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def main():
    parser = argparse.ArgumentParser(description="Project-controlled RKNHardering beta canary reference server")
    parser.add_argument("--bind4", default="127.0.0.1")
    parser.add_argument("--bind6", default="::1")
    parser.add_argument("--http-port", type=int, default=18080)
    parser.add_argument("--https-port", type=int)
    parser.add_argument("--tcp-port", type=int, default=18081)
    parser.add_argument("--udp-port", type=int, default=18082)
    parser.add_argument("--dns-port", type=int, default=15353)
    parser.add_argument("--dns-zone", default="canary.invalid")
    parser.add_argument("--instance", default=socket.gethostname()[:64])
    parser.add_argument("--tls-cert")
    parser.add_argument("--tls-key")
    args = parser.parse_args()

    tls_context = None
    if args.https_port is not None:
        if not args.tls_cert or not args.tls_key:
            parser.error("--https-port requires --tls-cert and --tls-key")
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
        tls_context.set_alpn_protocols(["http/1.1"])
        tls_context.load_cert_chain(args.tls_cert, args.tls_key)

    servers = []
    udp_threads = []
    for bind in filter(None, (args.bind4, args.bind6)):
        servers.append(start_tcp(bind, args.http_port, CanaryHttpHandler, args.instance))
        servers.append(start_tcp(bind, args.tcp_port, CanaryTcpHandler, args.instance))
        if tls_context:
            servers.append(start_tcp(bind, args.https_port, CanaryHttpHandler, args.instance, tls_context))
        udp_threads.append(UdpCanaryThread(bind, args.udp_port, args.instance))
        udp_threads.append(UdpCanaryThread(bind, args.dns_port, args.instance, args.dns_zone.strip(".").lower()))
    for thread in udp_threads:
        thread.start()

    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda _signum, _frame: stop.set())
    print(json.dumps({
        "schema": SCHEMA,
        "instance": args.instance,
        "pid": os.getpid(),
        "http_port": args.http_port,
        "https_port": args.https_port,
        "tcp_port": args.tcp_port,
        "udp_port": args.udp_port,
        "dns_port": args.dns_port,
        "dns_zone": args.dns_zone,
        "pktinfo": any(thread.pktinfo_type is not None for thread in udp_threads),
    }), flush=True)
    stop.wait()
    for server in servers:
        server.shutdown()
        server.server_close()
    for thread in udp_threads:
        thread.close()


if __name__ == "__main__":
    main()
