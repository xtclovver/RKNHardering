#!/usr/bin/env python3
import json
import socket
import struct
import unittest

import server


TOKEN = "0123456789abcdef0123456789abcdef"


class CanaryServerTest(unittest.TestCase):
    def setUp(self):
        self.http = server.start_tcp("127.0.0.1", 0, server.CanaryHttpHandler, "test")
        self.tcp = server.start_tcp("127.0.0.1", 0, server.CanaryTcpHandler, "test")
        self.udp = server.UdpCanaryThread("127.0.0.1", 0, "test")
        self.dns = server.UdpCanaryThread("127.0.0.1", 0, "test", "canary.invalid")
        self.udp.start()
        self.dns.start()

    def tearDown(self):
        for service in (self.http, self.tcp):
            service.shutdown()
            service.server_close()
        self.udp.close()
        self.dns.close()

    def test_http_observation_echoes_schema_token_and_source(self):
        request = (
            f"GET /v1/observe?schema=1&token={TOKEN}&family=ipv4 HTTP/1.1\r\n"
            "Host: localhost\r\nConnection: close\r\n\r\n"
        ).encode("ascii")
        with socket.create_connection(self.http.server_address, timeout=2) as client:
            client.sendall(request)
            response = read_all(client)
        body = json.loads(response.split(b"\r\n\r\n", 1)[1])
        self.assertEqual(1, body["schema"])
        self.assertEqual(TOKEN, body["token"])
        self.assertEqual("127.0.0.1", body["observed_address"])
        self.assertIn("fingerprint", body)

    def test_tcp_udp_and_dns_echo_real_peer(self):
        tcp_request = json.dumps({"schema": 1, "token": TOKEN, "family": "ipv4"}).encode() + b"\n"
        with socket.create_connection(self.tcp.server_address, timeout=2) as client:
            client.sendall(tcp_request)
            tcp_reply = json.loads(client.makefile("rb").readline())
        self.assertEqual("tcp", tcp_reply["protocol"])
        self.assertEqual("127.0.0.1", tcp_reply["observed_address"])

        udp_request = json.dumps({"schema": 1, "token": TOKEN, "family": "ipv4"}).encode()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(2)
            client.sendto(udp_request, self.udp.sock.getsockname())
            udp_reply = json.loads(client.recv(8192))
        self.assertEqual("udp", udp_reply["protocol"])
        self.assertEqual(TOKEN, udp_reply["token"])

        query_id = 1234
        qname = f"nonce.{TOKEN}.canary.invalid"
        dns_query = build_dns_query(query_id, qname)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(2)
            client.sendto(dns_query, self.dns.sock.getsockname())
            dns_reply = client.recv(4096)
        self.assertEqual(query_id, struct.unpack("!H", dns_reply[:2])[0])
        self.assertIn(f"t={TOKEN}".encode(), dns_reply)
        self.assertIn(b"src=127.0.0.1", dns_reply)


def build_dns_query(query_id, name):
    encoded_name = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + encoded_name + struct.pack("!HH", 16, 1)


def read_all(client):
    chunks = []
    while True:
        chunk = client.recv(4096)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


if __name__ == "__main__":
    unittest.main()
