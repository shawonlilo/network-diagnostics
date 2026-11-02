#!/usr/bin/env python3
"""Local test fixtures for nd-check (no internet needed).

  judge  :18080  echoes {"origin": ip, "headers": {...}} like httpbin /get
  proxy  :18081  transparent  (adds X-Forwarded-For with the client IP)
  proxy  :18082  anonymous    (adds Via only)
  proxy  :18083  elite        (adds nothing)
  dns    :15353  fake resolver answering A / MX / TXT (SPF) / TXT (DMARC)

Run: python3 fixtures.py   (Ctrl-C to stop)
"""
import http.client
import json
import socket
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

JUDGE_PORT = 18080
DNS_ADDR = ("127.0.0.1", 15353)


class Judge(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_GET(self):
        body = json.dumps({
            "origin": self.client_address[0],
            "headers": {k: v for k, v in self.headers.items()},
            "url": self.path,
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def make_proxy(extra_headers):
    class Proxy(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def do_GET(self):
            url = urlparse(self.path)
            host = url.hostname or "127.0.0.1"
            port = url.port or 80
            path = url.path or "/"
            if url.query:
                path += "?" + url.query
            headers = {k: v for k, v in self.headers.items()
                       if k.lower() not in ("proxy-authorization", "connection")}
            for k, v in extra_headers.items():
                headers[k] = v(self) if callable(v) else v
            conn = http.client.HTTPConnection(host, port, timeout=5)
            try:
                conn.request("GET", path, headers=headers)
                resp = conn.getresponse()
                body = resp.read()
                self.send_response(resp.status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except Exception as e:  # dead upstream
                body = str(e).encode()
                self.send_response(502)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            finally:
                conn.close()

        def log_message(self, *a):
            pass

    return Proxy


def parse_qname(packet):
    labels, off = [], 12
    while packet[off] != 0:
        ln = packet[off]
        labels.append(packet[off + 1:off + 1 + ln].decode())
        off += 1 + ln
    return ".".join(labels), off + 1  # offset just past root label


def encode_name(name):
    out = b""
    for label in name.split("."):
        if label:
            out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def dns_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(DNS_ADDR)
    while True:
        data, addr = sock.recvfrom(4096)
        try:
            qid = data[:2]
            qname, qend = parse_qname(data)
            qtype = struct.unpack(">H", data[qend:qend + 2])[0]
            question = data[12:qend + 4]
            answers = b""
            count = 0
            if qtype == 1:  # A
                answers += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4) + socket.inet_aton("93.184.216.34")
                count = 1
            elif qtype == 15:  # MX
                rdata = struct.pack(">H", 10) + encode_name("mail." + qname)
                answers += b"\xc0\x0c" + struct.pack(">HHIH", 15, 1, 300, len(rdata)) + rdata
                count = 1
            elif qtype == 16:  # TXT
                txt = ("v=DMARC1; p=reject; rua=mailto:dmarc@" + qname.split(".", 1)[-1]
                       if qname.startswith("_dmarc")
                       else "v=spf1 include:_spf.example.net -all")
                rdata = bytes([len(txt)]) + txt.encode()
                answers += b"\xc0\x0c" + struct.pack(">HHIH", 16, 1, 300, len(rdata)) + rdata
                count = 1
            header = qid + struct.pack(">HHHHH", 0x8180, 1, count, 0, 0)
            sock.sendto(header + question + answers, addr)
        except Exception:
            pass


def main():
    ThreadingHTTPServer(("127.0.0.1", JUDGE_PORT), Judge).serve_forever()


if __name__ == "__main__":
    threading.Thread(target=dns_server, daemon=True).start()
    proxies = [
        (18081, {"X-Forwarded-For": lambda h: h.client_address[0]}),
        (18082, {"Via": "1.1 nd-testproxy"}),
        (18083, {}),
    ]
    for port, hdrs in proxies:
        t = threading.Thread(
            target=lambda p=port, h=hdrs: ThreadingHTTPServer(("127.0.0.1", p), make_proxy(h)).serve_forever(),
            daemon=True)
        t.start()
    print("fixtures up: judge=18080 proxies=18081,18082,18083 dns=15353", flush=True)
    main()
