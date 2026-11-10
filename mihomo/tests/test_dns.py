"""Offline DNS regressions: python3 -B mihomo/tests/test_dns.py (requires PyYAML and mihomo)."""

import contextlib
import http.client
import http.server
import os
from pathlib import Path
import shutil
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
CORE = os.environ.get("MIHOMO", "mihomo")
LOCAL_NAMES = ("nas.lan", "nas.m2m", "nas.bogon", "lancache.steamcontent.com")


def port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def query(dns_port, name):
    question = b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\0\0\1\0\1"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        sock.sendto(struct.pack("!HHHHHH", 1234, 0x100, 1, 0, 0, 0) + question, ("127.0.0.1", dns_port))
        return sock.recv(4096)


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        packet, sock = self.request
        offset, parts = 12, []
        while packet[offset]:
            size = packet[offset]
            parts.append(packet[offset + 1:offset + 1 + size].decode())
            offset += size + 1
        name = ".".join(parts)
        self.server.hits.append((self.server.label, name))
        answer = b""
        if self.server.label == "local":
            answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("127.0.0.1")
        header = packet[:2] + struct.pack("!HHHHH", 0x8180 if answer else 0x8183, 1, bool(answer), 0, 0)
        sock.sendto(header + packet[12:offset + 5] + answer, self.client_address)


class HTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "10")
        self.end_headers()
        self.wfile.write(b"fixture-ok")

    def log_message(self, *_):
        pass


class DNSTests(unittest.TestCase):
    def setUp(self):
        self.resources = contextlib.ExitStack()
        self.addCleanup(self.resources.close)
        self.hits, self.servers = [], []
        for label in ("local", "public"):
            server = self.resources.enter_context(socketserver.UDPServer(("127.0.0.1", 0), DNSHandler))
            server.label, server.hits = label, self.hits
            self.servers.append(server)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            self.resources.callback(server.shutdown)
        self.origin = self.resources.enter_context(http.server.HTTPServer(("127.0.0.1", 0), HTTPHandler))
        threading.Thread(target=self.origin.serve_forever, daemon=True).start()
        self.resources.callback(self.origin.shutdown)

    def config(self, path):
        config = yaml.safe_load(path.read_text())
        config.update({"tun": {"enable": False}, "auto-detect-interface": False,
                       "find-process-mode": "off", "mixed-port": port(), "log-level": "debug"})
        for key in ("external-ui", "external-ui-name", "external-ui-url", "external-controller"):
            config.pop(key, None)
        config["proxy-providers"] = {"sub": {"type": "inline", "payload": [
            {"name": "HK RFC fixture", "type": "socks5", "server": "127.0.0.1", "port": port()}]}}
        for name, provider in config["rule-providers"].items():
            behavior = provider["behavior"]
            payload = {"domain": ["+.unused.invalid"], "classical": ["DOMAIN,unused.invalid"],
                       "ipcidr": ["192.0.2.0/24"]}[behavior]
            if name == "direct":
                payload = ["+.lan", "+.m2m", "+.bogon"]
            elif name in ("game_download", "download_domain"):
                payload = ["+.steamcontent.com"]
            provider.clear()
            provider.update(type="inline", behavior=behavior, payload=payload)
        for group in config["proxy-groups"]:
            if group["name"] == "GameDownload":
                group["proxies"] = ["Proxy", "DIRECT", "Download"]
        dns = config["dns"]
        dns["listen"] = f"127.0.0.1:{port(socket.SOCK_DGRAM)}"
        local, public = [f"udp://127.0.0.1:{server.server_address[1]}" for server in self.servers]
        dns["nameserver-policy"] = {key: local if value == "system" else public
                                    for key, value in dns["nameserver-policy"].items()}
        for key in ("nameserver", "default-nameserver", "proxy-server-nameserver", "direct-nameserver"):
            dns[key] = [public]
        dns["use-system-hosts"] = False
        return config

    @contextlib.contextmanager
    def running(self, config):
        with tempfile.TemporaryDirectory(prefix="mihomo-dns-test-") as directory:
            path = Path(directory) / "config.yaml"
            path.write_text(yaml.safe_dump(config, allow_unicode=True))
            with (Path(directory) / "core.log").open("w+") as log:
                process = subprocess.Popen([CORE, "-d", directory, "-f", str(path)], stdout=log, stderr=log)
                try:
                    for _ in range(100):
                        log.seek(0)
                        output = log.read()
                        if "DNS server(TCP) listening" in output and "start initial compatible provider default" in output.lower():
                            break
                        if process.poll() is not None:
                            self.fail(output)
                        time.sleep(0.03)
                    else:
                        self.fail(output)
                    yield
                finally:
                    process.terminate()
                    process.wait(timeout=5)

    def test_local_dns_queries_and_direct_connections(self):
        for path in sorted(ROOT.glob("*.yaml")):
            with self.subTest(profile=path.name):
                config = self.config(path)
                with self.running(config):
                    for name in LOCAL_NAMES:
                        with self.subTest(domain=name):
                            self.hits.clear()
                            reply = query(int(config["dns"]["listen"].split(":")[-1]), name)
                            self.assertEqual(reply[3] & 15, 0)
                            self.assertEqual(socket.inet_ntoa(reply[-4:]), "127.0.0.1")
                            conn = http.client.HTTPConnection("127.0.0.1", config["mixed-port"], timeout=3)
                            try:
                                conn.request("GET", f"http://{name}:{self.origin.server_address[1]}/")
                                response = conn.getresponse()
                                self.assertEqual(response.status, 200)
                                self.assertEqual(response.read(), b"fixture-ok")
                            finally:
                                conn.close()
                            self.assertTrue(self.hits)
                            self.assertTrue(all(label == "local" for label, _ in self.hits), self.hits)


if __name__ == "__main__":
    if not shutil.which(CORE):
        raise SystemExit("Requires mihomo; set MIHOMO to override the binary.")
    unittest.main(verbosity=2)
