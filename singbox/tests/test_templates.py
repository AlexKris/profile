"""Regression tests using the real generator and core, never TUN or system proxy."""

import contextlib
import http.client
import http.server
import ipaddress
import json
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


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = {mode: ROOT / f"xboard_singbox_{mode}_ipv4_only.json"
             for mode in ("realip", "fakeip")}
CORE = os.environ.get("SING_BOX", "sing-box")
NODES = ["HK RFC sample", "TW Ucom sample", "JP SoftBank sample",
         "US ATT sample", "DE sample", "SG Starlink sample"]
QTYPE = {"A": 1, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16,
         "AAAA": 28, "SRV": 33, "SVCB": 64, "HTTPS": 65}


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def generate(path, nodes=NODES, expect_success=True, private_secrets=True, admin_template=False):
    config = json.loads(path.read_text())
    if private_secrets:
        for service in config.get("services", []):
            if service.get("type") == "api" and service.get("secret") == "REPLACE_WITH_SECRET":
                service["secret"] = "fixture-private-secret-not-for-deployment"
    profile = "realip" if "realip" in path.name else "fakeip"
    with tempfile.TemporaryDirectory(prefix="singbox-generator-") as directory:
        directory = Path(directory)
        target = (directory / "admin-template.json" if admin_template else
                  directory / "resources/rules" / f"custom.sing-box.{profile}.json")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(config))
        result = subprocess.run(
            ["php", str(ROOT / "tests/generate_fixture.php"), str(directory), json.dumps(nodes), profile],
            capture_output=True, text=True, timeout=10,
        )
    if expect_success and result.returncode:
        raise AssertionError(result.stdout + result.stderr)
    if not expect_success and result.returncode == 0:
        raise AssertionError("generator unexpectedly accepted invalid input")
    return json.loads(result.stdout)


def core_check(config):
    with tempfile.TemporaryDirectory(prefix="singbox-check-") as directory:
        path = Path(directory) / "config.json"
        path.write_text(json.dumps(config))
        result = subprocess.run([CORE, "check", "-c", str(path)], cwd=directory,
                                capture_output=True, text=True, timeout=15)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)


class GenerationTests(unittest.TestCase):
    def test_core_schema_and_template_keys(self):
        for mode, path in TEMPLATES.items():
            with self.subTest(mode=mode):
                json.loads(path.read_text(), object_pairs_hook=unique_object)
                result = generate(path)
                self.assertEqual(result["warnings"], [])
                config = result["config"]
                core_check(config)
                encoded = json.dumps(config)
                for field in ("download_detour", "independent_cache", "store_rdrc",
                              "endpoint_independent_nat", '"include"', '"_filter"', '"fallback"'):
                    self.assertNotIn(field, encoded)
                groups = {item["tag"]: item for item in config["outbounds"]}
                self.assertEqual(groups["Proxy"]["outbounds"], NODES)
                for group in config["outbounds"]:
                    for name in group.get("outbounds", []):
                        self.assertIn(name, groups)
                self.assertEqual(config["route"]["rules"][1],
                                 {"ip_version": 6, "action": "reject", "no_drop": True})
                self.assertTrue(any(":" in address for address in config["inbounds"][0]["address"]))
                self.assertEqual(config["route"]["default_http_client"], "http_proxy")

    def test_common_behavior_stays_aligned(self):
        real, fake = (json.loads(path.read_text()) for path in TEMPLATES.values())
        for key in ("inbounds", "outbounds", "services", "http_clients"):
            self.assertEqual(real[key], fake[key], key)
        self.assertEqual(real["route"]["rules"], fake["route"]["rules"])
        remote = lambda cfg: [rs for rs in cfg["route"]["rule_set"] if rs["type"] == "remote"]
        self.assertEqual(remote(real), remote(fake))
        self.assertEqual(len(remote(real)), 22)
        self.assertTrue(real["dns"]["reverse_mapping"])
        self.assertTrue(fake["dns"]["reverse_mapping"])

    def test_region_regex_does_not_match_substrings(self):
        aliases = {
            "HK": ["HKG RFC sample", "Hong Kong RFC sample"],
            "TW": ["TWN Ucom sample", "Taiwan Ucom sample"],
            "JP": ["JPN SoftBank sample", "Japan SoftBank sample"],
            "US": ["USA ATT sample", "United States ATT sample"],
            "DE": ["DEU sample", "GER sample", "Germany sample"],
            "SG": ["SGP Starlink sample", "Singapore Starlink sample"],
        }
        extra = ["HK Node", "Australia Edge", "US Seattle sample", "USAGI sample", "SGPOOL sample"]
        names = NODES + [name for values in aliases.values() for name in values] + extra
        for path in TEMPLATES.values():
            with self.subTest(path=path.name):
                config = generate(path, names)["config"]
                groups = {item["tag"]: item for item in config["outbounds"]}
                for region, values in aliases.items():
                    self.assertTrue(set(values) <= set(groups[region]["outbounds"]), region)
                self.assertEqual(groups["DE"]["outbounds"], ["DE sample"] + aliases["DE"])
                self.assertNotIn("Australia Edge", groups["US"]["outbounds"])
                self.assertNotIn("USAGI sample", groups["US"]["outbounds"])
                self.assertNotIn("SGPOOL sample", groups["SG"]["outbounds"])
                self.assertNotIn("US Seattle sample", groups["AIGC"]["outbounds"])
                for group, regions in {"Telegram": ["HK", "JP"], "GlobalMedia": ["HK", "TW", "SG"],
                                       "GlobalEmby": ["HK", "JP", "SG"], "RFCEmby": ["HK"],
                                       "AIGC": ["TW", "JP", "US", "SG"], "Google": ["US"],
                                       "Speedtest": ["HK", "TW", "JP", "SG"],
                                       "Download": ["HK", "JP"]}.items():
                    expected = {name for region in regions for name in aliases[region]}
                    self.assertTrue(expected <= set(groups[group]["outbounds"]), group)

    def test_api_secrets_required_in_both_template_sources(self):
        for path in TEMPLATES.values():
            for admin_template in (False, True):
                with self.subTest(path=path.name, admin_template=admin_template):
                    result = generate(path, admin_template=admin_template)
                    core_check(result["config"])
                    self.assertNotIn("REPLACE_WITH_SECRET", json.dumps(result["config"]))
                    self.assertEqual(bool(result["warnings"]), admin_template)
                    for index in (0, 1):
                        for secret in (None, "", " \t", "REPLACE_WITH_SECRET", " REPLACE_WITH_SECRET ",
                                       "replace_with_secret", 0):
                            with self.subTest(index=index, secret=secret), tempfile.TemporaryDirectory() as directory:
                                config = json.loads(path.read_text())
                                for service in config["services"]:
                                    service["secret"] = "fixture-private-secret-not-for-deployment"
                                if secret is None:
                                    config["services"][index].pop("secret")
                                else:
                                    config["services"][index]["secret"] = secret
                                candidate = Path(directory) / path.name
                                candidate.write_text(json.dumps(config))
                                result = generate(candidate, expect_success=False, private_secrets=False,
                                                  admin_template=admin_template)
                                self.assertIn("private secret", result["error"])

    def test_legacy_api_secret_checked_only_when_listening(self):
        for path in TEMPLATES.values():
            for listening in (False, True):
                for secret in (None, "", "REPLACE_WITH_SECRET", "fixture-legacy-secret"):
                    with self.subTest(path=path.name, listening=listening, secret=secret):
                        with tempfile.TemporaryDirectory() as directory:
                            config = json.loads(path.read_text())
                            api = config["experimental"]["clash_api"]
                            if listening:
                                api["external_controller"] = "127.0.0.1:19090"
                            if secret is not None:
                                api["secret"] = secret
                            candidate = Path(directory) / path.name
                            candidate.write_text(json.dumps(config))
                            valid = not listening or secret == "fixture-legacy-secret"
                            result = generate(candidate, expect_success=valid, admin_template=True)
                            if not valid:
                                self.assertIn("private secret", result["error"])

    def test_empty_region_falls_back_to_proxy_not_direct(self):
        for path in TEMPLATES.values():
            result = generate(path, ["HK RFC sample"])
            groups = {item["tag"]: item for item in result["config"]["outbounds"]}
            self.assertEqual(groups["DE"]["outbounds"], ["Proxy"])
            self.assertEqual(groups["AIGC"]["outbounds"], ["Proxy"])
            self.assertTrue(result["warnings"])
            core_check(result["config"])

    def test_missing_duplicate_and_reserved_nodes_fail(self):
        for path in TEMPLATES.values():
            for nodes in ([], ["HK sample", "HK sample"], ["Proxy"], ["Direct"], ["JP"]):
                with self.subTest(path=path.name, nodes=nodes):
                    self.assertIn("error", generate(path, nodes, expect_success=False))

    def test_unusable_fallback_fails(self):
        config = json.loads(TEMPLATES["realip"].read_text())
        group = next(item for item in config["outbounds"] if item["tag"] == "DE")
        for fallback in (None, "DE", "no-such-group"):
            with self.subTest(fallback=fallback), tempfile.TemporaryDirectory() as directory:
                group["fallback"] = fallback
                path = Path(directory) / "config.json"
                path.write_text(json.dumps(config))
                self.assertIn("error", generate(path, ["HK sample"], expect_success=False))

    def test_invalid_include_or_exclude_fails(self):
        for field in ("include", "exclude"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                config = json.loads(TEMPLATES["realip"].read_text())
                config["outbounds"][0][field] = "("
                path = Path(directory) / "config.json"
                path.write_text(json.dumps(config))
                result = generate(path, expect_success=False)
                self.assertIn("invalid outbound pattern", result["error"])


def question(packet):
    offset, parts = 12, []
    while packet[offset]:
        size = packet[offset]
        parts.append(packet[offset + 1:offset + 1 + size].decode())
        offset += size + 1
    return ".".join(parts), struct.unpack("!H", packet[offset + 1:offset + 3])[0], offset + 5


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        packet, sock = self.request
        name, qtype, end = question(packet)
        self.server.hits.append((self.server.label, name, qtype))
        answer = b""
        if qtype == 1:
            address = "127.0.0.1" if name.startswith("http-") else "203.0.113.7"
            answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(address)
        header = packet[:2] + struct.pack("!HHHHH", 0x8180, 1, bool(answer), 0, 0)
        sock.sendto(header + packet[12:end] + answer, self.client_address)


class HTTPHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/rules.srs":
            self.server.rule_requests += 1
            if not self.server.rule_available:
                self.send_error(503)
                return
            payload = self.server.rule_data
        else:
            payload = b"fixture-ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_):
        pass


def port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def query(dns_port, name, kind="A"):
    name_wire = b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\0"
    packet = (struct.pack("!HHHHHH", 1234, 0x0100, 1, 0, 0, 0)
              + name_wire + struct.pack("!HH", QTYPE[kind], 1))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        sock.sendto(packet, ("127.0.0.1", dns_port))
        reply = sock.recv(4096)
    flags, _, count = struct.unpack("!HHH", reply[2:8])
    return {"rcode": flags & 15, "count": count,
            "ip": socket.inet_ntoa(reply[-4:]) if kind == "A" and count else None}


def fixture_rules(config):
    domains = {
        "geosite-private": ["lan.test", "in-addr.arpa"],
        "geosite-cn": ["cn.test", "apple.cn.test", "ai.cn.test", "stream.cn.test"],
        "ai": ["ai.cn.test"],
        "apple": ["apple.cn.test", "ai.cn.test"],
        "microsoft-cdn": ["cdn.microsoft.test"],
        "microsoft": ["microsoft.test"],
        "stream": ["stream.cn.test"],
        "geosite-google": ["google.test", "stun.l.google.com"],
    }
    for rule_set in config["route"]["rule_set"]:
        if rule_set["type"] == "remote":
            tag = rule_set["tag"]
            rule_set.clear()
            rule_set.update(tag=tag, type="inline",
                            rules=[{"domain_suffix": domains.get(tag, [tag + ".fixture.test"])}])


@contextlib.contextmanager
def running(config):
    with tempfile.TemporaryDirectory(prefix="singbox-offline-test-") as directory:
        directory = Path(directory)
        for api in config.get("services", []):
            if "dashboard" in api:
                dashboard = directory / api["dashboard"].get("path", "dashboard")
                dashboard.mkdir()
                (dashboard / "index.html").write_text("fixture-dashboard")
        path = directory / "config.json"
        path.write_text(json.dumps(config))
        with (directory / "core.log").open("w+") as logfile:
            process = subprocess.Popen([CORE, "run", "-c", str(path)], cwd=directory,
                                       stdout=logfile, stderr=logfile)
            try:
                for _ in range(100):
                    if process.poll() is not None:
                        logfile.seek(0)
                        raise AssertionError(logfile.read())
                    if "sing-box started" in (directory / "core.log").read_text():
                        break
                    time.sleep(0.03)
                else:
                    raise AssertionError("core did not become ready")
                try:
                    yield logfile
                except Exception as error:
                    raise AssertionError((directory / "core.log").read_text()) from error
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.resources = contextlib.ExitStack()
        self.addCleanup(self.resources.close)
        self.hits = []
        self.servers = []
        for label in ("dns_direct", "dns_proxy", "dns_local"):
            server = self.resources.enter_context(socketserver.UDPServer(("127.0.0.1", 0), DNSHandler))
            server.label, server.hits = label, self.hits
            self.servers.append(server)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            self.resources.callback(server.shutdown)
        self.origin = self.resources.enter_context(http.server.HTTPServer(("127.0.0.1", 0), HTTPHandler))
        threading.Thread(target=self.origin.serve_forever, daemon=True).start()
        self.resources.callback(self.origin.shutdown)

    def config(self, profile, mode="Rule", api=False):
        config = generate(TEMPLATES[profile])["config"]
        config["log"] = {"level": "debug"}
        config["dns"]["servers"] = [
            {"type": "udp", "tag": server.label, "server": "127.0.0.1",
             "server_port": server.server_address[1]} for server in self.servers
        ] + [item for item in config["dns"]["servers"] if item["type"] == "fakeip"]
        config["experimental"]["clash_api"]["default_mode"] = mode
        config["inbounds"] = [
            {"type": "mixed", "tag": "test-mixed", "listen": "127.0.0.1", "listen_port": port()},
            {"type": "direct", "tag": "test-dns", "listen": "127.0.0.1",
             "listen_port": port(socket.SOCK_DGRAM), "network": "udp",
             "override_address": "127.0.0.1", "override_port": 53},
        ]
        config["route"].pop("auto_detect_interface")
        fixture_rules(config)
        # Keep real selectors and routing; replace only external transport endpoints.
        for index, outbound in enumerate(config["outbounds"]):
            if outbound["type"] == "shadowsocks":
                config["outbounds"][index] = {"tag": outbound["tag"], "type": "direct"}
        if api:
            for service in config["services"]:
                service.update(listen="127.0.0.1", listen_port=port(), secret="fixture-secret")
        else:
            config["services"] = []
        return config

    def assert_resolver(self, config, name, expected, kind="A"):
        self.hits.clear()
        reply = query(config["inbounds"][1]["listen_port"], name, kind)
        self.assertEqual(reply["rcode"], 0, (name, kind, reply))
        if expected == "fake":
            self.assertEqual(reply["count"], 1)
            self.assertIn(ipaddress.ip_address(reply["ip"]), ipaddress.ip_network("198.18.0.0/15"))
            self.assertEqual(self.hits, [])
        elif expected is None:
            self.assertEqual(reply["count"], 0)
            self.assertEqual(self.hits, [])
        else:
            self.assertEqual(self.hits, [(expected, name, QTYPE[kind])])
        return reply

    def test_dns_routing_modes_types_and_cache(self):
        for profile in TEMPLATES:
            for mode in ("Rule", "Direct", "Global"):
                with self.subTest(profile=profile, mode=mode):
                    config = self.config(profile, mode)
                    foreign = "fake" if profile == "fakeip" else "dns_proxy"
                    expected = {
                        "unknown.test": foreign, "unlisted.foreign.test": foreign,
                        "www.cn.test": "dns_direct", "www.apple.cn.test": "dns_direct",
                        "www.ai.cn.test": foreign, "www.stream.cn.test": foreign,
                        "cdn.microsoft.test": "dns_direct", "www.microsoft.test": foreign,
                        "stun.l.google.com": "dns_proxy", "stun.cn.test": "dns_direct",
                        "www.msftconnecttest.com": "dns_direct",
                        "router.lan.test": "dns_local", "lancache.steamcontent.com": "dns_local",
                        "miwifi.com": "dns_local",
                    }
                    if mode != "Rule":
                        for name, server in expected.items():
                            if server == "dns_local":
                                continue
                            no_fake = name.startswith("stun.") or name.endswith("msftconnecttest.com")
                            expected[name] = ("dns_direct" if mode == "Direct" else
                                              "dns_proxy" if no_fake else foreign)
                    with running(config):
                        for name, server in expected.items():
                            with self.subTest(domain=name):
                                self.assert_resolver(config, name, server)
                        for kind in ("AAAA", "HTTPS", "SVCB"):
                            for name in ("type.cn.test", "type.foreign.test", "type.lan.test"):
                                self.assert_resolver(config, name, None, kind)
                        for kind in ("MX", "TXT", "SRV", "SOA"):
                            self.assert_resolver(config, "mail.foreign.test",
                                                 "dns_direct" if mode == "Direct" else "dns_proxy", kind)
                        self.assert_resolver(config, "1.0.0.10.in-addr.arpa", "dns_local", "PTR")
                        reply = self.assert_resolver(config, "cache.cn.test",
                                                     "dns_direct" if mode != "Global" else foreign)
                        self.hits.clear()
                        self.assertEqual(query(config["inbounds"][1]["listen_port"], "cache.cn.test"), reply)
                        self.assertEqual(self.hits, [], "repeat query missed cache")

    def http_request(self, config, destination):
        target = f"{destination}:{self.origin.server_address[1]}"
        connection = http.client.HTTPConnection("127.0.0.1", config["inbounds"][0]["listen_port"], timeout=3)
        try:
            connection.request("GET", f"http://{target}/")
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(response.read(), b"fixture-ok")
        finally:
            connection.close()

    def test_route_resolve_uses_dns_rules_and_skips_fake_transport(self):
        for profile in TEMPLATES:
            with self.subTest(profile=profile):
                config = self.config(profile)
                with running(config) as log:
                    for name, expected in (("http-unknown.test", "dns_proxy"),
                                           ("http-router.lan.test", "dns_local")):
                        self.hits.clear()
                        self.http_request(config, name)
                        self.assertEqual(self.hits, [(expected, name, 1)])
                    if profile == "fakeip":
                        reply = self.assert_resolver(config, "http-fake.test", "fake")
                        self.http_request(config, reply["ip"])
                        self.assertEqual(self.hits, [("dns_proxy", "http-fake.test", 1)])
                    log.seek(0)
                    output = log.read()
                    self.assertNotIn("sniffed", output)
                    self.assertNotIn("only IP queries", output)

    def test_explicit_ipv6_rejected_in_all_modes(self):
        for mode in ("Rule", "Direct", "Global"):
            config = self.config("realip", mode)
            with running(config) as log:
                with socket.create_connection(("127.0.0.1", config["inbounds"][0]["listen_port"]), 3) as conn:
                    conn.settimeout(3)
                    conn.sendall(b"\x05\x01\x00")
                    self.assertEqual(conn.recv(2), b"\x05\x00")
                    conn.sendall(b"\x05\x01\x00\x04" + socket.inet_pton(socket.AF_INET6, "2001:db8::1")
                                 + struct.pack("!H", 443))
                    self.assertNotEqual(conn.recv(10)[1], 0)
                log.seek(0)
                self.assertIn("reject", log.read())

    def test_fakeip_mapping_survives_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            config = self.config("fakeip")
            config["experimental"]["cache_file"]["path"] = str(Path(directory) / "cache.db")
            with running(config):
                reply = self.assert_resolver(config, "http-persistent.test", "fake")
            with running(config):
                self.hits.clear()
                self.http_request(config, reply["ip"])
                self.assertEqual(self.hits, [("dns_proxy", "http-persistent.test", 1)])

    def test_remote_rules_use_shared_client_and_warm_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            source, binary = Path(directory) / "rules.json", Path(directory) / "rules.srs"
            source.write_text(json.dumps({"version": 2, "rules": [{"domain_suffix": ["cn.test"]}]}))
            subprocess.run([CORE, "rule-set", "compile", "-o", str(binary), str(source)],
                           capture_output=True, check=True, timeout=10)
            self.origin.rule_data = binary.read_bytes()
            self.origin.rule_requests = 0
            self.origin.rule_available = True
            config = self.config("realip")
            config["experimental"]["cache_file"]["path"] = str(Path(directory) / "cache.db")
            rule = next(item for item in config["route"]["rule_set"] if item["tag"] == "geosite-cn")
            rule.clear()
            rule.update(tag="geosite-cn", type="remote", format="binary",
                        url=f"http://127.0.0.1:{self.origin.server_address[1]}/rules.srs")
            with running(config):
                self.assert_resolver(config, "cold.cn.test", "dns_direct")
            self.assertEqual(self.origin.rule_requests, 1)
            self.origin.rule_available = False
            with running(config):
                self.assert_resolver(config, "warm.cn.test", "dns_direct")
            self.assertEqual(self.origin.rule_requests, 1, "warm cache unexpectedly needs download")

    def test_api_dashboard_authentication_and_cors(self):
        config = self.config("realip", api=True)
        with running(config):
            for service in config["services"]:
                connection = http.client.HTTPConnection("127.0.0.1", service["listen_port"], timeout=3)
                try:
                    connection.request("GET", "/dashboard/")
                    response = connection.getresponse()
                    self.assertEqual(response.status, 200)
                    self.assertIn(b"fixture-dashboard", response.read())
                    for authenticated in (False, True):
                        headers = {"Content-Type": "application/grpc-web+proto"}
                        if authenticated:
                            headers["Authorization"] = "Bearer fixture-secret"
                        connection.request("POST", "/daemon.StartedService/GetVersion", b"\0" * 5, headers)
                        response = connection.getresponse()
                        body = response.read().lower()
                        expected = "0" if authenticated else "16"
                        if response.getheader("Grpc-Status") is not None:
                            self.assertEqual(response.getheader("Grpc-Status"), expected)
                        else:
                            self.assertIn(b"grpc-status: " + expected.encode(), body)
                    for origin, allowed in (("http://127.0.0.1:9090", True), ("https://untrusted.example", False)):
                        connection.request("OPTIONS", "/daemon.StartedService/GetVersion", headers={
                            "Origin": origin, "Access-Control-Request-Method": "POST",
                            "Access-Control-Request-Headers": "authorization,content-type",
                        })
                        response = connection.getresponse()
                        self.assertEqual(response.getheader("Access-Control-Allow-Origin"), origin if allowed else None)
                        response.read()
                finally:
                    connection.close()


if __name__ == "__main__":
    if not shutil.which(CORE) or not shutil.which("php"):
        raise SystemExit("Requires sing-box 1.14.x and PHP; set SING_BOX to override the binary.")
    unittest.main(verbosity=2)
