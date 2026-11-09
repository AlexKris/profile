#!/usr/bin/env python3
"""Render the deployed sing-box templates from the public templates, private policies and the API secret.

    render_singbox.py render [--ref main | --template-dir DIR] [--private-dir DIR] [--out-dir DIR] [--dry-run]
    render_singbox.py extract --from singbox_fakeip.json

The private directory holds two files that never enter the repository:
  api_secret     one line, replaces every REPLACE_WITH_SECRET in the templates
  policies.json  {"policies": [{"outbound": "GlobalEmby", "domain": [...], "domain_suffix": [...]}, ...]}

Each policy becomes one route rule plus the DNS rules the template uses for that kind of outbound
(FakeIP for proxied domains in the FakeIP template, dns_proxy in the RealIP template, dns_direct for the
direct outbound). The private block is inserted right before the `direct-check, direct-extra` rule in both
`dns.rules` and `route.rules`, so private domains win over every remote rule set. Outputs are rewritten in
place (same inode, the files are single-file bind mounts) after a copy into backups/render-<timestamp>/.
"""
import argparse
import datetime
import difflib
import json
import re
import shutil
import sys
import urllib.request
from pathlib import Path

PROFILES = ("fakeip", "realip")
TEMPLATE_URL = "https://raw.githubusercontent.com/AlexKris/profile/{ref}/singbox/xboard_singbox_{profile}_ipv4_only.json"
TEMPLATE_NAME = "xboard_singbox_{profile}_ipv4_only.json"
OUTPUT_NAME = "singbox_{profile}.json"
PLACEHOLDER = "REPLACE_WITH_SECRET"
ANCHOR = ["direct-check", "direct-extra"]
MATCHERS = ("domain", "domain_suffix")
REALIP_EXCEPTIONS = "dns-realip"


class RenderError(Exception):
    pass


def dumps(config):
    return json.dumps(config, indent=2, ensure_ascii=False) + "\n"


def load_policies(data):
    policies = data.get("policies") if isinstance(data, dict) else None
    if not isinstance(policies, list) or not policies:
        raise RenderError('policies.json must be {"policies": [...]} with at least one policy')
    seen = set()
    for index, policy in enumerate(policies):
        if not isinstance(policy, dict) or not isinstance(policy.get("outbound"), str) or not policy["outbound"]:
            raise RenderError(f"policy #{index}: outbound must be a non-empty string")
        unknown = set(policy) - {"outbound", *MATCHERS}
        if unknown:
            raise RenderError(f"policy #{index}: unknown keys {sorted(unknown)}")
        if not any(policy.get(key) for key in MATCHERS):
            raise RenderError(f"policy #{index}: needs domain or domain_suffix")
        for key in MATCHERS:
            values = policy.get(key, [])
            if not isinstance(values, list) or not all(isinstance(v, str) and v and not v.isspace() for v in values):
                raise RenderError(f"policy #{index}: {key} must be a list of non-empty strings")
            for value in values:
                if (key, value) in seen:
                    raise RenderError(f"policy #{index}: duplicate {key} {value}")
                seen.add((key, value))
    return policies


def matchers(policy):
    return {key: list(policy[key]) for key in MATCHERS if policy.get(key)}


def dns_rules(policy, profile, direct_tags):
    match = matchers(policy)
    if policy["outbound"] in direct_tags:
        return [{**match, "action": "route", "server": "dns_direct"}]
    rules = []
    if profile == "fakeip":
        rules.append({"type": "logical", "mode": "and",
                      "rules": [{**match, "query_type": ["A"]},
                                {"rule_set": [REALIP_EXCEPTIONS], "invert": True}],
                      "action": "route", "server": "dns_fakeip", "rewrite_ttl": 1})
    rules.append({**match, "action": "route", "server": "dns_proxy"})
    return rules


def route_rule(policy):
    return {**matchers(policy), "action": "route", "outbound": policy["outbound"]}


def anchor_index(rules, where):
    hits = [index for index, rule in enumerate(rules) if rule.get("rule_set") == ANCHOR]
    if len(hits) != 1:
        raise RenderError(f"{where}: expected exactly one rule with rule_set {ANCHOR}, found {len(hits)}")
    return hits[0]


def replace_secret(node, secret):
    count = 0
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "secret" and value == PLACEHOLDER:
                node[key] = secret
                count += 1
            else:
                count += replace_secret(value, secret)
    elif isinstance(node, list):
        for item in node:
            count += replace_secret(item, secret)
    return count


def render(template, profile, policies, secret):
    if profile not in PROFILES:
        raise RenderError(f"unknown profile {profile}")
    config = json.loads(json.dumps(template))
    tags = {outbound["tag"] for outbound in config["outbounds"]}
    direct_tags = {outbound["tag"] for outbound in config["outbounds"] if outbound.get("type") == "direct"}
    for policy in policies:
        if policy["outbound"] not in tags:
            raise RenderError(f"policy outbound {policy['outbound']!r} is not an outbound of the {profile} template")
    rule_set_tags = set()
    for rule_set in config["route"].get("rule_set", []):
        rule_set_tags.update(rule_set["tag"] if isinstance(rule_set["tag"], list) else [rule_set["tag"]])
    if profile == "fakeip" and REALIP_EXCEPTIONS not in rule_set_tags:
        raise RenderError(f"{profile} template has no {REALIP_EXCEPTIONS} rule set")
    dns = config["dns"]["rules"]
    index = anchor_index(dns, "dns.rules")
    dns[index:index] = [rule for policy in policies for rule in dns_rules(policy, profile, direct_tags)]
    route = config["route"]["rules"]
    index = anchor_index(route, "route.rules")
    route[index:index] = [route_rule(policy) for policy in policies]
    if replace_secret(config, secret) == 0:
        raise RenderError(f"{profile} template has no {PLACEHOLDER} to replace")
    if PLACEHOLDER in json.dumps(config):
        raise RenderError(f"{profile}: {PLACEHOLDER} left outside a secret field")
    return config


def extract(config):
    rules = config["route"]["rules"]
    end = anchor_index(rules, "route.rules")
    start = end
    while start > 0:
        rule = rules[start - 1]
        if (set(rule) <= {*MATCHERS, "action", "outbound"} and rule.get("action") == "route"
                and any(key in rule for key in MATCHERS)):
            start -= 1
        else:
            break
    return {"policies": [{"outbound": rule["outbound"], **{key: rule[key] for key in MATCHERS if key in rule}}
                         for rule in rules[start:end]]}


def load_secret(path):
    try:
        secret = path.read_text().strip()
    except FileNotFoundError:
        raise RenderError(f"missing {path}") from None
    if not secret or secret.upper() == PLACEHOLDER or any(c.isspace() for c in secret):
        raise RenderError(f"{path} must hold one non-empty secret without whitespace")
    return secret


def load_template(profile, args):
    if args.template_dir:
        return json.loads(Path(args.template_dir, TEMPLATE_NAME.format(profile=profile)).read_text())
    url = TEMPLATE_URL.format(ref=args.ref, profile=profile)
    with urllib.request.urlopen(url, timeout=20) as response:
        return json.loads(response.read().decode())


def masked(text):
    return re.sub(r'("secret": )"[^"]*"', r'\1"<secret>"', text)


def write_output(path, text, backups_dir, dry_run, stamp):
    current = path.read_text() if path.exists() else None
    if current == text:
        print(f"{path}: unchanged")
        return False
    if dry_run:
        print(f"{path}: would change ({len(text.encode())} bytes)")
        if current is not None:
            sys.stdout.writelines(difflib.unified_diff(masked(current).splitlines(True), masked(text).splitlines(True),
                                                       f"{path.name} (current)", f"{path.name} (rendered)"))
        return True
    if current is not None:
        backup = backups_dir / f"render-{stamp}"
        backup.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, backup / path.name)
        print(f"{path}: backup in {backup}")
    with open(path, "w") as handle:  # rewrite in place so the bind mount keeps the same inode
        handle.write(text)
    print(f"{path}: written ({len(text.encode())} bytes)")
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    render_parser = commands.add_parser("render", help="render both profiles into the output directory")
    source = render_parser.add_mutually_exclusive_group()
    source.add_argument("--ref", default="main", help="git ref of the public templates on GitHub (default: main)")
    source.add_argument("--template-dir", type=Path, help="read the public templates from this directory instead")
    render_parser.add_argument("--private-dir", type=Path, default=Path("/opt/xboard/protocols_data/private"))
    render_parser.add_argument("--out-dir", type=Path, default=Path("/opt/xboard/protocols_data"))
    render_parser.add_argument("--dry-run", action="store_true", help="show what would change, write nothing")
    extract_parser = commands.add_parser("extract", help="recover policies.json from a rendered file")
    extract_parser.add_argument("--from", dest="source", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "extract":
            print(json.dumps(extract(json.loads(args.source.read_text())), indent=2, ensure_ascii=False))
            return 0
        secret = load_secret(args.private_dir / "api_secret")
        policies = load_policies(json.loads((args.private_dir / "policies.json").read_text()))
        rendered = {profile: dumps(render(load_template(profile, args), profile, policies, secret))
                    for profile in PROFILES}
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        for profile, text in rendered.items():
            write_output(args.out_dir / OUTPUT_NAME.format(profile=profile), text, args.out_dir / "backups",
                         args.dry_run, stamp)
        return 0
    except RenderError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
