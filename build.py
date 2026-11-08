#!/usr/bin/env python3
"""Filters CISA's KEV catalog to home routers, Wi-Fi gear, cameras and network storage."""
import collections
import csv
import json
import pathlib
import re
import sys
import urllib.request

HERE = pathlib.Path(__file__).parent
SOURCE = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

VENDORS = (r'^(d-link|d-link and trendnet|zyxel|netgear|tp-link|mikrotik|draytek|ubiquiti|asus|realtek|tenda|'
           r'hikvision|reolink|dahua|edimax|netis|qnap|qnap systems|dasan)$')
OTHER = r'camera|\bdvr\b|\bnvr\b|network[- ]attached|\bnas\b'
EXCLUDE = r'firewall|switch|live update|vigorconnect|jgs516|^multiple products$|helpdesk|pt30x'

KINDS = [
    ('command injection', 'command-injection'), ('command execution', 'command-injection'), ('argument delimiters', 'command-injection'),
    ('authentication bypass', 'login-bypass'), ('improper authentication', 'login-bypass'), ('missing authentication', 'login-bypass'),
    ('hard-coded', 'built-in-password'), ('hardcoded', 'built-in-password'),
    ('remote code execution', 'remote-code-execution'), ('code injection', 'remote-code-execution'), ('deserialization', 'remote-code-execution'),
    ('buffer overflow', 'memory-bug'), ('out-of-bounds', 'memory-bug'), ('use-after-free', 'memory-bug'),
    ('directory traversal', 'file-access'), ('path traversal', 'file-access'),
    ('information disclosure', 'information-leak'), ('exposure of', 'information-leak'),
    ('sql injection', 'sql-injection'), ('cross-site', 'web-attack'),
    ('credential', 'password-exposure'), ('cleartext', 'password-exposure'),
    ('access control', 'access-control'), ('input validation', 'input-handling'),
    ('download of code', 'unverified-update'), ('unspecified', 'not-stated'),
]


def wanted(x):
    vendor, product = x['vendorProject'], x['product']
    if re.search(EXCLUDE, product, re.I):
        return vendor.lower() == 'hikvision' and product == 'Multiple Products'
    return bool(re.search(VENDORS, vendor, re.I) or re.search(OTHER, product, re.I))


def category(x):
    t = x['vendorProject'] + ' ' + x['product']
    if re.search(r'camera|dcs-|hikvision|dahua|reolink|\bdvr\b|\bnvr\b|dnr-', t, re.I):
        return 'camera-or-recorder'
    if re.search(r'\bnas\b|network[- ]attached|storage|qnap|dns-320', t, re.I):
        return 'network-storage'
    return 'router-or-wifi'


def action(required):
    r = required.lower()
    if 'could be end-of-life' in r:
        return 'check-if-supported'
    if r.startswith('the impacted product is end-of-life') or 'affects legacy' in r or 'retire' in r:
        return 'replace'
    return 'update'


def kind(name):
    n = name.lower()
    for key, label in KINDS:
        if key in n:
            return label
    return 'other'


def advisory(notes):
    for u in re.split(r'\s*;\s*', notes):
        u = u.strip()
        if u.startswith('http') and 'nvd.nist.gov' not in u and 'web.archive.org' not in u:
            return u
    return ''


def convert(catalog):
    rows = []
    for x in catalog['vulnerabilities']:
        if not wanted(x):
            continue
        rows.append({
            'cve': x['cveID'],
            'vendor': x['vendorProject'],
            'product': x['product'],
            'category': category(x),
            'type': kind(x['vulnerabilityName']),
            'action': action(x['requiredAction']),
            'date_added': x['dateAdded'],
            'ransomware': x['knownRansomwareCampaignUse'] == 'Known',
            'advisory': advisory(x['notes']),
        })
    rows.sort(key=lambda r: (r['date_added'], r['cve']), reverse=True)
    return rows


def main():
    if len(sys.argv) > 1:
        raw = pathlib.Path(sys.argv[1]).read_text(encoding='utf-8')
    else:
        req = urllib.request.Request(SOURCE, headers={'User-Agent': 'home-device-kev (github.com/examineip)'})
        raw = urllib.request.urlopen(req, timeout=60).read().decode('utf-8')
    catalog = json.loads(raw)
    rows = convert(catalog)
    if len(rows) < 50:
        sys.exit('Refusing to write: only %d rows, the source format may have changed.' % len(rows))
    summary = {
        'source': SOURCE,
        'catalog_version': catalog['catalogVersion'],
        'count': len(rows),
        'by_category': dict(collections.Counter(r['category'] for r in rows)),
        'by_action': dict(collections.Counter(r['action'] for r in rows)),
        'ransomware': sum(1 for r in rows if r['ransomware']),
    }
    data = HERE / 'data'
    data.mkdir(exist_ok=True)
    (data / 'home-devices.json').write_text(json.dumps({'summary': summary, 'vulnerabilities': rows}, indent=2) + '\n', encoding='utf-8')
    with (data / 'home-devices.csv').open('w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()), lineterminator='\n')
        w.writeheader()
        w.writerows(rows)
    print(json.dumps(summary))


if __name__ == '__main__':
    main()
