#!/usr/bin/env python3
"""python tests/run.py: classification rules, on made-up catalog entries."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import build


def e(vendor, product, name='Test Vulnerability', required='Apply updates per vendor instructions.', notes='', ransom='Unknown', cve='CVE-2024-0001', date='2024-01-02'):
    return {'cveID': cve, 'vendorProject': vendor, 'product': product, 'vulnerabilityName': name, 'requiredAction': required,
            'notes': notes, 'knownRansomwareCampaignUse': ransom, 'dateAdded': date}


CASES = [
    (build.wanted, e('TP-Link', 'Archer AX21'), True),
    (build.wanted, e('D-Link', 'DIR-820 Router'), True),
    (build.wanted, e('Zyxel', 'Multiple Firewalls'), False),
    (build.wanted, e('Zyxel', 'GS1900 Series Switches'), False),
    (build.wanted, e('ASUS', 'Live Update'), False),
    (build.wanted, e('Microsoft', 'Windows'), False),
    (build.wanted, e('Amcrest', 'Cameras and Network Video Recorder (NVR)'), True),
    (build.wanted, e('Hikvision', 'Multiple Products'), True),
    (build.category, e('QNAP', 'Photo Station'), 'network-storage'),
    (build.category, e('D-Link', 'DCS-930L Devices'), 'camera-or-recorder'),
    (build.category, e('Tenda', 'AC11 Router'), 'router-or-wifi'),
    (build.action, 'The impacted product is end-of-life and should be disconnected if still in use.', 'replace'),
    (build.action, 'The impacted product could be end-of-life (EoL). Users should check.', 'check-if-supported'),
    (build.action, 'Apply updates per vendor instructions. If the affected device has since entered end-of-life, it should be disconnected if still in use.', 'update'),
    (build.action, 'This vulnerability affects legacy D-Link products.', 'replace'),
    (build.kind, 'D-Link DIR-859 Router Command Execution Vulnerability', 'command-injection'),
    (build.kind, 'Zyxel Hard-Coded Credential Vulnerability', 'built-in-password'),
    (build.kind, 'Something Entirely New', 'other'),
    (build.advisory, 'https://nvd.nist.gov/vuln/detail/CVE-1 ; https://vendor.example/advisory', 'https://vendor.example/advisory'),
    (build.advisory, 'https://nvd.nist.gov/vuln/detail/CVE-1', ''),
]

failed = 0
for fn, arg, want in CASES:
    got = fn(arg)
    if got != want:
        failed += 1
        print('FAIL', fn.__name__, arg, 'got', got, 'want', want)

rows = build.convert({'vulnerabilities': [
    e('TP-Link', 'Archer', cve='CVE-2023-1', date='2023-05-01'),
    e('Microsoft', 'Windows', cve='CVE-2023-2', date='2025-05-01'),
    e('D-Link', 'DIR-1', cve='CVE-2024-3', date='2025-01-01', ransom='Known'),
]})
if [r['cve'] for r in rows] != ['CVE-2024-3', 'CVE-2023-1'] or rows[0]['ransomware'] is not True:
    failed += 1
    print('FAIL convert', rows)

print('%d passed, %d failed' % (len(CASES) + 1 - failed, failed))
sys.exit(1 if failed else 0)
