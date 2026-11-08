# home-device-kev

Which home routers, Wi-Fi gear, cameras and network storage devices have flaws that attackers
are confirmed to be using, as data you can download.

This filters the [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
down to equipment found in homes and small offices, and refreshes every week.

It contains no exploit code, only what you need to find out whether a device is affected and what to do.
There's a searchable version on the [Exploited Router Flaws](https://examineip.com/exploited-router-vulnerabilities/) page.

## Data

- [`data/home-devices.json`](data/home-devices.json), with a summary block
- [`data/home-devices.csv`](data/home-devices.csv)

| Field | Meaning |
|---|---|
| `cve` | CVE identifier |
| `vendor`, `product` | As CISA lists them |
| `category` | `router-or-wifi`, `network-storage` or `camera-or-recorder` |
| `type` | Plain category derived from CISA's vulnerability name |
| `action` | `update`, `replace` or `check-if-supported` |
| `date_added` | When CISA listed it, not when it was discovered |
| `ransomware` | CISA marks it as used in ransomware campaigns |
| `advisory` | First vendor link in CISA's notes, if there is one |

## Limits

- `category`, `type` and `action` are our summaries of CISA's entries. Check the original before acting on them.
- Business firewalls, switches and enterprise gateways are left out on purpose.
- A listed flaw may only affect certain models or firmware.
- Not being listed doesn't make a device safe. The catalog only covers flaws with evidence of real-world use.

## Run it

```
python build.py
python tests/run.py
```

Python 3 standard library only.

## License

Code: MIT. Data comes from CISA's catalog.
