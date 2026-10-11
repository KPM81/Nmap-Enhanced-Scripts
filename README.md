# Nmap UPnP Enhanced Scripts

Enhanced Nmap NSE scripts built on top of the base `broadcast-upnp-info.nse` script for UPnP device discovery, with two new capabilities: **Security Risk Assessment** and **JSON Export with Device Fingerprinting**.

## Scripts

| File | Description |
|------|-------------|
| `broadcast-upnp-info.nse` | Original base script — UPnP multicast discovery |
| `broadcast-upnp-info-security-risk.nse` | **Enhancement 1** — Security Risk Assessment |
| `broadcast-upnp-info-json-fingerprint.nse` | **Enhancement 2** — JSON Export & Device Fingerprinting |

## Enhancement 1: Security Risk Assessment

Analyzes discovered UPnP devices for potential security risks:
- Identifies risky service types (WANIPConnection, RemoteAccess, etc.)
- Detects known vulnerable UPnP stacks (old MiniUPnPd, Intel SDK, libupnp)
- Assigns per-device severity: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
- Generates actionable security recommendations

### Usage
```bash
nmap --script broadcast-upnp-info-security-risk.nse -e <interface>
```

## Enhancement 2: JSON Export & Device Fingerprinting

Fingerprints and classifies UPnP devices, then exports results as JSON:
- OS fingerprinting from server headers (Windows, Linux, macOS, etc.)
- Device category classification (Router, Media Server, Smart TV, IoT, NAS, etc.)
- UPnP stack identification
- Structured JSON export for SIEM/asset inventory integration

### Usage
```bash
nmap --script broadcast-upnp-info-json-fingerprint.nse -e <interface>
nmap --script broadcast-upnp-info-json-fingerprint.nse -e <interface> --script-args upnp_json_out=output.json
```

## Requirements

- [Nmap](https://nmap.org/) 7.x or later
- Network interface with UPnP devices on the LAN

## License

Same as Nmap — See https://nmap.org/book/man-legal.html
