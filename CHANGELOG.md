# Changelog

Notable changes to SPECTRA are documented here.

## 0.2.0 - Conversations, JSON reports, and parser hardening

### Added

- **Top conversations:** SPECTRA now tracks bidirectional endpoint pairs and
  ranks the busiest conversations alongside top talkers.
- **JSON reports:** `--json` prints a machine-readable report with packet
  counts, protocol statistics, top talkers, conversations, and warnings.
- `--version` / `-V` and clearer CLI errors for unknown options and missing
  capture paths.
- Linux cooked capture support (linktypes 113 and SLL2 276), including
  `tcpdump -i any` captures.
- Additional well-known port classifications (SMB, RDP, VNC, Redis, MongoDB,
  Telnet, TFTP, Syslog, OpenVPN, SSDP, mDNS, WireGuard, HTTP 8080).
- Unit tests covering IPv4/IPv6 parsing, VLAN tags, Linux cooked capture,
  PCAPNG little/big endian, SPB linktypes, truncation warnings, and JSON
  escaping.

### Fixed

- IPv6 extension headers (hop-by-hop, routing, destination options, fragment,
  AH) are walked so transport ports are classified correctly.
- IPv4 total length is respected, so Ethernet padding is never parsed as
  payload.
- 802.1Q, 802.1ad (QinQ), and legacy 0x9100 VLAN tags are unwrapped before
  network-layer parsing.
- Simple Packet Blocks in PCAPNG now use interface 0's link type instead of
  assuming Ethernet.
- Truncated PCAPNG blocks produce a warning and keep earlier packets instead
  of aborting with an error, matching PCAP behavior.
- PCAPNG big-endian sections and per-section interface IDs are handled
  correctly.
- Malformed enhanced packet blocks are bounded by their declared block length.
- Trailing bytes after the last complete record are reported instead of being
  silently ignored.
- Dead code and an unused destination variable were removed.

## 0.1.0 - Initial release

- Offline PCAP and PCAPNG parsing.
- IPv4/IPv6 and TCP/UDP statistics.
- Well-known port classification.
- Top protocol and top source-IP tables.
- Graceful handling of incomplete trailing PCAP records.
