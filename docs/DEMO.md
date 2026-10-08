# 🧪 Local Demo

This document records a small local validation run of SPECTRA.

A short TCP capture was created from loopback traffic generated against a local Python HTTP server. No external target was required.

## Capture

```text
File: test.pcap
Packets observed by SPECTRA: 20
IPv4 packets: 20
IPv6 packets: 0
TCP packets: 20
UDP packets: 0
```

## SPECTRA output

```text
SPECTRA
====================================
File       : test.pcap

Packets    : 20
IPv4       : 20
IPv6       : 0
TCP        : 20
UDP        : 0
Other      : 0

Top Protocols
────────────────────────────────────
TCP                            18
HTTP                            2

Top Talkers
────────────────────────────────────
127.0.0.1                      20
```

The original test capture also contained an incomplete trailing record. SPECTRA reported it as a warning instead of aborting after the 20 complete records.

## Notes

The demo is intentionally local and reproducible. The capture file itself is not committed to the repository because binary packet captures can be large and may contain environment-specific or sensitive traffic.
