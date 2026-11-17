# 🛰️ SPECTRA

**Lightweight offline network traffic analyzer written in Rust.**

SPECTRA reads local **PCAP** and **PCAPNG** capture files and produces a compact terminal report of packet counts, IP versions, transport protocols, common application protocols, top source IPs, **top conversations**, and parser warnings. It can also emit a **machine-readable JSON report** for automation.

The project is intentionally small and dependency-free. It focuses on **offline analysis of captured traffic** rather than generating traffic or probing live targets.

<p>
  <img src="https://img.shields.io/badge/version-0.2.0-9cffb5?style=for-the-badge&labelColor=101713" alt="Version 0.2.0" />
  <img src="https://img.shields.io/badge/Rust-1.82%2B-f3d58a?style=for-the-badge&logo=rust&logoColor=white&labelColor=101713" alt="Rust 1.82 or newer" />
  <img src="https://img.shields.io/badge/License-MIT-9bdcff?style=for-the-badge&labelColor=101713" alt="MIT License" />
</p>

[English](README.md) · [Türkçe](README.tr.md)

---

## ✨ Features

- 📦 PCAP support (little-endian, big-endian, microsecond and nanosecond magic)
- 📦 PCAPNG support (little-endian and big-endian sections)
- 🌐 IPv4 and IPv6 statistics
- 🔌 TCP and UDP statistics
- 🔗 **Bidirectional conversation tracking and top-conversation ranking**
- 🧾 **JSON report output with `--json`**
- 🏷️ 802.1Q, 802.1ad (QinQ), and legacy VLAN tag unwrapping
- 🧩 IPv6 extension-header aware transport parsing
- 🐧 Linux cooked capture support (SLL and SLL2, e.g. `tcpdump -i any`)
- 🔎 Common protocol identification by well-known ports
- 📊 Top protocol statistics
- 🛰️ Top source-IP statistics
- ⚠️ Graceful handling of incomplete/trailing PCAP and PCAPNG records
- 🦀 Pure Rust implementation
- 📚 Zero third-party Rust dependencies
- 💻 Command-line interface with `--help`, `--version`, and `--json`

---

## 📥 Installation

### Requirements

You need:

- Rust 1.82 or newer (Cargo included)
- A local `.pcap` or `.pcapng` capture file

Check your Rust installation:

```bash
rustc --version
cargo --version
```

### Clone the repository

```bash
git clone https://github.com/raxwqx/SPECTRA.git
cd SPECTRA
```

### Build SPECTRA

Create an optimized release binary:

```bash
cargo build --release
```

The compiled binary will be created at:

```text
target/release/spectra
```

No `pip install`, package manager, or third-party Rust dependency installation is required.

---

## 🚀 Usage

### Analyze a PCAP or PCAPNG file

```bash
./target/release/spectra capture.pcap
./target/release/spectra capture.pcapng
```

### Machine-readable JSON report

```bash
./target/release/spectra --json capture.pcap
```

### Help and version

```bash
./target/release/spectra --help
./target/release/spectra --version
```

During development, you can also run it through Cargo:

```bash
cargo run -- capture.pcap
cargo run -- --json capture.pcap
```

---

## 📋 Example Output

Example from a local test capture:

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

Top Conversations
────────────────────────────────────
127.0.0.1 ↔ 127.0.0.1          20

Warnings
────────────────────────────────────
[!] Stopped after 20 complete packet(s): trailing/incomplete packet record reports 1348031555 captured bytes, but only 3197 remain.
```

The values naturally depend on the capture file. The warning above demonstrates that SPECTRA can keep valid packet records when a capture contains an incomplete trailing record.

Conversations are normalized so that `A → B` and `B → A` count toward the same endpoint pair.

See [`docs/DEMO.md`](docs/DEMO.md) for a little more context about the test capture.

---

## 🧾 JSON Output

`--json` prints a stable, script-friendly report:

```json
{
  "tool": "SPECTRA",
  "version": "0.2.0",
  "file": "test.pcap",
  "packets": 20,
  "ipv4": 20,
  "ipv6": 0,
  "tcp": 20,
  "udp": 0,
  "other": 0,
  "protocols": {
    "HTTP": 2,
    "TCP": 18
  },
  "top_talkers": {
    "127.0.0.1": 20
  },
  "conversations": {
    "127.0.0.1 <-> 127.0.0.1": 20
  },
  "warnings": []
}
```

All map keys are sorted, strings are JSON-escaped, and warnings remain in the `warnings` array.

---

## 🧭 Processing Pipeline

```text
PCAP / PCAPNG
      ↓
Packet records
      ↓
Ethernet / VLAN / Linux cooked / raw IP
      ↓
IPv4 / IPv6 (extension headers)
      ↓
TCP / UDP parsing
      ↓
Well-known port classification
      ↓
Statistics and conversations
      ↓
Terminal report or JSON
```

Application protocols are identified conservatively from well-known TCP/UDP ports. SPECTRA does **not** attempt full application-payload decoding in the current release.

### Supported capture details

| Area | Support |
|---|---|
| PCAP byte order | Little-endian and big-endian |
| PCAP timestamp magic | Microsecond and nanosecond variants |
| PCAPNG byte order | Per-section little-endian and big-endian |
| Link types | Ethernet (1), raw IPv4/IPv6 (101), Linux SLL (113), Linux SLL2 (276) |
| Ethernet tags | 802.1Q, 802.1ad/QinQ, legacy 0x9100 |
| IPv6 extension headers | Hop-by-hop, routing, destination options, fragment, AH |
| Transport | TCP and UDP port classification; ICMP/ICMPv6 counters |

---

## 🧪 Testing

The repository includes a smoke test that verifies the release build, CLI startup, and JSON output:

```bash
bash tests/smoke.sh
```

You can also build, lint, and test the project directly with Cargo:

```bash
cargo fmt -- --check
cargo clippy --all-targets -- -D warnings
cargo build --release
cargo test
```

The unit tests build synthetic PCAP/PCAPNG buffers in memory, so they do not need a capture file or network access. GitHub Actions runs formatting, Clippy, build, tests, and the smoke test on every push and pull request.

---

## 📂 Project Structure

```text
SPECTRA/
├── .github/
│   ├── workflows/
│   │   └── ci.yml
│   └── dependabot.yml
├── docs/
│   └── DEMO.md
├── src/
│   └── main.rs
├── tests/
│   └── smoke.sh
├── Cargo.toml
├── CHANGELOG.md
├── SECURITY.md
├── LICENSE
├── README.md        # English (this file)
├── README.tr.md     # Turkish
└── .gitignore
```

---

## 🛡️ Scope

SPECTRA is deliberately focused on **offline packet analysis**.

It does not currently:

- scan live hosts
- open network connections to targets
- perform active reconnaissance
- inject packets
- decode arbitrary application payloads
- write or modify capture files

This keeps the tool small, predictable, and easy to audit.

---

## 🔐 Responsible Use

SPECTRA is intended for **security research, education, troubleshooting, and authorized network analysis**.

Only analyze packet captures that you are authorized to access and inspect. Capture files can contain personal data, credentials, and sensitive infrastructure details; review them before sharing reports or exporting JSON.

---

## 📜 License

MIT License. See [`LICENSE`](LICENSE) for details.

---

<div align="center">
  <strong>SPECTRA</strong><br />
  <sub>Offline PCAP/PCAPNG analysis · v0.2.0</sub>
</div>
