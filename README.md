# 🛰️ SPECTRA

**Lightweight offline network traffic analyzer written in Rust.**

SPECTRA reads local **PCAP** and **PCAPNG** capture files and produces a compact terminal report of packet counts, IP versions, transport protocols, common application protocols, top source IPs, and parser warnings.

The project is intentionally small and dependency-free. It focuses on **offline analysis of captured traffic** rather than generating traffic or probing live targets.

---

## ✨ Features

- Follows common IPv6 extension headers before classifying TCP/UDP ports, including DNS, HTTP and TLS hints.
- Avoids interpreting transport ports from non-initial IPv4 fragments.


- 📦 PCAP support
- 📦 PCAPNG support
- 🌐 IPv4 and IPv6 statistics
- 🔌 TCP and UDP statistics
- 🔎 Common protocol identification by well-known ports
- 📊 Top protocol statistics
- 🛰️ Top source-IP statistics
- ⚠️ Graceful handling of incomplete/trailing PCAP records
- 🦀 Pure Rust implementation
- 📚 Zero third-party Rust dependencies
- 💻 Command-line interface

---

## 📥 Installation

### Requirements

You need:

- Rust and Cargo
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

### Analyze a PCAP file

```bash
./target/release/spectra capture.pcap
```

### Analyze a PCAPNG file

```bash
./target/release/spectra capture.pcapng
```

### Show help

```bash
./target/release/spectra --help
```

During development, you can also run it through Cargo:

```bash
cargo run -- capture.pcap
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

Warnings
────────────────────────────────────
[!] Stopped after 20 complete packet(s): trailing/incomplete packet record reports 1348031555 captured bytes, but only 3197 remain.
```

The values naturally depend on the capture file. The warning above demonstrates that SPECTRA can keep valid packet records when a capture contains an incomplete trailing record.

See [`docs/DEMO.md`](docs/DEMO.md) for a little more context about the test capture.

---

## 🧭 Processing Pipeline

SPECTRA currently follows a lightweight offline parsing pipeline:

```text
PCAP / PCAPNG
      ↓
Packet records
      ↓
Ethernet / IP parsing
      ↓
TCP / UDP parsing
      ↓
Well-known port classification
      ↓
Statistics
      ↓
Terminal report
```

Application protocols are identified conservatively from well-known TCP/UDP ports. SPECTRA does **not** attempt full application-payload decoding in the current release.

---

## 🧪 Testing

The repository includes a small smoke test that verifies the release build and CLI startup:

```bash
bash tests/smoke.sh
```

You can also build and test the project directly with Cargo:

```bash
cargo build --release
cargo test
```

GitHub Actions is configured to run the build/test check automatically on pushes and pull requests.

---

## 📂 Project Structure

```text
SPECTRA/
├── .github/
│   └── workflows/
│       └── ci.yml
├── docs/
│   └── DEMO.md
├── src/
│   └── main.rs
├── tests/
│   └── smoke.sh
├── Cargo.toml
├── LICENSE
├── README.md
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

This keeps the tool small, predictable, and easy to audit.

---

## 🔐 Responsible Use

SPECTRA is intended for **security research, education, troubleshooting, and authorized network analysis**.

Only analyze packet captures that you are authorized to access and inspect.

---

## 📜 License

MIT License. See [`LICENSE`](LICENSE) for details.
