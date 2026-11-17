# 🛰️ SPECTRA

**Rust ile yazılmış hafif, çevrimdışı ağ trafiği analiz aracı.**

SPECTRA yerel **PCAP** ve **PCAPNG** yakalama dosyalarını okur; paket sayıları, IP sürümleri, taşıma protokolleri, yaygın uygulama protokolleri, en çok konuşan kaynak IP'ler, **en yoğun konuşmalar** ve ayrıştırıcı uyarılarından oluşan kompakt bir terminal raporu üretir. Otomasyon için **makine tarafından okunabilir JSON raporu** da yazdırabilir.

Proje bilinçli olarak küçük ve bağımlılıksızdır. Trafik üretmek veya canlı hedefleri yoklamak yerine **yakalanmış trafiğin çevrimdışı analizine** odaklanır.

<p>
  <img src="https://img.shields.io/badge/version-0.2.0-9cffb5?style=for-the-badge&labelColor=101713" alt="Sürüm 0.2.0" />
  <img src="https://img.shields.io/badge/Rust-1.82%2B-f3d58a?style=for-the-badge&logo=rust&logoColor=white&labelColor=101713" alt="Rust 1.82 veya üzeri" />
  <img src="https://img.shields.io/badge/License-MIT-9bdcff?style=for-the-badge&labelColor=101713" alt="MIT Lisansı" />
</p>

[English](README.md) · [Türkçe](README.tr.md)

---

## ✨ Özellikler

- 📦 PCAP desteği (küçük/büyük endian, mikrosaniye ve nanosaniye sihirli sayıları)
- 📦 PCAPNG desteği (küçük ve büyük endian bölümler)
- 🌐 IPv4 ve IPv6 istatistikleri
- 🔌 TCP ve UDP istatistikleri
- 🔗 **Çift yönlü konuşma takibi ve en yoğun konuşmalar sıralaması**
- 🧾 **`--json` ile JSON rapor çıktısı**
- 🏷️ 802.1Q, 802.1ad (QinQ) ve eski VLAN etiketlerinin açılması
- 🧩 IPv6 uzantı başlıklarını dikkate alan taşıma katmanı ayrıştırması
- 🐧 Linux cooked capture desteği (SLL ve SLL2; örn. `tcpdump -i any`)
- 🔎 Yaygın bağlantı noktalarıyla protokol tanımlama
- 📊 En çok görülen protokol istatistikleri
- 🛰️ En çok konuşan kaynak IP istatistikleri
- ⚠️ Eksik/sondaki PCAP ve PCAPNG kayıtlarına karşı dayanıklılık
- 🦀 Saf Rust uygulaması
- 📚 Sıfır üçüncü taraf Rust bağımlılığı
- 💻 `--help`, `--version` ve `--json` destekli komut satırı arayüzü

---

## 📥 Kurulum

### Gereksinimler

Şunlara ihtiyacınız var:

- Rust 1.82 veya üzeri (Cargo dahil)
- Yerel bir `.pcap` veya `.pcapng` yakalama dosyası

Rust kurulumunuzu kontrol edin:

```bash
rustc --version
cargo --version
```

### Depoyu klonlayın

```bash
git clone https://github.com/raxwqx/SPECTRA.git
cd SPECTRA
```

### SPECTRA'yı derleyin

Optimize edilmiş bir sürüm ikilisi oluşturun:

```bash
cargo build --release
```

Derlenen ikili şu konumda oluşur:

```text
target/release/spectra
```

`pip install`, paket yöneticisi veya üçüncü taraf Rust bağımlılığı kurulumu gerekmez.

---

## 🚀 Kullanım

### PCAP veya PCAPNG dosyasını analiz edin

```bash
./target/release/spectra capture.pcap
./target/release/spectra capture.pcapng
```

### Makine tarafından okunabilir JSON raporu

```bash
./target/release/spectra --json capture.pcap
```

### Yardım ve sürüm

```bash
./target/release/spectra --help
./target/release/spectra --version
```

Geliştirme sırasında Cargo üzerinden de çalıştırabilirsiniz:

```bash
cargo run -- capture.pcap
cargo run -- --json capture.pcap
```

---

## 📋 Örnek Çıktı

Yerel bir test yakalamasından örnek:

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

Değerler doğal olarak yakalama dosyasına bağlıdır. Yukarıdaki uyarı, yakalamada eksik bir son kayıt olduğunda SPECTRA'nın geçerli paket kayıtlarını koruyabildiğini gösterir.

Konuşmalar normalize edilir; `A → B` ve `B → A` aynı uç nokta çifti altında sayılır.

Test yakalaması hakkında daha fazla bağlam için [`docs/DEMO.md`](docs/DEMO.md) dosyasına bakın.

---

## 🧾 JSON Çıktısı

`--json` sabit ve betik dostu bir rapor yazdırır:

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

Tüm harita anahtarları sıralıdır, metinler JSON için kaçışlanır ve uyarılar `warnings` dizisinde korunur.

---

## 🧭 İşleme Hattı

```text
PCAP / PCAPNG
      ↓
Paket kayıtları
      ↓
Ethernet / VLAN / Linux cooked / ham IP
      ↓
IPv4 / IPv6 (uzantı başlıkları)
      ↓
TCP / UDP ayrıştırma
      ↓
Yaygın bağlantı noktası sınıflandırması
      ↓
İstatistikler ve konuşmalar
      ↓
Terminal raporu veya JSON
```

Uygulama protokolleri, yaygın TCP/UDP bağlantı noktalarından temkinli biçimde tanımlanır. SPECTRA mevcut sürümde tam uygulama yükü çözümlemesi yapmaz.

### Desteklenen yakalama ayrıntıları

| Alan | Destek |
|---|---|
| PCAP bayt sırası | Küçük endian ve büyük endian |
| PCAP zaman damgası | Mikrosaniye ve nanosaniye varyantları |
| PCAPNG bayt sırası | Bölüm bazında küçük ve büyük endian |
| Bağlantı türleri | Ethernet (1), ham IPv4/IPv6 (101), Linux SLL (113), Linux SLL2 (276) |
| Ethernet etiketleri | 802.1Q, 802.1ad/QinQ, eski 0x9100 |
| IPv6 uzantı başlıkları | Hop-by-hop, routing, destination options, fragment, AH |
| Taşıma katmanı | TCP/UDP bağlantı noktası sınıflandırması; ICMP/ICMPv6 sayaçları |

---

## 🧪 Testler

Depo, sürüm derlemesini, CLI başlangıcını ve JSON çıktısını doğrulayan bir smoke test içerir:

```bash
bash tests/smoke.sh
```

Projeyi doğrudan Cargo ile de derleyebilir, denetleyebilir ve test edebilirsiniz:

```bash
cargo fmt -- --check
cargo clippy --all-targets -- -D warnings
cargo build --release
cargo test
```

Birim testleri sentetik PCAP/PCAPNG tamponlarını bellekte oluşturur; yakalama dosyasına veya ağ erişimine ihtiyaç duymaz. GitHub Actions her push ve pull request'te biçimlendirme, Clippy, derleme, testler ve smoke test çalıştırır.

---

## 📂 Proje Yapısı

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
├── README.md        # İngilizce
├── README.tr.md     # Türkçe (bu dosya)
└── .gitignore
```

---

## 🛡️ Kapsam

SPECTRA bilinçli olarak **çevrimdışı paket analizine** odaklanır.

Mevcut sürümde şunları yapmaz:

- canlı ana makineleri taramak
- hedeflere ağ bağlantısı açmak
- aktif keşif yapmak
- paket enjekte etmek
- rastgele uygulama yüklerini çözmek
- yakalama dosyalarını yazmak veya değiştirmek

Bu, aracı küçük, öngörülebilir ve denetlenmesi kolay tutar.

---

## 🔐 Sorumlu Kullanım

SPECTRA **güvenlik araştırması, eğitim, sorun giderme ve yetkilendirilmiş ağ analizi** için tasarlanmıştır.

Yalnızca erişme ve inceleme yetkiniz olan paket yakalamalarını analiz edin. Yakalama dosyaları kişisel veri, kimlik bilgisi ve hassas altyapı ayrıntıları içerebilir; raporları veya JSON çıktısını paylaşmadan önce gözden geçirin.

---

## 📜 Lisans

MIT Lisansı. Ayrıntılar için [`LICENSE`](LICENSE) dosyasına bakın.

---

<div align="center">
  <strong>SPECTRA</strong><br />
  <sub>Çevrimdışı PCAP/PCAPNG analizi · v0.2.0</sub>
</div>
