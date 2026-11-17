# Security Policy / Güvenlik Politikası

## Supported versions / Desteklenen sürümler

Security fixes are applied to the latest release on the `main` branch.

Güvenlik düzeltmeleri `main` dalındaki en son sürüme uygulanır.

## Reporting a vulnerability / Güvenlik açığı bildirme

Please **do not** open a public issue for a security problem. Do not attach
real capture files, personal data, credentials, or sensitive network traffic.

Güvenlik sorunları için lütfen **herkese açık issue açma**. Gerçek paket
yakalama dosyası, kişisel veri, kimlik bilgisi veya hassas ağ trafiği ekleme.

Use GitHub private vulnerability reporting:

- <https://github.com/raxwqx/SPECTRA/security/advisories/new>

Please include:

- affected version or commit,
- steps to reproduce,
- a minimal synthetic capture or byte sequence,
- expected and actual behavior,
- impact assessment.

Lütfen şunları ekle:

- etkilenen sürüm veya commit,
- yeniden üretme adımları,
- en küçük sentetik yakalama veya bayt dizisi,
- beklenen ve gerçek davranış,
- etki değerlendirmesi.

## Scope / Kapsam

Relevant reports include parser crashes, out-of-bounds reads, unbounded memory
growth, integer overflows, malformed PCAP/PCAPNG handling, and terminal escape
injection through crafted packet data.

İlgili bildirimler arasında ayrıştırıcı çökmeleri, sınır dışı okumalar,
sınırsız bellek büyümesi, tamsayı taşmaları, bozuk PCAP/PCAPNG işleme ve
hazırlanmış paket verisi üzerinden terminal kaçış enjeksiyonu yer alır.

## Research boundaries / Araştırma sınırları

SPECTRA is a passive, offline analyzer. It does not open network connections,
scan hosts, inject packets, or fetch remote content. Only analyze captures you
are authorized to inspect.

SPECTRA pasif, çevrimdışı bir analiz aracıdır. Ağ bağlantısı açmaz, ana makine
taraması yapmaz, paket enjekte etmez veya uzak içerik getirmez. Yalnızca
inceleme yetkiniz olan yakalamaları analiz edin.
