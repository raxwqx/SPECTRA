use std::collections::HashMap;
use std::env;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const LIST_LIMIT: usize = 10;

#[derive(Default)]
struct Stats {
    packets: u64,
    ipv4: u64,
    ipv6: u64,
    tcp: u64,
    udp: u64,
    other: u64,
    protocols: HashMap<String, u64>,
    talkers: HashMap<String, u64>,
    conversations: HashMap<(String, String), u64>,
    warnings: Vec<String>,
}

impl Stats {
    fn record_protocol(&mut self, proto: &str) {
        *self.protocols.entry(proto.to_string()).or_insert(0) += 1;
    }

    fn record_talker(&mut self, ip: &str) {
        *self.talkers.entry(ip.to_string()).or_insert(0) += 1;
    }

    fn record_conversation(&mut self, a: &str, b: &str) {
        let key = if a <= b {
            (a.to_string(), b.to_string())
        } else {
            (b.to_string(), a.to_string())
        };
        *self.conversations.entry(key).or_insert(0) += 1;
    }
}

fn usage() {
    println!("SPECTRA {} - Offline Network Traffic Analyzer", VERSION);
    println!();
    println!("Usage:");
    println!("  spectra [--json] <capture.pcap|capture.pcapng>");
    println!();
    println!("Options:");
    println!("  --json         Print a machine-readable JSON report");
    println!("  -V, --version  Print the SPECTRA version");
    println!("  -h, --help     Show this help message");
}

fn read_u16(data: &[u8], off: usize, le: bool) -> Option<u16> {
    let b = data.get(off..off + 2)?;
    Some(if le {
        u16::from_le_bytes([b[0], b[1]])
    } else {
        u16::from_be_bytes([b[0], b[1]])
    })
}

fn read_u32(data: &[u8], off: usize, le: bool) -> Option<u32> {
    let b = data.get(off..off + 4)?;
    Some(if le {
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    } else {
        u32::from_be_bytes([b[0], b[1], b[2], b[3]])
    })
}

fn protocol_name(src: u16, dst: u16, transport: &str) -> &'static str {
    if transport == "TCP" {
        match (src, dst) {
            (80, _) | (_, 80) | (8080, _) | (_, 8080) => "HTTP",
            (443, _) | (_, 443) => "TLS",
            (22, _) | (_, 22) => "SSH",
            (21, _) | (_, 21) => "FTP",
            (23, _) | (_, 23) => "Telnet",
            (25, _) | (_, 25) => "SMTP",
            (110, _) | (_, 110) => "POP3",
            (143, _) | (_, 143) => "IMAP",
            (445, _) | (_, 445) => "SMB",
            (3306, _) | (_, 3306) => "MySQL",
            (3389, _) | (_, 3389) => "RDP",
            (5432, _) | (_, 5432) => "PostgreSQL",
            (5900, _) | (_, 5900) => "VNC",
            (6379, _) | (_, 6379) => "Redis",
            (27017, _) | (_, 27017) => "MongoDB",
            _ => "TCP",
        }
    } else if transport == "UDP" {
        match (src, dst) {
            (53, _) | (_, 53) => "DNS",
            (67, _) | (68, _) | (_, 67) | (_, 68) => "DHCP",
            (69, _) | (_, 69) => "TFTP",
            (123, _) | (_, 123) => "NTP",
            (161, _) | (_, 161) => "SNMP",
            (514, _) | (_, 514) => "Syslog",
            (1194, _) | (_, 1194) => "OpenVPN",
            (1900, _) | (_, 1900) => "SSDP",
            (5353, _) | (_, 5353) => "mDNS",
            (51820, _) | (_, 51820) => "WireGuard",
            _ => "UDP",
        }
    } else {
        transport_name_default(transport)
    }
}

fn transport_name_default(name: &str) -> &'static str {
    match name {
        "ICMP" => "ICMP",
        "ICMPv6" => "ICMPv6",
        _ => "Other",
    }
}

fn record_other(stats: &mut Stats) {
    stats.other += 1;
    stats.record_protocol("Other");
}

fn classify_transport(payload: &[u8], transport: &str, stats: &mut Stats) {
    if payload.len() >= 4 {
        let sp = u16::from_be_bytes([payload[0], payload[1]]);
        let dp = u16::from_be_bytes([payload[2], payload[3]]);
        stats.record_protocol(protocol_name(sp, dp, transport));
    } else {
        stats.record_protocol(transport);
    }
}

fn parse_ipv4(packet: &[u8], stats: &mut Stats) {
    if packet.len() < 20 || (packet[0] >> 4) != 4 {
        return;
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    if ihl < 20 || packet.len() < ihl {
        return;
    }
    // Respect the IPv4 total length so Ethernet padding is never parsed as payload.
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    let end = if total_len >= ihl && total_len <= packet.len() {
        total_len
    } else {
        packet.len()
    };
    stats.ipv4 += 1;
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]).to_string();
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]).to_string();
    stats.record_talker(&src);
    stats.record_conversation(&src, &dst);
    let payload = &packet[ihl..end];
    match packet[9] {
        6 => {
            stats.tcp += 1;
            classify_transport(payload, "TCP", stats);
        }
        17 => {
            stats.udp += 1;
            classify_transport(payload, "UDP", stats);
        }
        1 => stats.record_protocol("ICMP"),
        _ => record_other(stats),
    }
}

fn parse_ipv6(packet: &[u8], stats: &mut Stats) {
    if packet.len() < 40 || (packet[0] >> 4) != 6 {
        return;
    }
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let end = if payload_len > 0 {
        (40 + payload_len).min(packet.len())
    } else {
        packet.len()
    };
    stats.ipv6 += 1;
    let mut src_oct = [0u8; 16];
    src_oct.copy_from_slice(&packet[8..24]);
    let mut dst_oct = [0u8; 16];
    dst_oct.copy_from_slice(&packet[24..40]);
    let src = Ipv6Addr::from(src_oct).to_string();
    let dst = Ipv6Addr::from(dst_oct).to_string();
    stats.record_talker(&src);
    stats.record_conversation(&src, &dst);

    // Walk IPv6 extension headers to find the real transport offset.
    let mut next = packet[6];
    let mut off = 40usize;
    let mut hops = 0;
    while hops < 8 && off < end {
        match next {
            0 | 43 | 60 => {
                if off + 2 > end {
                    break;
                }
                let header_len = (usize::from(packet[off + 1]) + 1) * 8;
                if off + header_len > end {
                    off = end;
                    break;
                }
                next = packet[off];
                off += header_len;
            }
            51 => {
                if off + 2 > end {
                    break;
                }
                let header_len = (usize::from(packet[off + 1]) + 2) * 4;
                if off + header_len > end {
                    off = end;
                    break;
                }
                next = packet[off];
                off += header_len;
            }
            44 => {
                if off + 8 > end {
                    break;
                }
                let fragment = u16::from_be_bytes([packet[off + 2], packet[off + 3]]);
                next = packet[off];
                off += 8;
                if fragment & 0xfff8 != 0 {
                    // Non-first fragment: transport ports live in the first fragment.
                    off = end;
                    break;
                }
            }
            _ => break,
        }
        hops += 1;
    }
    let payload = if off <= end { &packet[off..end] } else { &[] };
    match next {
        6 => {
            stats.tcp += 1;
            classify_transport(payload, "TCP", stats);
        }
        17 => {
            stats.udp += 1;
            classify_transport(payload, "UDP", stats);
        }
        58 => stats.record_protocol("ICMPv6"),
        _ => record_other(stats),
    }
}

fn parse_network(ethertype: u16, payload: &[u8], stats: &mut Stats) {
    match ethertype {
        0x0800 => parse_ipv4(payload, stats),
        0x86dd => parse_ipv6(payload, stats),
        _ => record_other(stats),
    }
}

fn parse_ethernet(packet: &[u8], stats: &mut Stats) {
    if packet.len() < 14 {
        record_other(stats);
        return;
    }
    let mut ethertype = u16::from_be_bytes([packet[12], packet[13]]);
    let mut payload_off = 14usize;
    let mut tags = 0;
    // Support 802.1Q, 802.1ad (QinQ), and the legacy 0x9100 VLAN tag.
    while matches!(ethertype, 0x8100 | 0x88a8 | 0x9100) && tags < 4 {
        if packet.len() < payload_off + 4 {
            record_other(stats);
            return;
        }
        ethertype = u16::from_be_bytes([packet[payload_off + 2], packet[payload_off + 3]]);
        payload_off += 4;
        tags += 1;
    }
    parse_network(ethertype, &packet[payload_off..], stats);
}

fn parse_packet(packet: &[u8], linktype: u32, stats: &mut Stats) {
    stats.packets += 1;
    match linktype {
        // Ethernet
        1 => parse_ethernet(packet, stats),
        // Raw IPv4/IPv6
        101 => match packet.first().map(|b| b >> 4) {
            Some(4) => parse_ipv4(packet, stats),
            Some(6) => parse_ipv6(packet, stats),
            _ => record_other(stats),
        },
        // Linux cooked capture v1 (tcpdump -i any)
        113 => {
            if packet.len() < 16 {
                record_other(stats);
            } else {
                let ethertype = u16::from_be_bytes([packet[14], packet[15]]);
                parse_network(ethertype, &packet[16..], stats);
            }
        }
        // Linux cooked capture v2
        276 => {
            if packet.len() < 20 {
                record_other(stats);
            } else {
                let ethertype = u16::from_be_bytes([packet[0], packet[1]]);
                parse_network(ethertype, &packet[20..], stats);
            }
        }
        _ => record_other(stats),
    }
}

fn parse_pcap(data: &[u8], stats: &mut Stats) -> Result<(), String> {
    if data.len() < 24 {
        return Err("PCAP header is too short".into());
    }
    let magic = &data[0..4];
    let le = match magic {
        [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1] => true,
        [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d] => false,
        _ => return Err("Unsupported PCAP magic number".into()),
    };
    let linktype = read_u32(data, 20, le).ok_or("Invalid PCAP link type")?;
    let mut off = 24usize;
    let mut stopped = false;
    while off + 16 <= data.len() {
        let incl = read_u32(data, off + 8, le).ok_or("Invalid PCAP packet header")? as usize;
        off += 16;
        let remaining = data.len().saturating_sub(off);
        if incl > remaining {
            let parsed = stats.packets;
            stats.warnings.push(format!(
                "Stopped after {} complete packet(s): trailing/incomplete packet record reports {} captured bytes, but only {} remain.",
                parsed, incl, remaining
            ));
            stopped = true;
            break;
        }
        parse_packet(&data[off..off + incl], linktype, stats);
        off += incl;
    }
    if !stopped && off < data.len() {
        stats.warnings.push(format!(
            "Ignored {} trailing byte(s) after the last complete packet record.",
            data.len() - off
        ));
    }
    Ok(())
}

fn parse_pcapng(data: &[u8], stats: &mut Stats) -> Result<(), String> {
    let mut off = 0usize;
    let mut linktypes: HashMap<u32, u16> = HashMap::new();
    let mut little_endian = true;
    let mut stopped = false;
    while off + 12 <= data.len() {
        let is_section_header = data[off..off + 4] == [0x0a, 0x0d, 0x0d, 0x0a];
        if is_section_header {
            if off + 12 > data.len() {
                break;
            }
            let bom_le =
                u32::from_le_bytes([data[off + 8], data[off + 9], data[off + 10], data[off + 11]]);
            let bom_be =
                u32::from_be_bytes([data[off + 8], data[off + 9], data[off + 10], data[off + 11]]);
            if bom_le == 0x1a2b_3c4d {
                little_endian = true;
            } else if bom_be == 0x1a2b_3c4d {
                little_endian = false;
            } else {
                return Err("Invalid PCAPNG byte-order magic".into());
            }
            // Interface IDs restart in every section.
            linktypes.clear();
        }
        let block_type = if is_section_header {
            0x0a0d_0d0a
        } else {
            read_u32(data, off, little_endian).ok_or("Invalid PCAPNG block type")?
        };
        let blen =
            read_u32(data, off + 4, little_endian).ok_or("Invalid PCAPNG block length")? as usize;
        if blen < 12 || blen > data.len().saturating_sub(off) {
            stats.warnings.push(format!(
                "Stopped after {} complete packet(s): truncated PCAPNG block at offset {} (declared {} bytes).",
                stats.packets,
                off,
                blen
            ));
            stopped = true;
            break;
        }
        match block_type {
            0x0000_0001 => {
                if blen >= 20 {
                    let linktype = read_u16(data, off + 8, little_endian).unwrap_or(0);
                    let id = linktypes.len() as u32;
                    linktypes.insert(id, linktype);
                }
            }
            0x0000_0006 if blen >= 32 => {
                let available = blen.saturating_sub(32);
                let id = read_u32(data, off + 8, little_endian).unwrap_or(0);
                let cap_len = read_u32(data, off + 20, little_endian).unwrap_or(0) as usize;
                let packet_off = off + 28;
                if cap_len <= available && packet_off.saturating_add(cap_len) <= data.len() {
                    let linktype = linktypes.get(&id).copied().unwrap_or(1) as u32;
                    parse_packet(&data[packet_off..packet_off + cap_len], linktype, stats);
                } else {
                    stats.warnings.push(
                        "Skipped a malformed enhanced packet block with an invalid captured length."
                            .into(),
                    );
                }
            }
            0x0000_0003 if blen >= 16 => {
                let pkt_len = read_u32(data, off + 8, little_endian).unwrap_or(0) as usize;
                let start = off + 12;
                let cap_len = blen.saturating_sub(16).min(pkt_len);
                let linktype = linktypes.get(&0).copied().unwrap_or(1) as u32;
                if cap_len > 0 && start.saturating_add(cap_len) <= data.len() {
                    parse_packet(&data[start..start + cap_len], linktype, stats);
                }
            }
            _ => {}
        }
        off += blen;
    }
    if !stopped && off < data.len() {
        stats.warnings.push(format!(
            "Ignored {} trailing byte(s) after the last complete PCAPNG block.",
            data.len() - off
        ));
    }
    Ok(())
}

fn print_ranked(title: &str, map: &HashMap<String, u64>, limit: usize) {
    println!("{}", title);
    println!("────────────────────────────────────");
    let mut rows: Vec<_> = map.iter().collect();
    rows.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    for (name, count) in rows.into_iter().take(limit) {
        println!("{:<24} {:>8}", name, count);
    }
    println!();
}

fn print_conversations(map: &HashMap<(String, String), u64>, limit: usize) {
    println!("Top Conversations");
    println!("────────────────────────────────────");
    let mut rows: Vec<_> = map
        .iter()
        .map(|((a, b), count)| (format!("{} ↔ {}", a, b), *count))
        .collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    for (pair, count) in rows.into_iter().take(limit) {
        println!("{:<40} {:>8}", pair, count);
    }
    println!();
}

fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn json_string(value: &str) -> String {
    format!("\"{}\"", json_escape(value))
}

fn json_counts(mut entries: Vec<(String, u64)>) -> String {
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let body = entries
        .into_iter()
        .map(|(key, value)| format!("    {}: {}", json_string(&key), value))
        .collect::<Vec<_>>()
        .join(",\n");
    if body.is_empty() {
        "{}".to_string()
    } else {
        format!("{{\n{}\n  }}", body)
    }
}

fn stats_to_json(path: &str, stats: &Stats) -> String {
    let protocols = json_counts(
        stats
            .protocols
            .iter()
            .map(|(key, value)| (key.clone(), *value))
            .collect(),
    );
    let talkers = json_counts(
        stats
            .talkers
            .iter()
            .map(|(key, value)| (key.clone(), *value))
            .collect(),
    );
    let conversations = json_counts(
        stats
            .conversations
            .iter()
            .map(|((a, b), value)| (format!("{} <-> {}", a, b), *value))
            .collect(),
    );
    let warning_rows = stats
        .warnings
        .iter()
        .map(|warning| format!("    {}", json_string(warning)))
        .collect::<Vec<_>>()
        .join(",\n");
    let warnings = if warning_rows.is_empty() {
        "[]".to_string()
    } else {
        format!("[\n{}\n  ]", warning_rows)
    };
    format!(
        concat!(
            "{{\n",
            "  \"tool\": \"SPECTRA\",\n",
            "  \"version\": \"{}\",\n",
            "  \"file\": {},\n",
            "  \"packets\": {},\n",
            "  \"ipv4\": {},\n",
            "  \"ipv6\": {},\n",
            "  \"tcp\": {},\n",
            "  \"udp\": {},\n",
            "  \"other\": {},\n",
            "  \"protocols\": {},\n",
            "  \"top_talkers\": {},\n",
            "  \"conversations\": {},\n",
            "  \"warnings\": {}\n",
            "}}"
        ),
        VERSION,
        json_string(path),
        stats.packets,
        stats.ipv4,
        stats.ipv6,
        stats.tcp,
        stats.udp,
        stats.other,
        protocols,
        talkers,
        conversations,
        warnings
    )
}

fn main() {
    let mut path: Option<String> = None;
    let mut json = false;
    for arg in env::args().skip(1) {
        match arg.as_str() {
            "-h" | "--help" => {
                usage();
                return;
            }
            "-V" | "--version" => {
                println!("spectra {}", VERSION);
                return;
            }
            "--json" => json = true,
            value if value.starts_with('-') => {
                eprintln!("Error: unknown option '{}'", value);
                usage();
                process::exit(2);
            }
            value => {
                if path.is_some() {
                    eprintln!("Error: only one capture file can be analyzed at a time");
                    process::exit(2);
                }
                path = Some(value.to_string());
            }
        }
    }
    let Some(path) = path else {
        usage();
        process::exit(2);
    };

    let data = match fs::read(&path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Error: cannot read '{}': {}", path, e);
            process::exit(1);
        }
    };

    let mut stats = Stats::default();
    let result = if data.get(0..4) == Some(&[0x0a, 0x0d, 0x0d, 0x0a]) {
        parse_pcapng(&data, &mut stats)
    } else {
        parse_pcap(&data, &mut stats)
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        process::exit(1);
    }

    if json {
        println!("{}", stats_to_json(&path, &stats));
        return;
    }

    println!("SPECTRA");
    println!("====================================");
    println!("File       : {}", path);
    println!();
    println!("Packets    : {}", stats.packets);
    println!("IPv4       : {}", stats.ipv4);
    println!("IPv6       : {}", stats.ipv6);
    println!("TCP        : {}", stats.tcp);
    println!("UDP        : {}", stats.udp);
    println!("Other      : {}", stats.other);
    println!();
    print_ranked("Top Protocols", &stats.protocols, LIST_LIMIT);
    print_ranked("Top Talkers", &stats.talkers, LIST_LIMIT);
    print_conversations(&stats.conversations, LIST_LIMIT);

    if !stats.warnings.is_empty() {
        println!("Warnings");
        println!("────────────────────────────────────");
        for warning in &stats.warnings {
            println!("[!] {}", warning);
        }
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ethernet(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&ethertype.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    fn ipv4_tcp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&40u16.to_be_bytes());
        ip[8] = 64;
        ip[9] = 6;
        ip[12..16].copy_from_slice(&src);
        ip[16..20].copy_from_slice(&dst);
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&sport.to_be_bytes());
        tcp[2..4].copy_from_slice(&dport.to_be_bytes());
        tcp[12] = 0x50;
        ip.extend_from_slice(&tcp);
        ip
    }

    fn pcap(linktype: u32, packets: &[&[u8]]) -> Vec<u8> {
        let mut out = vec![0xd4, 0xc3, 0xb2, 0xa1];
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(&0i32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&65535u32.to_le_bytes());
        out.extend_from_slice(&linktype.to_le_bytes());
        for (index, packet) in packets.iter().enumerate() {
            out.extend_from_slice(&(index as u32).to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&(packet.len() as u32).to_le_bytes());
            out.extend_from_slice(&(packet.len() as u32).to_le_bytes());
            out.extend_from_slice(packet);
        }
        out
    }

    fn pcapng_block(block_type: u32, body: &[u8], little_endian: bool) -> Vec<u8> {
        let mut padded = body.to_vec();
        while padded.len() & 3 != 0 {
            padded.push(0);
        }
        let total = 12 + padded.len();
        let mut out = Vec::new();
        let put_u32 = |out: &mut Vec<u8>, value: u32| {
            if little_endian {
                out.extend_from_slice(&value.to_le_bytes());
            } else {
                out.extend_from_slice(&value.to_be_bytes());
            }
        };
        put_u32(&mut out, block_type);
        put_u32(&mut out, total as u32);
        out.extend_from_slice(&padded);
        put_u32(&mut out, total as u32);
        out
    }

    fn section_header(little_endian: bool) -> Vec<u8> {
        let mut body = Vec::new();
        if little_endian {
            body.extend_from_slice(&0x1a2b_3c4du32.to_le_bytes());
            body.extend_from_slice(&1u16.to_le_bytes());
            body.extend_from_slice(&0u16.to_le_bytes());
            body.extend_from_slice(&(-1i64).to_le_bytes());
        } else {
            body.extend_from_slice(&0x1a2b_3c4du32.to_be_bytes());
            body.extend_from_slice(&1u16.to_be_bytes());
            body.extend_from_slice(&0u16.to_be_bytes());
            body.extend_from_slice(&(-1i64).to_be_bytes());
        }
        pcapng_block(0x0a0d_0d0a, &body, little_endian)
    }

    fn interface_description(linktype: u16, little_endian: bool) -> Vec<u8> {
        let mut body = Vec::new();
        if little_endian {
            body.extend_from_slice(&linktype.to_le_bytes());
            body.extend_from_slice(&0u16.to_le_bytes());
            body.extend_from_slice(&65535u32.to_le_bytes());
        } else {
            body.extend_from_slice(&linktype.to_be_bytes());
            body.extend_from_slice(&0u16.to_be_bytes());
            body.extend_from_slice(&65535u32.to_be_bytes());
        }
        pcapng_block(0x0000_0001, &body, little_endian)
    }

    fn enhanced_packet(packet: &[u8], little_endian: bool) -> Vec<u8> {
        let mut body = Vec::new();
        let put_u32 = |body: &mut Vec<u8>, value: u32| {
            if little_endian {
                body.extend_from_slice(&value.to_le_bytes());
            } else {
                body.extend_from_slice(&value.to_be_bytes());
            }
        };
        put_u32(&mut body, 0);
        put_u32(&mut body, 0);
        put_u32(&mut body, 0);
        put_u32(&mut body, packet.len() as u32);
        put_u32(&mut body, packet.len() as u32);
        body.extend_from_slice(packet);
        pcapng_block(0x0000_0006, &body, little_endian)
    }

    #[test]
    fn parses_ipv4_tcp_and_bidirectional_conversations() {
        let a = ethernet(0x0800, &ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 40000, 80));
        let b = ethernet(0x0800, &ipv4_tcp([10, 0, 0, 2], [10, 0, 0, 1], 80, 40000));
        let data = pcap(1, &[&a, &b]);
        let mut stats = Stats::default();
        parse_pcap(&data, &mut stats).unwrap();

        assert_eq!(stats.packets, 2);
        assert_eq!(stats.ipv4, 2);
        assert_eq!(stats.tcp, 2);
        assert_eq!(stats.protocols.get("HTTP"), Some(&2));
        assert_eq!(stats.conversations.len(), 1);
        assert_eq!(
            stats
                .conversations
                .get(&("10.0.0.1".to_string(), "10.0.0.2".to_string())),
            Some(&2)
        );
    }

    #[test]
    fn parses_vlan_tagged_frames() {
        let ip = ipv4_tcp([192, 0, 2, 10], [192, 0, 2, 20], 53000, 3306);
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&0x8100u16.to_be_bytes());
        frame.extend_from_slice(&42u16.to_be_bytes());
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        frame.extend_from_slice(&ip);
        let data = pcap(1, &[&frame]);
        let mut stats = Stats::default();
        parse_pcap(&data, &mut stats).unwrap();

        assert_eq!(stats.ipv4, 1);
        assert_eq!(stats.tcp, 1);
        assert_eq!(stats.protocols.get("MySQL"), Some(&1));
    }

    #[test]
    fn parses_ipv6_extension_headers_and_ports() {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&16u16.to_be_bytes());
        packet[6] = 0;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet[24..40].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        // Hop-by-hop header: next header 17 (UDP), length 0 (= 8 bytes).
        packet.extend_from_slice(&[17, 0, 0, 0, 0, 0, 0, 0]);
        packet.extend_from_slice(&53u16.to_be_bytes());
        packet.extend_from_slice(&5353u16.to_be_bytes());
        packet.extend_from_slice(&[0u8; 4]);
        let frame = ethernet(0x86dd, &packet);
        let data = pcap(1, &[&frame]);
        let mut stats = Stats::default();
        parse_pcap(&data, &mut stats).unwrap();

        assert_eq!(stats.ipv6, 1);
        assert_eq!(stats.udp, 1);
        assert_eq!(stats.protocols.get("DNS"), Some(&1));
    }

    #[test]
    fn parses_linux_cooked_capture() {
        let ip = ipv4_tcp([172, 16, 0, 1], [172, 16, 0, 2], 50000, 443);
        let mut packet = vec![0u8; 16];
        packet[14..16].copy_from_slice(&0x0800u16.to_be_bytes());
        packet.extend_from_slice(&ip);
        let data = pcap(113, &[&packet]);
        let mut stats = Stats::default();
        parse_pcap(&data, &mut stats).unwrap();

        assert_eq!(stats.ipv4, 1);
        assert_eq!(stats.protocols.get("TLS"), Some(&1));
    }

    #[test]
    fn pcapng_spb_uses_interface_linktype() {
        let raw = ipv4_tcp([10, 10, 0, 1], [10, 10, 0, 2], 1234, 22);
        let mut spb_body = Vec::new();
        spb_body.extend_from_slice(&(raw.len() as u32).to_le_bytes());
        spb_body.extend_from_slice(&raw);
        let mut data = section_header(true);
        data.extend_from_slice(&interface_description(101, true));
        data.extend_from_slice(&pcapng_block(0x0000_0003, &spb_body, true));
        let mut stats = Stats::default();
        parse_pcapng(&data, &mut stats).unwrap();

        assert_eq!(stats.packets, 1);
        assert_eq!(stats.ipv4, 1);
        assert_eq!(stats.protocols.get("SSH"), Some(&1));
    }

    #[test]
    fn parses_big_endian_pcapng() {
        let frame = ethernet(0x0800, &ipv4_tcp([10, 1, 0, 1], [10, 1, 0, 2], 5000, 5432));
        let mut data = section_header(false);
        data.extend_from_slice(&interface_description(1, false));
        data.extend_from_slice(&enhanced_packet(&frame, false));
        let mut stats = Stats::default();
        parse_pcapng(&data, &mut stats).unwrap();

        assert_eq!(stats.ipv4, 1);
        assert_eq!(stats.protocols.get("PostgreSQL"), Some(&1));
    }

    #[test]
    fn truncated_pcapng_block_is_a_warning() {
        let mut data = section_header(true);
        data.extend_from_slice(&[0x06, 0x00, 0x00, 0x00]);
        data.extend_from_slice(&200u32.to_le_bytes());
        data.extend_from_slice(&[0u8; 4]);
        let mut stats = Stats::default();
        parse_pcapng(&data, &mut stats).unwrap();

        assert_eq!(stats.packets, 0);
        assert_eq!(stats.warnings.len(), 1);
        assert!(stats.warnings[0].contains("truncated PCAPNG block"));
    }

    #[test]
    fn json_output_escapes_strings() {
        let mut stats = Stats::default();
        stats.warnings.push("quote \" and \\ and \n newline".into());
        stats.record_talker("10.0.0.1");
        let json = stats_to_json("capture\"1.pcap", &stats);
        assert!(json.contains("\"file\": \"capture\\\"1.pcap\""));
        assert!(json.contains("quote \\\" and \\\\ and \\n newline"));
        assert!(json.contains("\"10.0.0.1\": 1"));
        assert!(json.starts_with("{\n  \"tool\": \"SPECTRA\""));
    }
}
