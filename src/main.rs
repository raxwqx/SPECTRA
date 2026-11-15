use std::collections::HashMap;
use std::env;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process;

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
    warnings: Vec<String>,
}

impl Stats {
    fn record_protocol(&mut self, proto: &str) {
        *self.protocols.entry(proto.to_string()).or_insert(0) += 1;
    }

    fn record_talker(&mut self, ip: &str) {
        *self.talkers.entry(ip.to_string()).or_insert(0) += 1;
    }
}

fn usage() {
    println!("SPECTRA - Offline Network Traffic Analyzer");
    println!();
    println!("Usage:");
    println!("  spectra <capture.pcap|capture.pcapng>");
    println!();
    println!("Options:");
    println!("  -h, --help    Show this help message");
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
            (80, _) | (_, 80) => "HTTP",
            (443, _) | (_, 443) => "TLS",
            (22, _) | (_, 22) => "SSH",
            (21, _) | (_, 21) => "FTP",
            (25, _) | (_, 25) => "SMTP",
            (110, _) | (_, 110) => "POP3",
            (143, _) | (_, 143) => "IMAP",
            (3306, _) | (_, 3306) => "MySQL",
            (5432, _) | (_, 5432) => "PostgreSQL",
            _ => "TCP",
        }
    } else if transport == "UDP" {
        match (src, dst) {
            (53, _) | (_, 53) => "DNS",
            (67, _) | (68, _) | (_, 67) | (_, 68) => "DHCP",
            (123, _) | (_, 123) => "NTP",
            (161, _) | (_, 161) => "SNMP",
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

fn parse_ipv4(packet: &[u8], stats: &mut Stats) {
    if packet.len() < 20 || (packet[0] >> 4) != 4 {
        return;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl {
        return;
    }
    stats.ipv4 += 1;
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]).to_string();
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]).to_string();
    stats.record_talker(&src);
    let proto = packet[9];
    let fragment_offset = u16::from_be_bytes([packet[6], packet[7]]) & 0x1fff;
    let payload = &packet[ihl..];
    match proto {
        6 => {
            stats.tcp += 1;
            if fragment_offset == 0 && payload.len() >= 4 {
                let sp = u16::from_be_bytes([payload[0], payload[1]]);
                let dp = u16::from_be_bytes([payload[2], payload[3]]);
                stats.record_protocol(protocol_name(sp, dp, "TCP"));
                let _ = dst;
            } else {
                stats.record_protocol("TCP");
            }
        }
        17 => {
            stats.udp += 1;
            if fragment_offset == 0 && payload.len() >= 4 {
                let sp = u16::from_be_bytes([payload[0], payload[1]]);
                let dp = u16::from_be_bytes([payload[2], payload[3]]);
                stats.record_protocol(protocol_name(sp, dp, "UDP"));
            } else {
                stats.record_protocol("UDP");
            }
        }
        1 => stats.record_protocol("ICMP"),
        _ => {
            stats.other += 1;
            stats.record_protocol("Other");
        }
    }
}

fn parse_ipv6(packet: &[u8], stats: &mut Stats) {
    if packet.len() < 40 || (packet[0] >> 4) != 6 {
        return;
    }
    stats.ipv6 += 1;
    let mut src_oct = [0u8; 16];
    src_oct.copy_from_slice(&packet[8..24]);
    let src = Ipv6Addr::from(src_oct).to_string();
    stats.record_talker(&src);

    let mut next_header = packet[6];
    let mut offset = 40usize;
    let mut non_initial_fragment = false;
    for _ in 0..16 {
        match next_header {
            0 | 43 | 60 | 135 => {
                if packet.len().saturating_sub(offset) < 2 {
                    stats.other += 1;
                    stats.record_protocol("Other");
                    return;
                }
                let length = (usize::from(packet[offset + 1]) + 1) * 8;
                if length > packet.len().saturating_sub(offset) {
                    stats.other += 1;
                    stats.record_protocol("Other");
                    return;
                }
                let following = packet[offset];
                offset += length;
                next_header = following;
                continue;
            }
            44 => {
                if packet.len().saturating_sub(offset) < 8 {
                    stats.other += 1;
                    stats.record_protocol("Other");
                    return;
                }
                let fragment = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
                non_initial_fragment = fragment & 0xfff8 != 0;
                let following = packet[offset];
                offset += 8;
                next_header = following;
                if non_initial_fragment {
                    break;
                }
                continue;
            }
            51 => {
                if packet.len().saturating_sub(offset) < 2 {
                    stats.other += 1;
                    stats.record_protocol("Other");
                    return;
                }
                let length = (usize::from(packet[offset + 1]) + 2) * 4;
                if length > packet.len().saturating_sub(offset) {
                    stats.other += 1;
                    stats.record_protocol("Other");
                    return;
                }
                let following = packet[offset];
                offset += length;
                next_header = following;
                continue;
            }
            _ => break,
        }
    }

    let payload = &packet[offset..];
    match next_header {
        6 => {
            stats.tcp += 1;
            if !non_initial_fragment && payload.len() >= 4 {
                let sp = u16::from_be_bytes([payload[0], payload[1]]);
                let dp = u16::from_be_bytes([payload[2], payload[3]]);
                stats.record_protocol(protocol_name(sp, dp, "TCP"));
            } else {
                stats.record_protocol("TCP");
            }
        }
        17 => {
            stats.udp += 1;
            if !non_initial_fragment && payload.len() >= 4 {
                let sp = u16::from_be_bytes([payload[0], payload[1]]);
                let dp = u16::from_be_bytes([payload[2], payload[3]]);
                stats.record_protocol(protocol_name(sp, dp, "UDP"));
            } else {
                stats.record_protocol("UDP");
            }
        }
        58 => stats.record_protocol("ICMPv6"),
        _ => {
            stats.other += 1;
            stats.record_protocol("Other");
        }
    }
}

fn parse_packet(packet: &[u8], linktype: u32, stats: &mut Stats) {
    stats.packets += 1;
    match linktype {
        1 => {
            if packet.len() < 14 {
                stats.other += 1;
                stats.record_protocol("Other");
                return;
            }
            let ethertype = u16::from_be_bytes([packet[12], packet[13]]);
            match ethertype {
                0x0800 => parse_ipv4(&packet[14..], stats),
                0x86dd => parse_ipv6(&packet[14..], stats),
                _ => {
                    stats.other += 1;
                    stats.record_protocol("Other");
                }
            }
        }
        101 => {
            match packet.first().map(|b| b >> 4) {
                Some(4) => parse_ipv4(packet, stats),
                Some(6) => parse_ipv6(packet, stats),
                _ => {
                    stats.other += 1;
                    stats.record_protocol("Other");
                }
            }
        }
        _ => {
            stats.other += 1;
            stats.record_protocol("Other");
        }
    }
}

fn parse_pcap(data: &[u8], stats: &mut Stats) -> Result<(), String> {
    if data.len() < 24 {
        return Err("PCAP header is too short".into());
    }
    let magic = &data[0..4];
    let (le, nano) = match magic {
        [0xd4, 0xc3, 0xb2, 0xa1] => (true, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (false, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (true, true),
        [0xa1, 0xb2, 0x3c, 0x4d] => (false, true),
        _ => return Err("Unsupported PCAP magic number".into()),
    };
    let _ = nano;
    let linktype = read_u32(data, 20, le).ok_or("Invalid PCAP link type")?;
    let mut off = 24usize;
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
            break;
        }
        parse_packet(&data[off..off + incl], linktype, stats);
        off += incl;
    }
    Ok(())
}

fn parse_pcapng(data: &[u8], stats: &mut Stats) -> Result<(), String> {
    let mut off = 0usize;
    let mut linktypes: HashMap<u32, u16> = HashMap::new();
    let mut little_endian = true;
    while off + 12 <= data.len() {
        let block_type_le = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        let block_type_be = u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        let block_type = if block_type_le == 0x0a0d0d0a || block_type_le == 0x00000001 || block_type_le == 0x00000006 || block_type_le == 0x00000003 { block_type_le } else { block_type_be };
        if block_type == 0x0a0d0d0a && off + 12 <= data.len() {
            let bom = u32::from_le_bytes([data[off + 8], data[off + 9], data[off + 10], data[off + 11]]);
            little_endian = bom == 0x1a2b3c4d;
        }
        let blen = read_u32(data, off + 4, little_endian).ok_or("Invalid PCAPNG block length")? as usize;
        if blen < 12 || blen > data.len().saturating_sub(off) {
            return Err("Truncated PCAPNG block".into());
        }
        match block_type {
            0x00000001 => {
                if blen >= 20 {
                    let linktype = read_u16(data, off + 8, little_endian).unwrap_or(0);
                    let id = linktypes.len() as u32;
                    linktypes.insert(id, linktype);
                }
            }
            0x00000006 => {
                if blen >= 32 {
                    let id = read_u32(data, off + 8, little_endian).unwrap_or(0);
                    let cap_len = read_u32(data, off + 20, little_endian).unwrap_or(0) as usize;
                    let packet_off = off + 28;
                    if cap_len <= data.len().saturating_sub(packet_off) {
                        let linktype = linktypes.get(&id).copied().unwrap_or(1) as u32;
                        parse_packet(&data[packet_off..packet_off + cap_len], linktype, stats);
                    }
                }
            }
            0x00000003 => {
                if blen >= 16 {
                    let pkt_len = read_u32(data, off + 8, little_endian).unwrap_or(0) as usize;
                    let start = off + 12;
                    let cap_len = blen.saturating_sub(16).min(pkt_len);
                    if cap_len > 0 && start + cap_len <= data.len() {
                        parse_packet(&data[start..start + cap_len], 1, stats);
                    }
                }
            }
            _ => {}
        }
        off += blen;
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

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 || matches!(args.get(1).map(String::as_str), Some("-h") | Some("--help")) {
        usage();
        if args.len() != 2 {
            process::exit(if args.len() == 1 { 0 } else { 1 });
        }
        return;
    }

    let path = &args[1];
    let data = match fs::read(path) {
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
    print_ranked("Top Protocols", &stats.protocols, 10);
    print_ranked("Top Talkers", &stats.talkers, 10);

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
    use super::{parse_ipv4, parse_ipv6, Stats};

    #[test]
    fn classifies_tcp_after_ipv6_hop_by_hop_header() {
        let mut packet = vec![0u8; 40 + 8 + 4];
        packet[0] = 0x60;
        packet[6] = 0; // Hop-by-Hop Options
        packet[40] = 6; // TCP follows
        packet[41] = 0; // 8-byte extension header
        packet[48..50].copy_from_slice(&12345u16.to_be_bytes());
        packet[50..52].copy_from_slice(&443u16.to_be_bytes());

        let mut stats = Stats::default();
        parse_ipv6(&packet, &mut stats);

        assert_eq!(stats.tcp, 1);
        assert_eq!(stats.protocols.get("TLS"), Some(&1));
    }

    #[test]
    fn does_not_classify_ports_in_non_initial_ipv4_fragment() {
        let mut packet = vec![0u8; 24];
        packet[0] = 0x45;
        packet[6..8].copy_from_slice(&1u16.to_be_bytes()); // fragment offset is nonzero
        packet[9] = 6; // TCP
        packet[20..22].copy_from_slice(&12345u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443u16.to_be_bytes());

        let mut stats = Stats::default();
        parse_ipv4(&packet, &mut stats);

        assert_eq!(stats.tcp, 1);
        assert_eq!(stats.protocols.get("TCP"), Some(&1));
        assert!(!stats.protocols.contains_key("TLS"));
    }

    #[test]
    fn non_initial_ipv6_fragment_does_not_infer_tcp_ports() {
        let mut packet = vec![0u8; 40 + 8 + 4];
        packet[0] = 0x60;
        packet[6] = 44; // Fragment header
        packet[40] = 6; // TCP follows
        packet[42..44].copy_from_slice(&8u16.to_be_bytes()); // nonzero fragment offset
        packet[48..50].copy_from_slice(&12345u16.to_be_bytes());
        packet[50..52].copy_from_slice(&443u16.to_be_bytes());

        let mut stats = Stats::default();
        parse_ipv6(&packet, &mut stats);

        assert_eq!(stats.tcp, 1);
        assert_eq!(stats.protocols.get("TCP"), Some(&1));
        assert!(!stats.protocols.contains_key("TLS"));
    }
}
