//! Encodage / décodage ICMPv4 et ICMPv6, + extraction des en-têtes « cités »
//! dans les messages d'erreur ICMP (pour apparier les sondes ICMP/UDP/TCP).
//!
//! Tout est fait à la main pour rester portable sans dépendance de parsing de
//! paquets. On ne fabrique que des requêtes Echo (ICMP) ; UDP et TCP sont émis
//! par le noyau via des sockets ordinaires, donc aucun checksum transport à
//! calculer ici.

// ── ICMPv4 ──
pub const ICMP_ECHO_REQUEST: u8 = 8;
pub const ICMP_ECHO_REPLY: u8 = 0;
pub const ICMP_TIME_EXCEEDED: u8 = 11;
pub const ICMP_DEST_UNREACH: u8 = 3;
// ── ICMPv6 ──
pub const ICMP6_ECHO_REQUEST: u8 = 128;
pub const ICMP6_ECHO_REPLY: u8 = 129;
pub const ICMP6_TIME_EXCEEDED: u8 = 3;
pub const ICMP6_DEST_UNREACH: u8 = 1;
// ── Numéros de protocole IP ──
const PROTO_ICMP: u8 = 1;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMP6: u8 = 58;

/// Somme de contrôle Internet (RFC 1071) sur `data`.
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn build_echo(typ: u8, ident: u16, seq: u16, payload: &[u8], with_checksum: bool) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(8 + payload.len());
    pkt.push(typ);
    pkt.push(0); // code
    pkt.extend_from_slice(&[0, 0]); // checksum (placeholder)
    pkt.extend_from_slice(&ident.to_be_bytes());
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(payload);
    if with_checksum {
        let ck = checksum(&pkt);
        pkt[2..4].copy_from_slice(&ck.to_be_bytes());
    }
    // Pour ICMPv6, le noyau calcule et pose le checksum à l'émission.
    pkt
}

/// Requête Echo ICMPv4 (type 8), checksum calculé.
pub fn build_echo_request(ident: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    build_echo(ICMP_ECHO_REQUEST, ident, seq, payload, true)
}

/// Requête Echo ICMPv6 (type 128) ; checksum laissé à 0 (calculé par le noyau).
pub fn build_echo_request_v6(ident: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    build_echo(ICMP6_ECHO_REQUEST, ident, seq, payload, false)
}

/// Longueur (octets) de l'en-tête IPv4 depuis son 1er octet (IHL).
fn ipv4_header_len(buf: &[u8]) -> Option<usize> {
    let b0 = *buf.first()?;
    if b0 >> 4 != 4 {
        return None;
    }
    let ihl = (b0 & 0x0f) as usize * 4;
    if ihl < 20 || ihl > buf.len() {
        return None;
    }
    Some(ihl)
}

fn be16(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

/// Identifiants extraits de l'en-tête transport « cité » dans une erreur ICMP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inner {
    Icmp { ident: u16, seq: u16 },
    Udp { src_port: u16, dst_port: u16 },
    Tcp { src_port: u16, dst_port: u16 },
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrKind {
    TimeExceeded,
    Unreachable,
}

/// Résultat du décodage d'un datagramme reçu sur le socket raw ICMP(v6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Matched {
    /// Echo Reply : la cible a répondu (mode ICMP) ; nos ident/seq.
    Echo { ident: u16, seq: u16 },
    /// Time Exceeded / Unreachable, citant notre sonde d'origine.
    Error { kind: ErrKind, inner: Inner },
    Other,
}

/// Décode l'en-tête transport cité à partir du numéro de protocole.
fn parse_inner(proto: u8, seg: &[u8]) -> Inner {
    match proto {
        PROTO_ICMP | PROTO_ICMP6 => match (be16(seg, 4), be16(seg, 6)) {
            (Some(ident), Some(seq)) => Inner::Icmp { ident, seq },
            _ => Inner::Unknown,
        },
        PROTO_UDP => match (be16(seg, 0), be16(seg, 2)) {
            (Some(src_port), Some(dst_port)) => Inner::Udp { src_port, dst_port },
            _ => Inner::Unknown,
        },
        PROTO_TCP => match (be16(seg, 0), be16(seg, 2)) {
            (Some(src_port), Some(dst_port)) => Inner::Tcp { src_port, dst_port },
            _ => Inner::Unknown,
        },
        _ => Inner::Unknown,
    }
}

/// Décode un datagramme reçu sur un socket raw ICMPv4 (en-tête IP inclus).
pub fn parse_v4(buf: &[u8]) -> Matched {
    let Some(ihl) = ipv4_header_len(buf) else {
        return Matched::Other;
    };
    let icmp = &buf[ihl..];
    if icmp.len() < 8 {
        return Matched::Other;
    }
    match icmp[0] {
        ICMP_ECHO_REPLY => Matched::Echo {
            ident: u16::from_be_bytes([icmp[4], icmp[5]]),
            seq: u16::from_be_bytes([icmp[6], icmp[7]]),
        },
        ICMP_TIME_EXCEEDED | ICMP_DEST_UNREACH => {
            let kind = if icmp[0] == ICMP_TIME_EXCEEDED {
                ErrKind::TimeExceeded
            } else {
                ErrKind::Unreachable
            };
            // Corps = 4 octets + en-tête IP d'origine + début du datagramme.
            let Some(body) = buf.get(ihl + 8..) else {
                return Matched::Other;
            };
            let Some(inner_ihl) = ipv4_header_len(body) else {
                return Matched::Other;
            };
            let proto = body[9];
            let Some(seg) = body.get(inner_ihl..) else {
                return Matched::Other;
            };
            Matched::Error {
                kind,
                inner: parse_inner(proto, seg),
            }
        }
        _ => Matched::Other,
    }
}

/// Décode un datagramme reçu sur un socket raw ICMPv6 (pas d'en-tête IP).
pub fn parse_v6(buf: &[u8]) -> Matched {
    if buf.len() < 8 {
        return Matched::Other;
    }
    match buf[0] {
        ICMP6_ECHO_REPLY => Matched::Echo {
            ident: u16::from_be_bytes([buf[4], buf[5]]),
            seq: u16::from_be_bytes([buf[6], buf[7]]),
        },
        ICMP6_TIME_EXCEEDED | ICMP6_DEST_UNREACH => {
            let kind = if buf[0] == ICMP6_TIME_EXCEEDED {
                ErrKind::TimeExceeded
            } else {
                ErrKind::Unreachable
            };
            // Corps = 4 octets + en-tête IPv6 d'origine (40 o) + datagramme.
            let Some(body) = buf.get(8..) else {
                return Matched::Other;
            };
            if body.len() < 40 {
                return Matched::Other;
            }
            let next_header = body[6];
            let seg = &body[40..];
            Matched::Error {
                kind,
                inner: parse_inner(next_header, seg),
            }
        }
        _ => Matched::Other,
    }
}

/// Encode `(round, ttl)` dans un numéro de séquence 16 bits.
pub fn make_seq(round: u8, ttl: u8) -> u16 {
    ((round as u16) << 8) | ttl as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_hdr(proto: u8) -> Vec<u8> {
        let mut h = vec![0u8; 20];
        h[0] = 0x45;
        h[9] = proto;
        h
    }

    fn ipv6_hdr(next_header: u8) -> Vec<u8> {
        let mut h = vec![0u8; 40];
        h[0] = 0x60; // version 6
        h[6] = next_header;
        h
    }

    #[test]
    fn checksum_of_valid_packet_is_zero() {
        let pkt = build_echo_request(0xABCD, 0x0102, b"hello world");
        assert_eq!(checksum(&pkt), 0);
    }

    #[test]
    fn v4_echo_reply_roundtrip() {
        let (ident, seq) = (0x1234, make_seq(7, 12));
        let mut pkt = ipv4_hdr(PROTO_ICMP);
        pkt.extend_from_slice(&build_echo_request(ident, seq, b"x"));
        pkt[20] = ICMP_ECHO_REPLY;
        assert_eq!(parse_v4(&pkt), Matched::Echo { ident, seq });
    }

    #[test]
    fn v4_time_exceeded_icmp_inner() {
        let (ident, seq) = (0x7f7f, make_seq(3, 5));
        let mut pkt = ipv4_hdr(PROTO_ICMP);
        pkt.extend_from_slice(&[ICMP_TIME_EXCEEDED, 0, 0, 0, 0, 0, 0, 0]);
        pkt.extend_from_slice(&ipv4_hdr(PROTO_ICMP));
        pkt.extend_from_slice(&build_echo_request(ident, seq, b"orig"));
        assert_eq!(
            parse_v4(&pkt),
            Matched::Error {
                kind: ErrKind::TimeExceeded,
                inner: Inner::Icmp { ident, seq },
            }
        );
    }

    #[test]
    fn v4_time_exceeded_udp_inner() {
        let mut pkt = ipv4_hdr(PROTO_ICMP);
        pkt.extend_from_slice(&[ICMP_TIME_EXCEEDED, 0, 0, 0, 0, 0, 0, 0]);
        pkt.extend_from_slice(&ipv4_hdr(PROTO_UDP));
        // en-tête UDP : src 50000, dst 33450
        pkt.extend_from_slice(&50000u16.to_be_bytes());
        pkt.extend_from_slice(&33450u16.to_be_bytes());
        pkt.extend_from_slice(&[0, 8, 0, 0]);
        match parse_v4(&pkt) {
            Matched::Error { kind: ErrKind::TimeExceeded, inner: Inner::Udp { src_port, dst_port } } => {
                assert_eq!(src_port, 50000);
                assert_eq!(dst_port, 33450);
            }
            other => panic!("attendu Udp, obtenu {other:?}"),
        }
    }

    #[test]
    fn v4_port_unreachable_tcp_inner() {
        let mut pkt = ipv4_hdr(PROTO_ICMP);
        pkt.extend_from_slice(&[ICMP_DEST_UNREACH, 3, 0, 0, 0, 0, 0, 0]);
        pkt.extend_from_slice(&ipv4_hdr(PROTO_TCP));
        pkt.extend_from_slice(&44444u16.to_be_bytes()); // src
        pkt.extend_from_slice(&443u16.to_be_bytes()); // dst
        pkt.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(
            parse_v4(&pkt),
            Matched::Error {
                kind: ErrKind::Unreachable,
                inner: Inner::Tcp { src_port: 44444, dst_port: 443 },
            }
        );
    }

    #[test]
    fn v6_echo_reply_roundtrip() {
        let (ident, seq) = (0xBEEF, make_seq(2, 9));
        let mut pkt = build_echo_request_v6(ident, seq, b"y");
        pkt[0] = ICMP6_ECHO_REPLY;
        assert_eq!(parse_v6(&pkt), Matched::Echo { ident, seq });
    }

    #[test]
    fn v6_time_exceeded_icmp_inner() {
        let (ident, seq) = (0x0303, make_seq(1, 4));
        let mut pkt = vec![ICMP6_TIME_EXCEEDED, 0, 0, 0, 0, 0, 0, 0];
        pkt.extend_from_slice(&ipv6_hdr(PROTO_ICMP6));
        pkt.extend_from_slice(&build_echo_request_v6(ident, seq, b"orig"));
        assert_eq!(
            parse_v6(&pkt),
            Matched::Error {
                kind: ErrKind::TimeExceeded,
                inner: Inner::Icmp { ident, seq },
            }
        );
    }

    #[test]
    fn truncated_is_other() {
        assert_eq!(parse_v4(&[0x45, 0x00]), Matched::Other);
        assert_eq!(parse_v6(&[128, 0]), Matched::Other);
        assert_eq!(parse_v4(&[]), Matched::Other);
    }
}
