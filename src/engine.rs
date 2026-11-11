//! Moteur de sonde : traceroute continu par TTL croissant.
//!
//! Supporte trois protocoles et les deux familles d'adresses :
//!   - **ICMP / ICMPv6** : requête Echo fabriquée à la main, émise sur le socket
//!     raw ; appariement par (ident, seq).
//!   - **UDP** : datagrammes émis par le noyau (socket DGRAM) vers un port
//!     destination qui encode la sonde ; le noyau calcule tout. Les erreurs
//!     ICMP (Time Exceeded / Port Unreachable) citent l'en-tête UDP : on
//!     apparie par le port destination.
//!   - **TCP** : `connect()` non-bloquant (SYN émis par le noyau) ; les sauts
//!     intermédiaires arrivent via les erreurs ICMP (appariées par le port
//!     source), la cible est détectée quand la connexion aboutit ou est refusée.
//!
//! La réception des erreurs ICMP se fait toujours sur un socket raw ICMP(v6)
//! (privilèges requis). Aucun checksum transport n'est calculé ici.

use std::collections::{HashMap, HashSet};
use std::io;
use std::mem::MaybeUninit;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::time::{Duration, Instant};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::icmp::{self, ErrKind, Inner, Matched};

/// Protocole de sonde.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProbeProtocol {
    #[default]
    Icmp,
    Udp,
    Tcp,
}

impl ProbeProtocol {
    pub fn label(self) -> &'static str {
        match self {
            ProbeProtocol::Icmp => "ICMP",
            ProbeProtocol::Udp => "UDP",
            ProbeProtocol::Tcp => "TCP",
        }
    }
    /// Un port de destination est-il pertinent (UDP/TCP) ?
    /// Libellé complet, port compris s'il a un sens (« TCP port 443 »).
    pub fn describe(self, port: u16) -> String {
        if self.uses_port() {
            format!("{} port {port}", self.label())
        } else {
            self.label().to_string()
        }
    }

    pub fn uses_port(self) -> bool {
        matches!(self, ProbeProtocol::Udp | ProbeProtocol::Tcp)
    }
}

/// Un échantillon pour un saut lors d'un tour.
#[derive(Debug, Clone)]
pub struct HopSample {
    pub ttl: u8,
    pub addr: Option<IpAddr>,
    pub rtt_ms: Option<f64>,
}

/// Résultat d'un tour complet (un passage TTL 1..=probe_max).
pub struct RoundOutcome {
    pub samples: Vec<HopSample>,
    /// TTL auquel la cible a répondu (= longueur du chemin), si atteinte.
    pub reached_ttl: Option<u8>,
}

/// Commandes envoyées par l'IHM au moteur.
pub enum EngineCmd {
    Start {
        target: String,
        interval: Duration,
        max_hops: u8,
        protocol: ProbeProtocol,
        port: u16,
        prefer_v6: bool,
    },
    Stop,
}

/// Messages du moteur vers l'IHM.
pub enum EngineMsg {
    Resolved { target: String, addr: IpAddr },
    Started,
    Round {
        final_ttl: Option<u8>,
        samples: Vec<HopSample>,
    },
    /// Nom (DNS inverse) d'une adresse rencontrée sur le chemin.
    HopName { addr: IpAddr, name: String },
    Error(String),
    Stopped,
}

/// Résout un nom d'hôte en IP (v4 ou v6 selon préférence et disponibilité).
pub fn resolve_ip(host: &str, prefer_v6: bool) -> io::Result<IpAddr> {
    let host = host.trim();
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }
    let addrs: Vec<SocketAddr> = format!("{host}:0").to_socket_addrs()?.collect();
    let v6 = addrs.iter().find_map(|a| match a {
        SocketAddr::V6(x) => Some(IpAddr::V6(*x.ip())),
        _ => None,
    });
    let v4 = addrs.iter().find_map(|a| match a {
        SocketAddr::V4(x) => Some(IpAddr::V4(*x.ip())),
        _ => None,
    });
    let chosen = if prefer_v6 { v6.or(v4) } else { v4.or(v6) };
    chosen.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("aucune adresse IP trouvée pour « {host} »"),
        )
    })
}

fn dur_ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

fn sockaddr(ip: IpAddr, port: u16) -> SockAddr {
    SockAddr::from(SocketAddr::new(ip, port))
}

fn sockaddr_ip(sa: &SockAddr) -> Option<IpAddr> {
    if let Some(v4) = sa.as_socket_ipv4() {
        Some(IpAddr::V4(*v4.ip()))
    } else {
        sa.as_socket_ipv6().map(|v6| IpAddr::V6(*v6.ip()))
    }
}

fn sockaddr_port(sa: &SockAddr) -> Option<u16> {
    if let Some(v4) = sa.as_socket_ipv4() {
        Some(v4.port())
    } else {
        sa.as_socket_ipv6().map(|v6| v6.port())
    }
}

fn set_ttl_hops(sock: &Socket, is_v6: bool, ttl: u8) -> io::Result<()> {
    if is_v6 {
        sock.set_unicast_hops_v6(ttl as u32)
    } else {
        sock.set_ttl(ttl as u32)
    }
}

// SÛRETÉ : `s` correspond aux octets effectivement reçus, donc initialisés.
unsafe fn assume_init(s: &[MaybeUninit<u8>]) -> &[u8] {
    unsafe { &*(s as *const [MaybeUninit<u8>] as *const [u8]) }
}

enum TcpState {
    Reached, // SYN-ACK (connexion ouverte) ou RST (port fermé) : l'hôte a répondu
    Failed,  // injoignable / autre erreur
    Pending,
}

/// Déduit l'état d'un `connect()` TCP non-bloquant, de façon portable.
fn tcp_state(s: &Socket) -> TcpState {
    if s.peer_addr().is_ok() {
        return TcpState::Reached;
    }
    match s.take_error() {
        Ok(Some(e)) if e.kind() == io::ErrorKind::ConnectionRefused => TcpState::Reached,
        Ok(Some(_)) => TcpState::Failed,
        _ => TcpState::Pending,
    }
}

fn bump(reached: &mut Option<u8>, ttl: u8) {
    let v = (*reached).map_or(ttl, |p| p.min(ttl));
    *reached = Some(v);
}

/// Sondeur : détient le socket de réception (et le socket UDP si besoin).
pub struct Prober {
    protocol: ProbeProtocol,
    target: IpAddr,
    port: u16,
    is_v6: bool,
    recv: Socket,
    udp: Option<Socket>,
    ident: u16,
    port_ctr: u16,
}

impl Prober {
    pub fn new(protocol: ProbeProtocol, target: IpAddr, port: u16) -> io::Result<Self> {
        let is_v6 = target.is_ipv6();
        let domain = if is_v6 { Domain::IPV6 } else { Domain::IPV4 };
        let icmp_proto = if is_v6 {
            Protocol::ICMPV6
        } else {
            Protocol::ICMPV4
        };
        let recv = Socket::new(domain, Type::RAW, Some(icmp_proto))?;
        recv.set_read_timeout(Some(Duration::from_millis(100)))?;
        let udp = if protocol == ProbeProtocol::Udp {
            Some(Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?)
        } else {
            None
        };
        Ok(Self {
            protocol,
            target,
            port,
            is_v6,
            recv,
            udp,
            ident: (std::process::id() as u16) ^ 0x7f7f,
            port_ctr: 0,
        })
    }

    /// Apparie une réponse reçue à une sonde en attente et enregistre le RTT.
    fn process(
        &self,
        m: Matched,
        responder: Option<IpAddr>,
        now: Instant,
        sent_at: &mut HashMap<u16, (u8, Instant)>,
        results: &mut HashMap<u8, (Option<IpAddr>, f64)>,
        reached: &mut Option<u8>,
    ) {
        match self.protocol {
            ProbeProtocol::Icmp => match m {
                Matched::Echo { ident, seq } if ident == self.ident => {
                    if let Some((ttl, t0)) = sent_at.remove(&seq) {
                        results.insert(ttl, (responder.or(Some(self.target)), dur_ms(now - t0)));
                        bump(reached, ttl);
                    }
                }
                Matched::Error {
                    kind,
                    inner: Inner::Icmp { ident, seq },
                } if ident == self.ident => {
                    if let Some((ttl, t0)) = sent_at.remove(&seq) {
                        results.entry(ttl).or_insert((responder, dur_ms(now - t0)));
                        if kind == ErrKind::Unreachable {
                            bump(reached, ttl);
                        }
                    }
                }
                _ => {}
            },
            ProbeProtocol::Udp => {
                if let Matched::Error {
                    kind,
                    inner: Inner::Udp { dst_port, .. },
                } = m
                {
                    if let Some((ttl, t0)) = sent_at.remove(&dst_port) {
                        results.entry(ttl).or_insert((responder, dur_ms(now - t0)));
                        if kind == ErrKind::Unreachable {
                            bump(reached, ttl);
                        }
                    }
                }
            }
            ProbeProtocol::Tcp => {
                if let Matched::Error {
                    kind,
                    inner: Inner::Tcp { src_port, .. },
                } = m
                {
                    if let Some((ttl, t0)) = sent_at.remove(&src_port) {
                        results.entry(ttl).or_insert((responder, dur_ms(now - t0)));
                        if kind == ErrKind::Unreachable {
                            bump(reached, ttl);
                        }
                    }
                }
            }
        }
    }

    pub fn round(
        &mut self,
        round: u8,
        probe_max: u8,
        deadline: Instant,
        payload: &[u8],
    ) -> io::Result<RoundOutcome> {
        let mut sent_at: HashMap<u16, (u8, Instant)> = HashMap::new();
        let mut tcp: Vec<(u8, Socket, Instant)> = Vec::new();

        // ── Émission ──
        for ttl in 1..=probe_max {
            match self.protocol {
                ProbeProtocol::Icmp => {
                    let seq = icmp::make_seq(round, ttl);
                    let pkt = if self.is_v6 {
                        icmp::build_echo_request_v6(self.ident, seq, payload)
                    } else {
                        icmp::build_echo_request(self.ident, seq, payload)
                    };
                    set_ttl_hops(&self.recv, self.is_v6, ttl)?;
                    let now = Instant::now();
                    self.recv.send_to(&pkt, &sockaddr(self.target, 0))?;
                    sent_at.insert(seq, (ttl, now));
                }
                ProbeProtocol::Udp => {
                    self.port_ctr = self.port_ctr.wrapping_add(1);
                    let dport = 33434u16.wrapping_add(self.port_ctr).max(1);
                    let udp = self.udp.as_ref().expect("socket UDP");
                    set_ttl_hops(udp, self.is_v6, ttl)?;
                    let now = Instant::now();
                    let _ = udp.send_to(payload, &sockaddr(self.target, dport));
                    sent_at.insert(dport, (ttl, now));
                }
                ProbeProtocol::Tcp => {
                    let domain = if self.is_v6 { Domain::IPV6 } else { Domain::IPV4 };
                    let s = match Socket::new(domain, Type::STREAM, Some(Protocol::TCP)) {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    let _ = s.set_nonblocking(true);
                    let _ = set_ttl_hops(&s, self.is_v6, ttl);
                    let now = Instant::now();
                    // connect() non-bloquant : EINPROGRESS attendu.
                    let _ = s.connect(&sockaddr(self.target, self.port));
                    if let Ok(la) = s.local_addr() {
                        if let Some(lp) = sockaddr_port(&la) {
                            sent_at.insert(lp, (ttl, now));
                        }
                    }
                    tcp.push((ttl, s, now));
                }
            }
        }

        // ── Réception / scrutation ──
        let mut results: HashMap<u8, (Option<IpAddr>, f64)> = HashMap::new();
        let mut reached: Option<u8> = None;
        let mut buf = [MaybeUninit::<u8>::uninit(); 1500];

        while Instant::now() < deadline && !(sent_at.is_empty() && tcp.is_empty()) {
            let remaining = deadline.saturating_duration_since(Instant::now());
            // Tant que des connexions TCP sont en attente, on les scrute à
            // chaque passage : l'attente ICMP doit rester très courte, sinon
            // elle s'ajoute au RTT mesuré de la destination (jusqu'à 80 ms).
            let slice = if tcp.is_empty() { 80 } else { 1 };
            let to = remaining
                .min(Duration::from_millis(slice))
                .max(Duration::from_millis(1));
            self.recv.set_read_timeout(Some(to))?;
            match self.recv.recv_from(&mut buf) {
                Ok((n, from)) => {
                    let now = Instant::now();
                    let data = unsafe { assume_init(&buf[..n]) };
                    let responder = sockaddr_ip(&from);
                    let m = if self.is_v6 {
                        icmp::parse_v6(data)
                    } else {
                        icmp::parse_v4(data)
                    };
                    self.process(m, responder, now, &mut sent_at, &mut results, &mut reached);
                }
                Err(ref e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut => {}
                Err(_) => {}
            }

            // Scrutation des connexions TCP en cours.
            if self.protocol == ProbeProtocol::Tcp {
                let mut i = 0;
                while i < tcp.len() {
                    match tcp_state(&tcp[i].1) {
                        TcpState::Reached => {
                            let ttl = tcp[i].0;
                            let t0 = tcp[i].2;
                            results.insert(ttl, (Some(self.target), dur_ms(Instant::now() - t0)));
                            bump(&mut reached, ttl);
                            sent_at.retain(|_, (t, _)| *t != ttl);
                            tcp.remove(i);
                        }
                        TcpState::Failed => {
                            let ttl = tcp[i].0;
                            sent_at.retain(|_, (t, _)| *t != ttl);
                            tcp.remove(i);
                        }
                        TcpState::Pending => i += 1,
                    }
                }
            }
        }

        let samples = (1..=probe_max)
            .map(|ttl| match results.get(&ttl) {
                Some((addr, rtt)) => HopSample {
                    ttl,
                    addr: *addr,
                    rtt_ms: Some(*rtt),
                },
                None => HopSample {
                    ttl,
                    addr: None,
                    rtt_ms: None,
                },
            })
            .collect();

        Ok(RoundOutcome {
            samples,
            reached_ttl: reached,
        })
    }
}

/// Charge utile fixe des sondes (contenu sans importance, taille constante).
pub fn make_payload() -> Vec<u8> {
    let mut p = b"lagtrail".to_vec();
    p.resize(24, 0);
    p
}

/// Message d'erreur clair quand l'ouverture du socket échoue.
pub fn socket_error_message(e: &io::Error) -> String {
    if e.kind() == io::ErrorKind::PermissionDenied {
        if cfg!(target_os = "windows") {
            return "Permission refusée : lance lagtrail en tant qu'administrateur \
                    (un socket ICMP brut est requis)."
                .to_string();
        }
        return "Permission refusée : les sockets ICMP bruts demandent des privilèges.\n\
                Lance avec « sudo lagtrail », ou autorise le binaire une fois \
                pour toutes :  sudo setcap cap_net_raw+ep <chemin-du-binaire>"
            .to_string();
    }
    format!("Ouverture du socket impossible : {e}")
}

/// Lance la résolution inverse (PTR) d'un saut dans un thread détaché.
fn spawn_reverse_dns(ip: IpAddr, tx: Sender<EngineMsg>) {
    std::thread::spawn(move || {
        if let Ok(name) = dns_lookup::lookup_addr(&ip) {
            if name != ip.to_string() {
                let _ = tx.send(EngineMsg::HopName { addr: ip, name });
            }
        }
    });
}

/// PRNG xorshift64 (suffisant pour la démo, pas de dépendance).
fn xorshift(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

/// Trace synthétique : chemin fixe de 8 sauts avec gigue et pertes aléatoires
/// (dont un saut « bruyant »). Aucun réseau ni privilège requis.
fn run_demo(
    cmd_rx: &Receiver<EngineCmd>,
    msg_tx: &Sender<EngineMsg>,
    repaint: &dyn Fn(),
    interval: Duration,
) {
    let target_ip = IpAddr::from([203, 0, 113, 50]);
    let _ = msg_tx.send(EngineMsg::Resolved {
        target: "demo".to_string(),
        addr: target_ip,
    });
    repaint();
    let _ = msg_tx.send(EngineMsg::Started);
    repaint();

    let path: [(IpAddr, f64, &str); 8] = [
        (IpAddr::from([192, 168, 1, 1]), 1.0, "box.local"),
        (IpAddr::from([10, 0, 0, 1]), 4.0, ""),
        (IpAddr::from([100, 64, 0, 1]), 9.0, "core1.fai.net"),
        (IpAddr::from([172, 16, 5, 1]), 14.0, ""),
        (IpAddr::from([203, 0, 113, 1]), 22.0, "peer.transit.net"),
        (IpAddr::from([203, 0, 113, 20]), 48.0, ""),
        (IpAddr::from([203, 0, 113, 40]), 55.0, ""),
        (target_ip, 58.0, "demo.cible"),
    ];
    let final_ttl = path.len() as u8;
    // Le saut 4 alterne entre deux routeurs (répartition de charge simulée).
    let alt_hop = 3;
    let alt_ip = IpAddr::from([172, 16, 5, 2]);
    for (ip, _, name) in path.iter() {
        if !name.is_empty() {
            let _ = msg_tx.send(EngineMsg::HopName {
                addr: *ip,
                name: (*name).to_string(),
            });
        }
    }

    let mut rng = 0x9E37_79B9_7F4A_7C15u64
        ^ std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x1234_5678);

    loop {
        match cmd_rx.try_recv() {
            Ok(EngineCmd::Stop) => {
                let _ = msg_tx.send(EngineMsg::Stopped);
                repaint();
                return;
            }
            Err(TryRecvError::Disconnected) => return,
            _ => {}
        }

        let round_start = Instant::now();
        let mut samples = Vec::with_capacity(path.len());
        for (i, (ip, base, _)) in path.iter().enumerate() {
            let (loss_pct, span) = match i {
                5 => (18u64, 30.0),
                7 => (10, 12.0),
                _ => (3, 6.0),
            };
            let rtt = if (xorshift(&mut rng) % 100) < loss_pct {
                None
            } else {
                let jitter = ((xorshift(&mut rng) % 1000) as f64 / 1000.0 - 0.5) * span;
                Some((base + jitter).max(0.3))
            };
            let ip = if i == alt_hop && xorshift(&mut rng) % 3 == 0 {
                alt_ip
            } else {
                *ip
            };
            samples.push(HopSample {
                ttl: (i + 1) as u8,
                addr: Some(ip),
                rtt_ms: rtt,
            });
        }
        let _ = msg_tx.send(EngineMsg::Round {
            final_ttl: Some(final_ttl),
            samples,
        });
        repaint();

        let elapsed = round_start.elapsed();
        if elapsed < interval {
            let mut remaining = interval - elapsed;
            while remaining > Duration::ZERO {
                let chunk = remaining.min(Duration::from_millis(100));
                std::thread::sleep(chunk);
                remaining = remaining.saturating_sub(chunk);
                match cmd_rx.try_recv() {
                    Ok(EngineCmd::Stop) => {
                        let _ = msg_tx.send(EngineMsg::Stopped);
                        repaint();
                        return;
                    }
                    Err(TryRecvError::Disconnected) => return,
                    _ => {}
                }
            }
        }
    }
}

/// Démarre le thread du moteur. `repaint` réveille l'IHM après chaque message.
pub fn spawn_engine(
    cmd_rx: Receiver<EngineCmd>,
    msg_tx: Sender<EngineMsg>,
    repaint: impl Fn() + Send + 'static,
) {
    std::thread::spawn(move || engine_loop(cmd_rx, msg_tx, repaint));
}

fn engine_loop(cmd_rx: Receiver<EngineCmd>, msg_tx: Sender<EngineMsg>, repaint: impl Fn()) {
    'session: loop {
        // --- État « au repos » : on attend un Start (bloquant). ---
        let (target, interval, max_hops, protocol, port, prefer_v6) = loop {
            match cmd_rx.recv() {
                Ok(EngineCmd::Start {
                    target,
                    interval,
                    max_hops,
                    protocol,
                    port,
                    prefer_v6,
                }) => break (target, interval, max_hops, protocol, port, prefer_v6),
                Ok(EngineCmd::Stop) => continue,
                Err(_) => return,
            }
        };

        // --- Mode démonstration (données synthétiques, sans privilèges). ---
        if target.eq_ignore_ascii_case("demo") {
            run_demo(&cmd_rx, &msg_tx, &repaint, interval);
            continue 'session;
        }

        // --- Résolution DNS. ---
        let addr = match resolve_ip(&target, prefer_v6) {
            Ok(a) => a,
            Err(e) => {
                let _ = msg_tx.send(EngineMsg::Error(format!("Résolution impossible : {e}")));
                repaint();
                continue 'session;
            }
        };
        let _ = msg_tx.send(EngineMsg::Resolved {
            target: target.clone(),
            addr,
        });
        repaint();

        // --- Sondeur (ouvre les sockets). ---
        let mut prober = match Prober::new(protocol, addr, port) {
            Ok(p) => p,
            Err(e) => {
                let _ = msg_tx.send(EngineMsg::Error(socket_error_message(&e)));
                repaint();
                continue 'session;
            }
        };

        let per_round = interval
            .min(Duration::from_millis(1500))
            .max(Duration::from_millis(300));
        let payload = make_payload();
        let mut round: u8 = 0;
        let mut final_ttl: Option<u8> = None;
        let mut named: HashSet<IpAddr> = HashSet::new();

        let _ = msg_tx.send(EngineMsg::Started);
        repaint();

        // --- Boucle de tours. ---
        loop {
            match cmd_rx.try_recv() {
                Ok(EngineCmd::Stop) => {
                    let _ = msg_tx.send(EngineMsg::Stopped);
                    repaint();
                    continue 'session;
                }
                Ok(EngineCmd::Start { .. }) => {}
                Err(TryRecvError::Disconnected) => return,
                Err(TryRecvError::Empty) => {}
            }

            round = round.wrapping_add(1);
            let probe_max = final_ttl.unwrap_or(max_hops);
            let round_start = Instant::now();
            let deadline = round_start + per_round;

            match prober.round(round, probe_max, deadline, &payload) {
                Ok(outcome) => {
                    if let Some(t) = outcome.reached_ttl {
                        final_ttl = Some(final_ttl.map_or(t, |p| p.min(t)));
                    }
                    for s in &outcome.samples {
                        if let Some(ip) = s.addr {
                            // Une résolution par adresse : une route qui
                            // alterne ne relance pas de requêtes en boucle.
                            if named.insert(ip) {
                                spawn_reverse_dns(ip, msg_tx.clone());
                            }
                        }
                    }
                    let _ = msg_tx.send(EngineMsg::Round {
                        final_ttl,
                        samples: outcome.samples,
                    });
                    repaint();
                }
                Err(e) => {
                    let _ = msg_tx.send(EngineMsg::Error(format!("Erreur réseau : {e}")));
                    repaint();
                    continue 'session;
                }
            }

            // Pacing : on dort le reste de l'intervalle en restant réactif.
            let elapsed = round_start.elapsed();
            if elapsed < interval {
                let mut remaining = interval - elapsed;
                while remaining > Duration::ZERO {
                    let chunk = remaining.min(Duration::from_millis(100));
                    std::thread::sleep(chunk);
                    remaining = remaining.saturating_sub(chunk);
                    match cmd_rx.try_recv() {
                        Ok(EngineCmd::Stop) => {
                            let _ = msg_tx.send(EngineMsg::Stopped);
                            repaint();
                            continue 'session;
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}
