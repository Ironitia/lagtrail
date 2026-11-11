//! lagtrail — traceroute visuel continu (ping + latence par saut dans le temps).
//!
//! Réimplémentation originale et indépendante d'un outil de diagnostic réseau :
//! on sonde le chemin vers une cible par TTL croissant et on trace l'évolution
//! de la latence et des pertes, saut par saut. GUI par défaut (egui/eframe).
//!
//! Usage :
//!   lagtrail [cible]            lance l'interface graphique (cible pré-remplie)
//!   lagtrail --selftest <cible> trace headless dans le terminal (diagnostic)
//!   lagtrail --help
//!
//! Note : l'envoi/réception ICMP brut requiert des privilèges.
//!   Linux :  sudo setcap cap_net_raw+ep <binaire>   (ou lancer avec sudo)
//!   Windows: exécuter en administrateur

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod config;
mod diagnosis;
mod engine;
mod icmp;
mod stats;

use eframe::egui;
use std::time::{Duration, Instant};

fn print_help() {
    println!(
        "lagtrail — traceroute visuel continu\n\n\
         USAGE :\n\
         \x20 lagtrail [cible ...]          interface graphique ; chaque cible démarre\n\
         \x20                              dans son onglet (« demo » = sans privilèges)\n\
         \x20 lagtrail --selftest <cible>   trace dans le terminal (diagnostic)\n\
         \x20 lagtrail --report <cible> [icmp|udp|tcp] [port] [--rounds N] [--interval S] [-6]\n\
         \x20                              mesure N tours (défaut 20) sans interface, affiche\n\
         \x20                              tableau + diagnostic ; code de sortie 0 = sain,\n\
         \x20                              1 = attention, 2 = critique, 3 = erreur\n\
         \x20 lagtrail --help               cette aide\n\n\
         PRIVILÈGES : socket ICMP brut requis.\n\
         \x20 Linux  : sudo setcap cap_net_raw+ep <binaire>  (ou lancer avec sudo)\n\
         \x20 Windows: exécuter en administrateur"
    );
}

fn main() -> eframe::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return Ok(());
    }

    if let Some(pos) = args.iter().position(|a| a == "--report") {
        std::process::exit(run_report(&args[pos + 1..]));
    }

    if let Some(pos) = args.iter().position(|a| a == "--selftest") {
        let target = args
            .get(pos + 1)
            .cloned()
            .unwrap_or_else(|| "1.1.1.1".to_string());
        let proto = match args.get(pos + 2).map(|s| s.to_ascii_lowercase()).as_deref() {
            Some("udp") => engine::ProbeProtocol::Udp,
            Some("tcp") => engine::ProbeProtocol::Tcp,
            _ => engine::ProbeProtocol::Icmp,
        };
        let port = args.get(pos + 3).and_then(|s| s.parse().ok()).unwrap_or(443);
        run_selftest(&target, proto, port);
        return Ok(());
    }

    let targets: Vec<String> = args[1..]
        .iter()
        .filter(|a| !a.starts_with('-'))
        .cloned()
        .collect();

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1040.0, 760.0])
            .with_min_inner_size([680.0, 420.0])
            .with_title("lagtrail — traceroute visuel"),
        ..Default::default()
    };

    eframe::run_native(
        "lagtrail",
        native_options,
        Box::new(move |cc| Ok(Box::new(app::App::new(&cc.egui_ctx, targets)))),
    )
}

/// Mode diagnostic sans interface : quelques tours affichés dans le terminal.
fn run_selftest(target: &str, protocol: engine::ProbeProtocol, port: u16) {
    println!("lagtrail — selftest {} → {target}", protocol.label());
    let addr = match engine::resolve_ip(target, false) {
        Ok(a) => {
            println!("résolu : {a}");
            a
        }
        Err(e) => {
            eprintln!("résolution : {e}");
            return;
        }
    };
    let mut prober = match engine::Prober::new(protocol, addr, port) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("socket : {e}");
            eprintln!("(astuce : sudo setcap cap_net_raw+ep <binaire>, ou lancer avec sudo)");
            return;
        }
    };
    let payload = engine::make_payload();
    let mut final_ttl: Option<u8> = None;

    for round in 1..=5u8 {
        let start = Instant::now();
        let probe_max = final_ttl.unwrap_or(30);
        let deadline = start + Duration::from_millis(1500);
        match prober.round(round, probe_max, deadline, &payload) {
            Ok(o) => {
                if let Some(t) = o.reached_ttl {
                    final_ttl = Some(final_ttl.map_or(t, |p| p.min(t)));
                }
                println!("--- tour {round} (saut final : {final_ttl:?}) ---");
                for s in &o.samples {
                    let a = s.addr.map(|a| a.to_string()).unwrap_or_else(|| "*".into());
                    let r = s
                        .rtt_ms
                        .map(|r| format!("{r:7.2} ms"))
                        .unwrap_or_else(|| "   timeout".into());
                    println!("{:2}  {:<24}  {}", s.ttl, a, r);
                }
            }
            Err(e) => {
                eprintln!("tour {round} : {e}");
                break;
            }
        }
        let el = start.elapsed();
        if el < Duration::from_secs(1) {
            std::thread::sleep(Duration::from_secs(1) - el);
        }
    }
}

/// Mode rapport sans interface : mesure N tours via le moteur, affiche le
/// rapport texte et renvoie un code de sortie exploitable par un script
/// (0 sain, 1 attention, 2 critique, 3 erreur).
fn run_report(args: &[String]) -> i32 {
    use std::collections::HashMap;
    use std::sync::mpsc;

    let flag_value = |name: &str| {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
    };
    let rounds: u64 = flag_value("--rounds").and_then(|v| v.parse().ok()).unwrap_or(20).max(1);
    let interval_secs: f32 = flag_value("--interval")
        .and_then(|v| v.parse().ok())
        .unwrap_or(1.0f32)
        .clamp(0.2, 3600.0);
    let prefer_v6 = args.iter().any(|a| a == "-6");

    // Arguments positionnels : tout ce qui n'est ni un drapeau ni sa valeur.
    let mut positional = Vec::new();
    let mut skip = false;
    for a in args {
        if skip {
            skip = false;
        } else if a == "--rounds" || a == "--interval" {
            skip = true;
        } else if !a.starts_with('-') {
            positional.push(a.as_str());
        }
    }
    let Some(target) = positional.first().map(|s| s.to_string()) else {
        eprintln!("usage : lagtrail --report <cible> [icmp|udp|tcp] [port] [--rounds N] [--interval S] [-6]");
        return 3;
    };
    let protocol = match positional.get(1).map(|s| s.to_ascii_lowercase()).as_deref() {
        Some("udp") => engine::ProbeProtocol::Udp,
        Some("tcp") => engine::ProbeProtocol::Tcp,
        _ => engine::ProbeProtocol::Icmp,
    };
    let port: u16 = positional.get(2).and_then(|s| s.parse().ok()).unwrap_or(443);

    let (cmd_tx, cmd_rx) = mpsc::channel();
    let (msg_tx, msg_rx) = mpsc::channel();
    engine::spawn_engine(cmd_rx, msg_tx, || {});
    let interval = Duration::from_secs_f32(interval_secs);
    let _ = cmd_tx.send(engine::EngineCmd::Start {
        target: target.clone(),
        interval,
        max_hops: 30,
        protocol,
        port,
        prefer_v6,
    });

    let mut hops: Vec<stats::HopView> = Vec::new();
    let mut names = HashMap::new();
    let mut final_ttl = None;
    let mut resolved = None;
    let mut done = 0u64;
    let start = Instant::now();
    let patience = interval + Duration::from_secs(15);

    while done < rounds {
        match msg_rx.recv_timeout(patience) {
            Ok(engine::EngineMsg::Resolved { addr, .. }) => resolved = Some(addr),
            Ok(engine::EngineMsg::Round { final_ttl: ft, samples }) => {
                final_ttl = ft;
                stats::apply_round(&mut hops, &names, start.elapsed().as_secs_f64(), ft, &samples);
                done += 1;
                eprint!("\rtour {done}/{rounds}");
            }
            Ok(engine::EngineMsg::HopName { addr, name }) => {
                stats::apply_name(&mut hops, &mut names, addr, name);
            }
            Ok(engine::EngineMsg::Error(e)) => {
                eprintln!("\n{e}");
                return 3;
            }
            Ok(_) => {}
            Err(_) => {
                eprintln!("\nle moteur ne répond plus");
                return 3;
            }
        }
    }
    eprintln!();
    let _ = cmd_tx.send(engine::EngineCmd::Stop);
    // Laisse une courte chance aux derniers noms DNS d'arriver.
    let grace = Instant::now() + Duration::from_millis(400);
    while let Ok(msg) = msg_rx.recv_timeout(grace.saturating_duration_since(Instant::now())) {
        if let engine::EngineMsg::HopName { addr, name } = msg {
            stats::apply_name(&mut hops, &mut names, addr, name);
        }
    }

    let meta = stats::ReportMeta {
        target,
        addr: resolved,
        protocol: protocol.describe(port),
        interval_secs,
        elapsed_secs: start.elapsed().as_secs_f64(),
    };
    let reached = final_ttl.is_some();
    print!("{}", stats::text_report(&meta, &hops, reached));
    match diagnosis::worst(&stats::findings(&hops, reached)) {
        diagnosis::Severity::Critical => 2,
        diagnosis::Severity::Warning => 1,
        _ => 0,
    }
}
