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
mod engine;
mod icmp;

use eframe::egui;
use std::time::{Duration, Instant};

fn print_help() {
    println!(
        "lagtrail — traceroute visuel continu\n\n\
         USAGE :\n\
         \x20 lagtrail [cible]              interface graphique (cible optionnelle)\n\
         \x20 lagtrail --selftest <cible>   trace dans le terminal (diagnostic)\n\
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

    let initial_target = args.get(1).filter(|a| !a.starts_with('-')).cloned();

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([980.0, 660.0])
            .with_min_inner_size([680.0, 420.0])
            .with_title("lagtrail — traceroute visuel"),
        ..Default::default()
    };

    eframe::run_native(
        "lagtrail",
        native_options,
        Box::new(move |cc| Ok(Box::new(app::App::new(&cc.egui_ctx, initial_target)))),
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
