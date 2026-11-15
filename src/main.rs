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

mod app;
mod config;
mod diagnosis;
mod engine;
mod html;
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
         \x20 lagtrail --report <cible ...> [icmp|udp|tcp] [port] [--rounds N] [--interval S] [-6]\n\
         \x20                              mesure N tours (défaut 20) sans interface, affiche\n\
         \x20                              tableau + diagnostic ; code de sortie 0 = sain,\n\
         \x20                              1 = attention, 2 = critique, 3 = erreur ;\n\
         \x20                              plusieurs cibles : mesurées en parallèle, un\n\
         \x20                              rapport chacune puis une synthèse ;\n\
         \x20                              --json : sortie JSON pour un script ;\n\
         \x20                              --html FICHIER : rapport HTML avec graphe, à\n\
         \x20                              joindre à un ticket (aussi avec --watch)\n\
         \x20 lagtrail --watch <cible ...> [icmp|udp|tcp] [port] [--interval S] [--rounds N] [--log fichier] [--exec CMD]\n\
         \x20                              surveillance continue dans le terminal : chaque\n\
         \x20                              événement (coupure, pic, route) horodaté en UTC ;\n\
         \x20                              --exec CMD : lance CMD à chaque événement\n\
         \x20                              (variables LAGTRAIL_TARGET, _SEVERITY, _EVENT) ;\n\
         \x20                              Ctrl-C arrête avec un bilan ; --json : une ligne\n\
         \x20                              JSON par événement ; plusieurs cibles possibles\n\
         \x20 lagtrail --help               cette aide\n\
         \x20 lagtrail --version            numéro de version\n\n\
         PRIVILÈGES : socket ICMP brut requis.\n\
         \x20 Linux  : sudo setcap cap_net_raw+ep <binaire>  (ou lancer avec sudo)\n\
         \x20 Windows: exécuter en administrateur"
    );
}

/// Sous Windows, le programme est une application console pour que
/// `--report`, `--watch` et `--help` écrivent dans le terminal. Lancé par un
/// double-clic, il reçoit une console rien que pour lui : on la referme avant
/// d'ouvrir l'interface. Lancé depuis un terminal, on laisse celui-ci tranquille.
#[cfg(windows)]
fn hide_own_console() {
    use windows_sys::Win32::System::Console::{FreeConsole, GetConsoleProcessList};
    let mut pids = [0u32; 2];
    // Un seul processus attaché à la console : elle n'existe que pour nous.
    if unsafe { GetConsoleProcessList(pids.as_mut_ptr(), 2) } == 1 {
        unsafe { FreeConsole() };
    }
}

#[cfg(not(windows))]
fn hide_own_console() {}

fn main() -> eframe::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return Ok(());
    }
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("lagtrail {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    if let Some(pos) = args.iter().position(|a| a == "--report") {
        std::process::exit(run_report(&args[pos + 1..]));
    }
    if let Some(pos) = args.iter().position(|a| a == "--watch") {
        std::process::exit(run_watch(&args[pos + 1..]));
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

    hide_own_console();
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

/// Options communes aux modes sans interface (`--report`, `--watch`).
#[derive(Clone)]
struct CliOpts {
    /// Cible courante (la première, ou celle du rapport en cours).
    target: String,
    /// Toutes les cibles données (plusieurs possibles avec `--report`).
    targets: Vec<String>,
    protocol: engine::ProbeProtocol,
    port: u16,
    rounds: Option<u64>,
    interval_secs: f32,
    prefer_v6: bool,
    json: bool,
    log: Option<String>,
    exec: Option<String>,
    html: Option<String>,
}

const CLI_USAGE: &str = "usage : lagtrail --report|--watch <cible> [icmp|udp|tcp] [port] \
                         [--rounds N] [--interval S] [-6] [--json] [--log fichier] [--exec commande] [--html fichier]";

fn parse_cli(args: &[String]) -> Option<CliOpts> {
    const VALUED: [&str; 5] = ["--rounds", "--interval", "--log", "--exec", "--html"];
    let flag_value = |name: &str| {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
    };
    // Arguments positionnels (ni drapeau ni valeur de drapeau) : des cibles,
    // puis éventuellement un protocole et son port.
    let mut targets = Vec::new();
    let mut protocol = None;
    let mut port = None;
    let mut skip = false;
    for a in args {
        if skip {
            skip = false;
        } else if VALUED.contains(&a.as_str()) {
            skip = true;
        } else if !a.starts_with('-') {
            match a.to_ascii_lowercase().as_str() {
                "icmp" => protocol = Some(engine::ProbeProtocol::Icmp),
                "udp" => protocol = Some(engine::ProbeProtocol::Udp),
                "tcp" => protocol = Some(engine::ProbeProtocol::Tcp),
                _ => match a.parse::<u16>() {
                    Ok(p) if protocol.is_some() && port.is_none() => port = Some(p),
                    // Une cible répétée ne serait mesurée qu'en double.
                    _ if targets.contains(a) => {}
                    _ => targets.push(a.clone()),
                },
            }
        }
    }
    Some(CliOpts {
        target: targets.first()?.clone(),
        targets,
        protocol: protocol.unwrap_or(engine::ProbeProtocol::Icmp),
        port: port.unwrap_or(443),
        rounds: flag_value("--rounds").and_then(|v| v.parse().ok()).filter(|n| *n > 0),
        interval_secs: flag_value("--interval")
            .and_then(|v| v.parse().ok())
            .unwrap_or(1.0f32)
            .clamp(0.2, 3600.0),
        prefer_v6: args.iter().any(|a| a == "-6"),
        json: args.iter().any(|a| a == "--json"),
        log: flag_value("--log").cloned(),
        exec: flag_value("--exec").cloned(),
        html: flag_value("--html").cloned(),
    })
}

/// Une trace pilotée hors interface : moteur + agrégation + journal.
struct Headless {
    cmd_tx: std::sync::mpsc::Sender<engine::EngineCmd>,
    msg_rx: std::sync::mpsc::Receiver<engine::EngineMsg>,
    hops: Vec<stats::HopView>,
    names: std::collections::HashMap<std::net::IpAddr, String>,
    journal: stats::Journal,
    final_ttl: Option<u8>,
    resolved: Option<std::net::IpAddr>,
    start: Instant,
    patience: Duration,
    /// Levé par Ctrl-C : on termine proprement, avec le bilan.
    interrupted: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Headless {
    fn start(o: &CliOpts) -> Self {
        let (cmd_tx, cmd_rx) = std::sync::mpsc::channel();
        let (msg_tx, msg_rx) = std::sync::mpsc::channel();
        engine::spawn_engine(cmd_rx, msg_tx, || {});
        // Un seul gestionnaire pour tout le processus, partagé par les traces
        // menées en parallèle. Sans lui (cas improbable), Ctrl-C garde son
        // effet par défaut.
        static INTERRUPTED: std::sync::OnceLock<std::sync::Arc<std::sync::atomic::AtomicBool>> =
            std::sync::OnceLock::new();
        let interrupted = INTERRUPTED
            .get_or_init(|| {
                let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                let seen = flag.clone();
                let _ = ctrlc::set_handler(move || {
                    // Second Ctrl-C : sortie immédiate.
                    if seen.swap(true, std::sync::atomic::Ordering::SeqCst) {
                        std::process::exit(130);
                    }
                });
                flag
            })
            .clone();
        let interval = Duration::from_secs_f32(o.interval_secs);
        let _ = cmd_tx.send(engine::EngineCmd::Start {
            target: o.target.clone(),
            interval,
            max_hops: 30,
            protocol: o.protocol,
            port: o.port,
            prefer_v6: o.prefer_v6,
        });
        Self {
            cmd_tx,
            msg_rx,
            hops: Vec::new(),
            names: Default::default(),
            journal: Default::default(),
            final_ttl: None,
            resolved: None,
            start: Instant::now(),
            patience: interval + Duration::from_secs(15),
            interrupted,
        }
    }

    /// Attend le prochain tour de mesure réel (les tours de découverte sont
    /// intégrés mais pas comptés). `Ok(false)` = interrompu par Ctrl-C,
    /// `Err` = message d'erreur à afficher.
    fn next_round(&mut self) -> Result<bool, String> {
        use std::sync::mpsc::RecvTimeoutError;
        let deadline = Instant::now() + self.patience;
        loop {
            if self.interrupted.load(std::sync::atomic::Ordering::SeqCst) {
                return Ok(false);
            }
            match self.msg_rx.recv_timeout(Duration::from_millis(100)) {
                Ok(engine::EngineMsg::Resolved { addr, .. }) => self.resolved = Some(addr),
                Ok(engine::EngineMsg::Round { final_ttl, samples, warmup }) => {
                    self.final_ttl = final_ttl;
                    stats::apply_round_ex(
                        &mut self.hops,
                        &self.names,
                        &mut self.journal,
                        self.start.elapsed().as_secs_f64(),
                        final_ttl,
                        &samples,
                        warmup,
                    );
                    if !warmup {
                        return Ok(true);
                    }
                }
                Ok(engine::EngineMsg::HopName { addr, name }) => {
                    stats::apply_name(&mut self.hops, &mut self.names, addr, name);
                }
                Ok(engine::EngineMsg::Error(e)) => return Err(e),
                Ok(_) => {}
                Err(RecvTimeoutError::Timeout) if Instant::now() < deadline => {}
                Err(_) => return Err("le moteur ne répond plus".to_string()),
            }
        }
    }

    /// Arrête le moteur et laisse une courte chance aux derniers noms DNS.
    fn finish(&mut self) {
        let _ = self.cmd_tx.send(engine::EngineCmd::Stop);
        let grace = Instant::now() + Duration::from_millis(400);
        while let Ok(msg) = self
            .msg_rx
            .recv_timeout(grace.saturating_duration_since(Instant::now()))
        {
            if let engine::EngineMsg::HopName { addr, name } = msg {
                stats::apply_name(&mut self.hops, &mut self.names, addr, name);
            }
        }
    }

    fn reached(&self) -> bool {
        self.final_ttl.is_some()
    }

    fn meta(&self, o: &CliOpts) -> stats::ReportMeta {
        stats::ReportMeta {
            target: o.target.clone(),
            addr: self.resolved,
            protocol: o.protocol.describe(o.port),
            interval_secs: o.interval_secs,
            elapsed_secs: self.start.elapsed().as_secs_f64(),
        }
    }

    /// Écrit le rapport HTML demandé par `--html`. Renvoie `false` en cas d'échec.
    fn write_html(&self, o: &CliOpts) -> bool {
        let Some(path) = &o.html else { return true };
        let page = html::html_report(
            &self.meta(o),
            &self.hops,
            self.reached(),
            &self.journal,
            &stats::fmt_utc(std::time::SystemTime::now()),
        );
        match std::fs::write(path, page) {
            Ok(()) => {
                eprintln!("rapport HTML : {path}");
                true
            }
            Err(e) => {
                eprintln!("rapport HTML {path} : {e}");
                false
            }
        }
    }

    fn exit_code(&self) -> i32 {
        match diagnosis::worst(&stats::findings(&self.hops, self.reached())) {
            diagnosis::Severity::Critical => 2,
            diagnosis::Severity::Warning => 1,
            _ => 0,
        }
    }
}

/// Mode rapport : mesure N tours, affiche le rapport (texte ou JSON) et
/// renvoie un code de sortie exploitable par un script
/// (0 sain, 1 attention, 2 critique, 3 erreur).
fn run_report(args: &[String]) -> i32 {
    let Some(o) = parse_cli(args) else {
        eprintln!("{CLI_USAGE}");
        return 3;
    };
    if o.targets.len() > 1 {
        return run_multi_report(&o);
    }
    let rounds = o.rounds.unwrap_or(20);
    // La progression n'a de sens que dans un terminal (pas dans un log cron).
    let progress = std::io::IsTerminal::is_terminal(&std::io::stderr());
    let mut h = Headless::start(&o);
    for done in 1..=rounds {
        match h.next_round() {
            Ok(true) if progress => eprint!("\rtour {done}/{rounds}"),
            Ok(true) => {}
            // Ctrl-C : on rend le rapport des tours déjà mesurés.
            Ok(false) => break,
            Err(e) => {
                eprintln!("\n{e}");
                return 3;
            }
        }
    }
    if progress {
        eprintln!();
    }
    h.finish();
    let (meta, reached) = (h.meta(&o), h.reached());
    if o.json {
        println!("{}", stats::json_report(&meta, &h.hops, reached, &h.journal));
    } else {
        print!("{}", stats::text_report(&meta, &h.hops, reached, &h.journal));
    }
    if !h.write_html(&o) {
        return 3;
    }
    h.exit_code()
}

/// Rapport sur plusieurs cibles mesurées en parallèle : un rapport par cible,
/// puis une synthèse. Le code de sortie est celui de la cible la plus mal en
/// point. Avec `--html`, un fichier par cible (nom suffixé par la cible).
fn run_multi_report(o: &CliOpts) -> i32 {
    let rounds = o.rounds.unwrap_or(20);
    eprintln!("mesure de {} cibles en parallèle, {rounds} tours…", o.targets.len());
    let workers: Vec<_> = o
        .targets
        .iter()
        .map(|t| {
            let mut one = o.clone();
            one.target = t.clone();
            one.html = o.html.as_ref().map(|path| suffixed_path(path, t));
            std::thread::spawn(move || {
                let mut h = Headless::start(&one);
                let mut error = None;
                for _ in 0..rounds {
                    match h.next_round() {
                        Ok(true) => {}
                        Ok(false) => break,
                        Err(e) => {
                            error = Some(e);
                            break;
                        }
                    }
                }
                h.finish();
                (one, h, error)
            })
        })
        .collect();

    let mut code = 0;
    let mut json = Vec::new();
    let mut summary = Vec::new();
    let mut health = Vec::new();
    for w in workers {
        let Ok((one, h, error)) = w.join() else {
            code = 3;
            continue;
        };
        if let Some(e) = error {
            eprintln!("{} : {e}", one.target);
            summary.push(format!("  [ERREUR]     {:<28}  {e}", one.target));
            code = 3;
            continue;
        }
        let (meta, reached) = (h.meta(&one), h.reached());
        health.push(stats::target_health(&one.target, &h.hops, reached));
        if o.json {
            json.push(stats::json_report(&meta, &h.hops, reached, &h.journal));
        } else {
            print!("{}", stats::text_report(&meta, &h.hops, reached, &h.journal));
            println!("\n{}\n", "─".repeat(72));
        }
        if !h.write_html(&one) {
            code = 3;
        }
        let (tag, c) = match h.exit_code() {
            2 => ("CRITIQUE", 2),
            1 => ("ATTENTION", 1),
            _ => ("OK", 0),
        };
        code = code.max(c);
        let detail = match h.hops.last().filter(|_| reached) {
            Some(d) => format!(
                "{} ms en moyenne, {:.1} % de perte, {} sauts",
                stats::fmt_ms(d.avg()),
                d.loss_pct(),
                h.hops.len()
            ),
            None => "destination non atteinte".to_string(),
        };
        summary.push(format!("  [{tag}]{}  {:<28}  {detail}", " ".repeat(9 - tag.chars().count()), one.target));
    }
    if o.json {
        println!("[\n{}\n]", json.join(",\n"));
    } else {
        println!("Synthèse :");
        for line in &summary {
            println!("{line}");
        }
        if let Some(f) = diagnosis::compare_targets(&health) {
            println!("\n  {}", f.text);
        }
    }
    code
}

/// `rapport.html` + `exemple.com` → `rapport-exemple.com.html`.
fn suffixed_path(path: &str, target: &str) -> String {
    let safe: String = target
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
        .collect();
    let p = std::path::Path::new(path);
    match (p.file_stem().and_then(|s| s.to_str()), p.extension().and_then(|e| e.to_str())) {
        (Some(stem), Some(ext)) => p
            .with_file_name(format!("{stem}-{safe}.{ext}"))
            .to_string_lossy()
            .into_owned(),
        _ => format!("{path}-{safe}"),
    }
}

/// Sortie du mode surveillance : terminal et fichier `--log`, en lignes de
/// texte ou en JSON Lines (`--json`), partagée entre les cibles surveillées.
struct Emitter {
    log: Option<std::fs::File>,
    json: bool,
    /// Plusieurs cibles : chaque ligne de texte nomme la sienne.
    multi: bool,
}

/// Nature d'une ligne de surveillance.
#[derive(Clone, Copy)]
enum Kind {
    Note,
    Event(diagnosis::Severity),
    Status,
    Summary,
    Error,
}

impl Kind {
    /// Étiquette du format texte (et de `LAGTRAIL_SEVERITY` pour `--exec`).
    fn label(self) -> &'static str {
        match self {
            Kind::Note => "",
            Kind::Event(diagnosis::Severity::Critical) => "CRITIQUE",
            Kind::Event(diagnosis::Severity::Warning) => "ATTENTION",
            Kind::Event(diagnosis::Severity::Ok) => "OK",
            Kind::Event(diagnosis::Severity::Info) => "info",
            Kind::Status => "état",
            Kind::Summary => "bilan",
            Kind::Error => "ERREUR",
        }
    }

    /// Clé stable du format JSON.
    fn key(self) -> &'static str {
        match self {
            Kind::Note => "note",
            Kind::Event(diagnosis::Severity::Critical) => "critical",
            Kind::Event(diagnosis::Severity::Warning) => "warning",
            Kind::Event(diagnosis::Severity::Ok) => "recovered",
            Kind::Event(diagnosis::Severity::Info) => "info",
            Kind::Status => "status",
            Kind::Summary => "summary",
            Kind::Error => "error",
        }
    }
}

/// Met en forme une ligne de surveillance (sans retour à la ligne).
fn watch_line(json: bool, multi: bool, time: &str, target: Option<&str>, kind: Kind, text: &str) -> String {
    if json {
        let target = target.map(stats::json_str).unwrap_or_else(|| "null".into());
        return format!(
            "{{\"time\": \"{time}\", \"target\": {target}, \"kind\": \"{}\", \"text\": {}}}",
            kind.key(),
            stats::json_str(text)
        );
    }
    let mut line = time.to_string();
    if let Some(t) = target.filter(|_| multi) {
        line.push_str(&format!("  [{t}]"));
    }
    if !kind.label().is_empty() {
        line.push_str(&format!("  {}", kind.label()));
    }
    format!("{line}  {text}")
}

impl Emitter {
    fn emit(&mut self, target: Option<&str>, kind: Kind, text: &str) {
        use std::io::Write;
        let time = stats::fmt_utc(std::time::SystemTime::now());
        let line = watch_line(self.json, self.multi, &time, target, kind, text);
        println!("{line}");
        if let Some(f) = self.log.as_mut() {
            let _ = writeln!(f, "{line}");
        }
    }
}

type SharedEmitter = std::sync::Arc<std::sync::Mutex<Emitter>>;

/// Mode surveillance : tourne jusqu'à interruption (ou `--rounds N`), écrit
/// chaque événement dès qu'il survient, horodaté en UTC, plus un point d'état
/// périodique. `--log fichier` ajoute les mêmes lignes à un fichier ;
/// `--json` les écrit en JSON Lines. Plusieurs cibles sont surveillées en
/// parallèle et comparées dans le bilan.
fn run_watch(args: &[String]) -> i32 {
    let Some(o) = parse_cli(args) else {
        eprintln!("{CLI_USAGE}");
        return 3;
    };
    let log = match &o.log {
        Some(path) => match std::fs::OpenOptions::new().create(true).append(true).open(path) {
            Ok(f) => Some(f),
            Err(e) => {
                eprintln!("journal {path} : {e}");
                return 3;
            }
        },
        None => None,
    };
    let multi = o.targets.len() > 1;
    let em: SharedEmitter =
        std::sync::Arc::new(std::sync::Mutex::new(Emitter { log, json: o.json, multi }));
    let workers: Vec<_> = o
        .targets
        .iter()
        .map(|t| {
            let mut one = o.clone();
            one.target = t.clone();
            if multi {
                one.html = o.html.as_ref().map(|path| suffixed_path(path, t));
            }
            let em = em.clone();
            std::thread::spawn(move || watch_one(&one, &em))
        })
        .collect();
    let mut code = 0;
    let mut health = Vec::new();
    for w in workers {
        match w.join() {
            Ok((c, h)) => {
                code = code.max(c);
                health.extend(h);
            }
            Err(_) => code = 3,
        }
    }
    if let Some(f) = diagnosis::compare_targets(&health) {
        if let Ok(mut em) = em.lock() {
            em.emit(None, Kind::Summary, &f.text);
        }
    }
    code
}

/// Surveille une cible. Renvoie son code de sortie et, si elle a été mesurée,
/// son état pour la comparaison entre cibles.
fn watch_one(o: &CliOpts, em: &SharedEmitter) -> (i32, Option<diagnosis::TargetHealth>) {
    let emit = |kind: Kind, text: String| {
        if let Ok(mut em) = em.lock() {
            em.emit(Some(&o.target), kind, &text);
        }
    };
    emit(
        Kind::Note,
        format!(
            "surveillance de {} ({}, intervalle {} s) — Ctrl-C pour arrêter",
            o.target,
            o.protocol.describe(o.port),
            o.interval_secs
        ),
    );
    let mut h = Headless::start(o);
    let status_every = Duration::from_secs(60);
    let mut next_status = Instant::now() + status_every;
    let mut seen = 0u64;
    let mut announced = false;
    let mut done = 0u64;

    loop {
        let interrupted = match h.next_round() {
            Ok(measured) => !measured,
            Err(e) => {
                emit(Kind::Error, e);
                return (3, None);
            }
        };
        if interrupted {
            emit(Kind::Note, format!("arrêt demandé après {done} tours"));
        } else {
            done += 1;
        }
        if !announced && h.reached() {
            announced = true;
            let addr = h.resolved.map(|a| a.to_string()).unwrap_or_default();
            emit(Kind::Note, format!("chemin établi : {} sauts jusqu'à {addr}", h.hops.len()));
        }
        // Nouveaux événements du journal depuis le dernier passage.
        let fresh = (h.journal.total - seen) as usize;
        seen = h.journal.total;
        let events = &h.journal.events;
        for e in &events[events.len().saturating_sub(fresh)..] {
            let kind = Kind::Event(e.severity);
            emit(kind, e.text.clone());
            if let Some(cmd) = &o.exec {
                run_hook(cmd, &o.target, kind.label(), &e.text);
            }
        }
        let last_round = interrupted || o.rounds.is_some_and(|n| done >= n);
        if Instant::now() >= next_status || last_round {
            next_status = Instant::now() + status_every;
            let line = match h.hops.last().filter(|_| h.reached()) {
                Some(d) => format!(
                    "{} tours — destination : {} ms en moyenne, {:.1} % de perte, gigue {} ms",
                    d.sent,
                    stats::fmt_ms(d.avg()),
                    d.loss_pct(),
                    stats::fmt_ms(d.jitter()),
                ),
                None => format!("{done} tours — destination non atteinte"),
            };
            emit(Kind::Status, line);
        }
        if last_round {
            h.finish();
            let elapsed = h.start.elapsed().as_secs_f64();
            emit(Kind::Summary, h.journal.outages(elapsed).describe());
            for f in stats::findings(&h.hops, h.reached()) {
                emit(Kind::Summary, f.text);
            }
            let health = stats::target_health(&o.target, &h.hops, h.reached());
            let code = if h.write_html(o) { h.exit_code() } else { 3 };
            return (code, Some(health));
        }
    }
}

/// Lance la commande `--exec` pour un événement, sans attendre sa fin.
/// L'événement est passé par variables d'environnement, jamais interpolé
/// dans la ligne de commande.
fn run_hook(cmd: &str, target: &str, severity: &str, text: &str) {
    let mut c = if cfg!(windows) {
        let mut c = std::process::Command::new("cmd");
        c.args(["/C", cmd]);
        c
    } else {
        let mut c = std::process::Command::new("sh");
        c.args(["-c", cmd]);
        c
    };
    c.env("LAGTRAIL_TARGET", target)
        .env("LAGTRAIL_SEVERITY", severity)
        .env("LAGTRAIL_EVENT", text)
        .stdin(std::process::Stdio::null());
    match c.spawn() {
        // Un fil par commande évite de laisser des processus zombies.
        Ok(mut child) => {
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
        Err(e) => eprintln!("--exec : {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cli(args: &[&str]) -> CliOpts {
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        parse_cli(&args).expect("cible attendue")
    }

    #[test]
    fn cli_single_target_with_protocol_and_port() {
        let o = cli(&["1.1.1.1", "tcp", "8443", "--rounds", "5"]);
        assert_eq!(o.targets, ["1.1.1.1"]);
        assert!(matches!(o.protocol, engine::ProbeProtocol::Tcp));
        assert_eq!((o.port, o.rounds), (8443, Some(5)));
    }

    #[test]
    fn cli_several_targets_and_flag_values_are_not_targets() {
        let o = cli(&["--log", "x.log", "a.example", "b.example", "a.example", "udp", "--interval", "2"]);
        assert_eq!(o.targets, ["a.example", "b.example"]);
        assert!(matches!(o.protocol, engine::ProbeProtocol::Udp));
        assert_eq!(o.port, 443);
        assert_eq!(o.log.as_deref(), Some("x.log"));
    }

    #[test]
    fn cli_requires_a_target() {
        let args = vec!["--rounds".to_string(), "5".to_string()];
        assert!(parse_cli(&args).is_none());
    }

    #[test]
    fn watch_lines_in_text_and_json() {
        let ev = Kind::Event(diagnosis::Severity::Critical);
        let t = "2026-11-15T10:00:00Z";
        assert_eq!(watch_line(false, false, t, Some("a"), ev, "x"), format!("{t}  CRITIQUE  x"));
        assert_eq!(watch_line(false, true, t, Some("a"), ev, "x"), format!("{t}  [a]  CRITIQUE  x"));
        assert_eq!(watch_line(false, true, t, None, Kind::Note, "x"), format!("{t}  x"));
        assert_eq!(
            watch_line(true, true, t, Some("a\"b"), ev, "x"),
            format!("{{\"time\": \"{t}\", \"target\": \"a\\\"b\", \"kind\": \"critical\", \"text\": \"x\"}}")
        );
    }

    #[test]
    fn html_path_gets_target_suffix() {
        assert_eq!(suffixed_path("out/r.html", "a.example"), "out/r-a.example.html");
        assert_eq!(suffixed_path("rapport", "::1"), "rapport-__1");
    }
}
