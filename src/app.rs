//! Interface graphique (egui / eframe).
//!
//! L'appli gère **plusieurs traces simultanées** : chaque onglet est une
//! `Session` indépendante (sa cible, son thread moteur, ses mesures). Un
//! sélecteur de thème clair/sombre/auto est disponible en haut.

use std::collections::{HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

use eframe::egui;
use egui_extras::{Column, TableBuilder};
use egui_plot::{HLine, Legend, Line, Plot, PlotPoints, Points};

use crate::engine::{self, EngineCmd, EngineMsg, HopSample, ProbeProtocol};

/// Nombre d'échantillons conservés par saut pour le graphe.
const HISTORY: usize = 600;

// ───────────────────────────── Vue d'un saut ─────────────────────────────

/// État affiché d'un saut (agrège les tours successifs).
struct HopView {
    ttl: u8,
    addr: Option<IpAddr>,
    name: Option<String>,
    sent: u64,
    recv: u64,
    last: Option<f64>,
    best: f64,
    worst: f64,
    sum: f64,
    prev: Option<f64>,
    jitter_sum: f64,
    jitter_n: u64,
    /// (x = numéro de tour, y = RTT en ms ; None = timeout)
    history: VecDeque<(f64, Option<f64>)>,
}

impl HopView {
    fn new(ttl: u8) -> Self {
        Self {
            ttl,
            addr: None,
            name: None,
            sent: 0,
            recv: 0,
            last: None,
            best: f64::INFINITY,
            worst: 0.0,
            sum: 0.0,
            prev: None,
            jitter_sum: 0.0,
            jitter_n: 0,
            history: VecDeque::new(),
        }
    }

    fn loss_pct(&self) -> f64 {
        if self.sent == 0 {
            0.0
        } else {
            (self.sent - self.recv) as f64 / self.sent as f64 * 100.0
        }
    }

    fn avg(&self) -> Option<f64> {
        (self.recv > 0).then(|| self.sum / self.recv as f64)
    }

    fn jitter(&self) -> Option<f64> {
        (self.jitter_n > 0).then(|| self.jitter_sum / self.jitter_n as f64)
    }

    fn record(&mut self, x: f64, s: &HopSample) {
        if let Some(a) = s.addr {
            self.addr = Some(a);
        }
        self.sent += 1;
        match s.rtt_ms {
            Some(rtt) => {
                self.recv += 1;
                self.last = Some(rtt);
                self.sum += rtt;
                if rtt < self.best {
                    self.best = rtt;
                }
                if rtt > self.worst {
                    self.worst = rtt;
                }
                if let Some(p) = self.prev {
                    self.jitter_sum += (rtt - p).abs();
                    self.jitter_n += 1;
                }
                self.prev = Some(rtt);
            }
            None => self.last = None,
        }
        self.history.push_back((x, s.rtt_ms));
        while self.history.len() > HISTORY {
            self.history.pop_front();
        }
    }
}

fn fmt_ms(v: Option<f64>) -> String {
    match v {
        Some(x) if x.is_finite() => format!("{x:.1}"),
        _ => "—".to_string(),
    }
}

/// Couleur d'une cellule « perte » selon le pourcentage.
fn loss_color(pct: f64) -> egui::Color32 {
    if pct <= 0.0 {
        egui::Color32::from_rgb(90, 180, 110)
    } else if pct < 20.0 {
        egui::Color32::from_rgb(200, 170, 60)
    } else {
        egui::Color32::from_rgb(210, 90, 90)
    }
}

/// Échappe un champ CSV (guillemets si virgule, guillemet ou saut de ligne).
fn csv_escape(s: &str) -> String {
    if s.contains([',', '"', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

// ───────────────────────────── Une session ───────────────────────────────

/// Une trace indépendante : sa cible, son moteur, ses mesures, son onglet.
struct Session {
    cmd_tx: Sender<EngineCmd>,
    msg_rx: Receiver<EngineMsg>,
    target_input: String,
    interval_secs: f32,
    max_hops: u8,
    running: bool,
    status: String,
    error: Option<String>,
    resolved: Option<(String, IpAddr)>,
    hops: Vec<HopView>,
    final_ttl: Option<u8>,
    selected: Option<usize>,
    x: f64,
    start: Option<Instant>,
    alerts_on: bool,
    alert_latency: f32,
    alert_loss: f32,
    protocol: ProbeProtocol,
    port: u16,
    prefer_v6: bool,
}

impl Session {
    /// Crée une session et démarre son thread moteur (réveille l'IHM via `ctx`).
    fn new(ctx: &egui::Context, target: String) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::channel();
        let (msg_tx, msg_rx) = mpsc::channel();
        let ctx = ctx.clone();
        engine::spawn_engine(cmd_rx, msg_tx, move || ctx.request_repaint());
        Self {
            cmd_tx,
            msg_rx,
            target_input: target,
            interval_secs: 1.0,
            max_hops: 30,
            running: false,
            status: "Prêt.".to_string(),
            error: None,
            resolved: None,
            hops: Vec::new(),
            final_ttl: None,
            selected: None,
            x: 0.0,
            start: None,
            alerts_on: false,
            alert_latency: 100.0,
            alert_loss: 5.0,
            protocol: ProbeProtocol::Icmp,
            port: 443,
            prefer_v6: false,
        }
    }

    /// Libellé d'onglet : cible en cours, sinon saisie, sinon générique.
    fn tab_label(&self) -> String {
        let name = self
            .resolved
            .as_ref()
            .map(|(t, _)| t.clone())
            .or_else(|| {
                let t = self.target_input.trim();
                (!t.is_empty()).then(|| t.to_string())
            })
            .unwrap_or_else(|| "nouvelle".to_string());
        let dot = if self.running { "● " } else { "" };
        let warn = if self.alerting_ttls().is_empty() { "" } else { "⚠ " };
        format!("{warn}{dot}{name}")
    }

    /// Un saut est-il en alerte (latence moyenne ou perte au-dessus du seuil) ?
    fn hop_alerts(&self, h: &HopView) -> bool {
        self.alerts_on
            && h.sent > 0
            && (h.avg().is_some_and(|a| a > self.alert_latency as f64)
                || h.loss_pct() > self.alert_loss as f64)
    }

    /// TTL des sauts actuellement en alerte.
    fn alerting_ttls(&self) -> Vec<u8> {
        if !self.alerts_on {
            return Vec::new();
        }
        self.hops
            .iter()
            .filter(|h| self.hop_alerts(h))
            .map(|h| h.ttl)
            .collect()
    }

    fn start(&mut self) {
        let target = self.target_input.trim().to_string();
        if target.is_empty() {
            self.error = Some("Indique une cible (nom d'hôte ou adresse IP).".into());
            return;
        }
        self.error = None;
        self.hops.clear();
        self.final_ttl = None;
        self.selected = None;
        self.resolved = None;
        self.x = 0.0;
        self.start = Some(Instant::now());
        let interval = Duration::from_secs_f32(self.interval_secs.max(0.2));
        let _ = self.cmd_tx.send(EngineCmd::Start {
            target: target.clone(),
            interval,
            max_hops: self.max_hops.clamp(1, 64),
            protocol: self.protocol,
            port: self.port,
            prefer_v6: self.prefer_v6,
        });
        self.status = format!("Démarrage vers {target} …");
        self.running = true;
    }

    fn stop(&mut self) {
        let _ = self.cmd_tx.send(EngineCmd::Stop);
        self.running = false;
        self.status = "Arrêté.".to_string();
    }

    fn apply_msgs(&mut self) {
        while let Ok(msg) = self.msg_rx.try_recv() {
            match msg {
                EngineMsg::Resolved { target, addr } => {
                    self.status = format!("{target} → {addr}");
                    self.resolved = Some((target, addr));
                }
                EngineMsg::Started => self.status = "Trace en cours…".to_string(),
                EngineMsg::Round { final_ttl, samples } => {
                    self.final_ttl = final_ttl;
                    self.x = self
                        .start
                        .map(|s| s.elapsed().as_secs_f64())
                        .unwrap_or(self.x + 1.0);
                    for s in &samples {
                        let idx = (s.ttl as usize).saturating_sub(1);
                        while self.hops.len() <= idx {
                            let ttl = (self.hops.len() + 1) as u8;
                            self.hops.push(HopView::new(ttl));
                        }
                        self.hops[idx].record(self.x, s);
                    }
                    if let Some(ft) = final_ttl {
                        self.hops.truncate(ft as usize);
                        if self.selected.is_none() {
                            self.selected = Some(ft as usize - 1);
                        }
                    }
                }
                EngineMsg::HopName { ttl, name } => {
                    if let Some(h) = self.hops.get_mut(ttl as usize - 1) {
                        h.name = Some(name);
                    }
                }
                EngineMsg::Error(e) => {
                    self.error = Some(e);
                    self.running = false;
                    self.status = "Erreur.".to_string();
                }
                EngineMsg::Stopped => {
                    self.running = false;
                    self.status = "Arrêté.".to_string();
                }
            }
        }
    }

    fn controls(&mut self, ui: &mut egui::Ui) {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label("Cible :");
            let resp = ui.add(
                egui::TextEdit::singleline(&mut self.target_input)
                    .desired_width(220.0)
                    .hint_text("nom d'hôte ou IP"),
            );
            let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if self.running {
                if ui.button("⏹ Arrêter").clicked() {
                    self.stop();
                }
            } else if ui.button("▶ Démarrer").clicked() || enter {
                self.start();
            }
            ui.separator();
            ui.label("Intervalle :");
            ui.add(
                egui::DragValue::new(&mut self.interval_secs)
                    .range(0.2..=10.0)
                    .speed(0.05)
                    .suffix(" s"),
            );
            ui.label("Max sauts :");
            let mut mh = self.max_hops as i32;
            if ui
                .add_enabled(!self.running, egui::DragValue::new(&mut mh).range(1..=64))
                .changed()
            {
                self.max_hops = mh.clamp(1, 64) as u8;
            }
        });
        ui.add_space(2.0);
        ui.add_enabled_ui(!self.running, |ui| {
            ui.horizontal(|ui| {
                ui.label("Protocole :");
                ui.selectable_value(&mut self.protocol, ProbeProtocol::Icmp, "ICMP");
                ui.selectable_value(&mut self.protocol, ProbeProtocol::Udp, "UDP");
                ui.selectable_value(&mut self.protocol, ProbeProtocol::Tcp, "TCP");
                if self.protocol.uses_port() {
                    ui.separator();
                    ui.label("Port :");
                    ui.add(egui::DragValue::new(&mut self.port).range(1..=65535));
                }
                ui.separator();
                ui.checkbox(&mut self.prefer_v6, "IPv6")
                    .on_hover_text("Résoudre et sonder en IPv6 (ICMPv6)");
            });
        });
        ui.add_space(2.0);
        ui.horizontal(|ui| {
            let has = !self.hops.is_empty();
            ui.label("Export :");
            if ui
                .add_enabled(has, egui::Button::new("⤓ Résumé CSV"))
                .on_hover_text("Exporter le tableau actuel (une ligne par saut)")
                .clicked()
            {
                self.export_summary();
            }
            if ui
                .add_enabled(has, egui::Button::new("⤓ Historique CSV"))
                .on_hover_text("Exporter toute la série temporelle (tour × saut)")
                .clicked()
            {
                self.export_history();
            }
        });
        ui.add_space(2.0);
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.alerts_on, "Alertes");
            ui.add_enabled(
                self.alerts_on,
                egui::DragValue::new(&mut self.alert_latency)
                    .range(1.0..=10000.0)
                    .speed(1.0)
                    .prefix("latence > ")
                    .suffix(" ms"),
            );
            ui.add_enabled(
                self.alerts_on,
                egui::DragValue::new(&mut self.alert_loss)
                    .range(0.0..=100.0)
                    .speed(0.5)
                    .prefix("perte > ")
                    .suffix(" %"),
            );
        });
        ui.add_space(2.0);
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(&self.status).weak());
            if let Some((_, addr)) = &self.resolved {
                ui.separator();
                ui.monospace(addr.to_string());
            }
        });
        if let Some(err) = &self.error {
            ui.add_space(2.0);
            ui.label(egui::RichText::new(err).color(egui::Color32::from_rgb(230, 90, 90)));
        }
        let alerting = self.alerting_ttls();
        if !alerting.is_empty() {
            let list = alerting
                .iter()
                .map(|t| format!("#{t}"))
                .collect::<Vec<_>>()
                .join(", ");
            ui.add_space(2.0);
            ui.label(
                egui::RichText::new(format!("⚠ Alerte — sauts {list} au-dessus du seuil"))
                    .color(egui::Color32::from_rgb(235, 140, 40))
                    .strong(),
            );
        }
        ui.add_space(4.0);
    }

    fn table(&mut self, ui: &mut egui::Ui) {
        if self.hops.is_empty() {
            ui.centered_and_justified(|ui| {
                ui.label(
                    egui::RichText::new("Aucun saut encore. Clique « Démarrer ».")
                        .weak()
                        .italics(),
                );
            });
            return;
        }

        let row_h = egui::TextStyle::Body.resolve(ui.style()).size + 8.0;
        let alerting: HashSet<u8> = self.alerting_ttls().into_iter().collect();
        let hops = &self.hops;
        let mut new_sel = self.selected;

        TableBuilder::new(ui)
            .striped(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::exact(34.0))
            .column(Column::initial(150.0).at_least(110.0))
            .column(Column::remainder().at_least(150.0))
            .column(Column::exact(64.0))
            .column(Column::exact(64.0))
            .column(Column::exact(64.0))
            .column(Column::exact(64.0))
            .column(Column::exact(64.0))
            .column(Column::exact(64.0))
            .header(row_h, |mut h| {
                for t in [
                    "#", "Adresse", "Nom", "Perte", "Dern.", "Moy.", "Min.", "Max.", "Gigue",
                ] {
                    h.col(|ui| {
                        ui.strong(t);
                    });
                }
            })
            .body(|mut body| {
                for (i, hop) in hops.iter().enumerate() {
                    let selected = new_sel == Some(i);
                    body.row(row_h, |mut row| {
                        row.set_selected(selected);
                        let mut clicked = false;
                        row.col(|ui| {
                            let label = if alerting.contains(&hop.ttl) {
                                egui::RichText::new(format!("⚠{}", hop.ttl))
                                    .color(egui::Color32::from_rgb(235, 140, 40))
                                    .strong()
                            } else {
                                egui::RichText::new(format!("{}", hop.ttl))
                            };
                            if ui.selectable_label(selected, label).clicked() {
                                clicked = true;
                            }
                        });
                        row.col(|ui| {
                            let s = hop.addr.map(|a| a.to_string()).unwrap_or_else(|| "*".into());
                            if ui.monospace(s).clicked() {
                                clicked = true;
                            }
                        });
                        row.col(|ui| {
                            let s = hop
                                .name
                                .clone()
                                .or_else(|| hop.addr.map(|a| a.to_string()))
                                .unwrap_or_else(|| "(en attente)".into());
                            ui.label(s);
                        });
                        row.col(|ui| {
                            let pct = hop.loss_pct();
                            ui.colored_label(loss_color(pct), format!("{pct:.0} %"));
                        });
                        row.col(|ui| {
                            ui.label(fmt_ms(hop.last));
                        });
                        row.col(|ui| {
                            ui.label(fmt_ms(hop.avg()));
                        });
                        row.col(|ui| {
                            ui.label(fmt_ms((hop.best.is_finite()).then_some(hop.best)));
                        });
                        row.col(|ui| {
                            ui.label(fmt_ms((hop.worst > 0.0).then_some(hop.worst)));
                        });
                        row.col(|ui| {
                            ui.label(fmt_ms(hop.jitter()));
                        });
                        if row.response().clicked() || clicked {
                            new_sel = Some(i);
                        }
                    });
                }
            });

        self.selected = new_sel;
    }

    fn plot(&mut self, ui: &mut egui::Ui) {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.strong("Latence dans le temps");
            match self.selected.and_then(|i| self.hops.get(i)) {
                Some(h) => {
                    ui.separator();
                    let label = h
                        .name
                        .clone()
                        .or_else(|| h.addr.map(|a| a.to_string()))
                        .unwrap_or_else(|| "*".into());
                    ui.label(format!("Saut {} — {label}", h.ttl));
                }
                None => {
                    ui.label(egui::RichText::new("(clique un saut dans le tableau)").weak());
                }
            }
        });

        // Découpe l'historique en segments continus (coupés aux timeouts) et
        // collecte les instants de perte pour les marquer en rouge.
        let sel = self.selected.and_then(|i| self.hops.get(i));
        let mut segments: Vec<Vec<[f64; 2]>> = Vec::new();
        let mut current: Vec<[f64; 2]> = Vec::new();
        let mut loss_pts: Vec<[f64; 2]> = Vec::new();
        if let Some(h) = sel {
            for (x, y) in &h.history {
                match y {
                    Some(v) => current.push([*x, *v]),
                    None => {
                        if !current.is_empty() {
                            segments.push(std::mem::take(&mut current));
                        }
                        loss_pts.push([*x, 0.0]);
                    }
                }
            }
            if !current.is_empty() {
                segments.push(current);
            }
        }
        let avg = sel.and_then(|h| h.avg());

        Plot::new("latency_plot")
            .legend(Legend::default())
            .x_axis_label("temps (s)")
            .y_axis_label("latence (ms)")
            .include_y(0.0)
            .show(ui, |pui| {
                let rtt_color = egui::Color32::from_rgb(95, 160, 235);
                for (i, seg) in segments.iter().enumerate() {
                    let name = if i == 0 { "RTT (ms)" } else { "" };
                    pui.line(Line::new(name, PlotPoints::from(seg.clone())).color(rtt_color));
                }
                if let Some(a) = avg {
                    pui.hline(HLine::new("moyenne", a));
                }
                if !loss_pts.is_empty() {
                    pui.points(
                        Points::new("pertes", PlotPoints::from(loss_pts))
                            .color(egui::Color32::from_rgb(220, 60, 60))
                            .radius(3.5),
                    );
                }
            });
    }

    /// CSV « résumé » : une ligne par saut (snapshot du tableau).
    fn summary_csv(&self) -> String {
        let f = |v: Option<f64>| v.map(|x| format!("{x:.3}")).unwrap_or_default();
        let mut out = String::from(
            "hop,address,hostname,sent,recv,loss_pct,last_ms,avg_ms,min_ms,max_ms,jitter_ms\n",
        );
        for h in &self.hops {
            let addr = h.addr.map(|a| a.to_string()).unwrap_or_default();
            let name = h.name.clone().unwrap_or_default();
            let min = h.best.is_finite().then_some(h.best);
            let max = (h.worst > 0.0).then_some(h.worst);
            out.push_str(&format!(
                "{},{},{},{},{},{:.2},{},{},{},{},{}\n",
                h.ttl,
                csv_escape(&addr),
                csv_escape(&name),
                h.sent,
                h.recv,
                h.loss_pct(),
                f(h.last),
                f(h.avg()),
                f(min),
                f(max),
                f(h.jitter()),
            ));
        }
        out
    }

    /// CSV « historique » : une ligne par (tour, saut), format long.
    fn history_csv(&self) -> String {
        let mut out = String::from("round,hop,address,rtt_ms\n");
        for h in &self.hops {
            let addr = csv_escape(&h.addr.map(|a| a.to_string()).unwrap_or_default());
            for (x, y) in &h.history {
                let rtt = y.map(|v| format!("{v:.3}")).unwrap_or_default();
                out.push_str(&format!("{},{},{},{}\n", *x as i64, h.ttl, addr, rtt));
            }
        }
        out
    }

    fn export_summary(&mut self) {
        let csv = self.summary_csv();
        self.save_csv("resume", csv);
    }

    fn export_history(&mut self) {
        let csv = self.history_csv();
        self.save_csv("historique", csv);
    }

    /// Ouvre un dialogue « Enregistrer sous » et écrit le CSV.
    fn save_csv(&mut self, kind: &str, contents: String) {
        let target = self
            .resolved
            .as_ref()
            .map(|(t, _)| t.clone())
            .unwrap_or_else(|| self.target_input.trim().to_string());
        let safe: String = target
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
            .collect();
        let name = format!("lagtrail-{safe}-{kind}.csv");
        if let Some(path) = rfd::FileDialog::new()
            .set_file_name(name)
            .add_filter("CSV", &["csv"])
            .save_file()
        {
            match std::fs::write(&path, contents) {
                Ok(()) => {
                    self.error = None;
                    self.status = format!("Exporté : {}", path.display());
                }
                Err(e) => self.error = Some(format!("Échec de l'export : {e}")),
            }
        }
    }
}

// ───────────────────────────── Application ───────────────────────────────

enum TabAction {
    Select(usize),
    Close(usize),
    Add,
}

pub struct App {
    sessions: Vec<Session>,
    active: usize,
    theme: egui::ThemePreference,
}

impl App {
    pub fn new(ctx: &egui::Context, initial_target: Option<String>) -> Self {
        let target = initial_target.unwrap_or_else(|| "1.1.1.1".to_string());
        let mut session = Session::new(ctx, target.clone());
        // La cible spéciale « demo » démarre d'elle-même (aucun privilège requis),
        // avec des alertes pré-réglées pour illustrer la fonction.
        if target.eq_ignore_ascii_case("demo") {
            session.alerts_on = true;
            session.alert_latency = 55.0;
            session.alert_loss = 8.0;
            session.start();
        }
        Self {
            sessions: vec![session],
            active: 0,
            theme: egui::ThemePreference::System,
        }
    }

    fn apply_tab_action(&mut self, action: TabAction, ctx: &egui::Context) {
        match action {
            TabAction::Select(i) => self.active = i,
            TabAction::Add => {
                self.sessions.push(Session::new(ctx, "1.1.1.1".to_string()));
                self.active = self.sessions.len() - 1;
            }
            TabAction::Close(i) => {
                if i < self.sessions.len() {
                    // Retirer la session suffit : son `cmd_tx` est libéré, le
                    // thread moteur se termine quand le canal se ferme.
                    self.sessions.remove(i);
                }
                if self.active >= self.sessions.len() {
                    self.active = self.sessions.len().saturating_sub(1);
                }
            }
        }
    }

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.heading("lagtrail");
            ui.separator();
            ui.label("Thème :");
            theme_button(ui, &mut self.theme, egui::ThemePreference::System, "Auto");
            theme_button(ui, &mut self.theme, egui::ThemePreference::Light, "Clair");
            theme_button(ui, &mut self.theme, egui::ThemePreference::Dark, "Sombre");
        });

        ui.add_space(4.0);
        let mut action: Option<TabAction> = None;
        egui::ScrollArea::horizontal().show(ui, |ui| {
            ui.horizontal(|ui| {
                for i in 0..self.sessions.len() {
                    let selected = self.active == i;
                    if ui
                        .selectable_label(selected, self.sessions[i].tab_label())
                        .clicked()
                    {
                        action = Some(TabAction::Select(i));
                    }
                    if ui.small_button("✕").on_hover_text("Fermer cette trace").clicked() {
                        action = Some(TabAction::Close(i));
                    }
                    ui.separator();
                }
                if ui.button("➕ Nouvelle trace").clicked() {
                    action = Some(TabAction::Add);
                }
            });
        });
        if let Some(a) = action {
            self.apply_tab_action(a, ui.ctx());
        }
        ui.add_space(2.0);
    }
}

fn theme_button(
    ui: &mut egui::Ui,
    current: &mut egui::ThemePreference,
    value: egui::ThemePreference,
    label: &str,
) {
    if ui.selectable_label(*current == value, label).clicked() {
        *current = value;
        ui.ctx().set_theme(value);
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // Draine les messages de TOUTES les sessions (les traces de fond
        // continuent d'avancer même si leur onglet n'est pas actif).
        let mut any_running = false;
        for s in &mut self.sessions {
            s.apply_msgs();
            any_running |= s.running;
        }

        egui::Panel::top("topbar").show(ui, |ui| self.top_bar(ui));

        if self.sessions.is_empty() {
            egui::CentralPanel::default().show(ui, |ui| {
                ui.centered_and_justified(|ui| {
                    ui.label(
                        egui::RichText::new("Aucune trace ouverte. Clique « ➕ Nouvelle trace ».")
                            .weak(),
                    );
                });
            });
            return;
        }

        let active = self.active.min(self.sessions.len() - 1);
        self.active = active;

        egui::Panel::top("controls").show(ui, |ui| self.sessions[active].controls(ui));
        egui::Panel::bottom("plot")
            .resizable(true)
            .default_size(240.0)
            .min_size(140.0)
            .show(ui, |ui| self.sessions[active].plot(ui));
        egui::CentralPanel::default().show(ui, |ui| self.sessions[active].table(ui));

        if any_running {
            ui.ctx().request_repaint_after(Duration::from_millis(200));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::HopSample;

    fn hop_with_samples() -> HopView {
        let mut h = HopView::new(1);
        let ip = IpAddr::from([10, 0, 0, 1]);
        h.name = Some("routeur.local".to_string());
        h.record(1.0, &HopSample { ttl: 1, addr: Some(ip), rtt_ms: Some(10.0) });
        h.record(2.0, &HopSample { ttl: 1, addr: Some(ip), rtt_ms: None }); // perte
        h.record(3.0, &HopSample { ttl: 1, addr: Some(ip), rtt_ms: Some(20.0) });
        h
    }

    #[test]
    fn summary_csv_header_and_stats() {
        let mut s = Session::new(&egui::Context::default(), "x".into());
        s.hops.push(hop_with_samples());
        let lines: Vec<String> = s.summary_csv().lines().map(String::from).collect();
        assert_eq!(
            lines[0],
            "hop,address,hostname,sent,recv,loss_pct,last_ms,avg_ms,min_ms,max_ms,jitter_ms"
        );
        // 3 envoyés, 2 reçus → perte 33,33 % ; min 10 / max 20 / moy 15 / gigue 10
        assert_eq!(
            lines[1],
            "1,10.0.0.1,routeur.local,3,2,33.33,20.000,15.000,10.000,20.000,10.000"
        );
    }

    #[test]
    fn history_csv_marks_timeouts_empty() {
        let mut s = Session::new(&egui::Context::default(), "x".into());
        s.hops.push(hop_with_samples());
        let lines: Vec<String> = s.history_csv().lines().map(String::from).collect();
        assert_eq!(lines[0], "round,hop,address,rtt_ms");
        assert_eq!(lines[1], "1,1,10.0.0.1,10.000");
        assert_eq!(lines[2], "2,1,10.0.0.1,"); // timeout → champ RTT vide
        assert_eq!(lines[3], "3,1,10.0.0.1,20.000");
    }

    #[test]
    fn csv_escape_quotes_commas() {
        assert_eq!(csv_escape("ab"), "ab");
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
        assert_eq!(csv_escape("a\"b"), "\"a\"\"b\"");
    }
}
