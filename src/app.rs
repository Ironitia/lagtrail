//! Interface graphique (egui / eframe).
//!
//! L'appli gère **plusieurs traces simultanées** : chaque onglet est une
//! `Session` indépendante (sa cible, son thread moteur, ses mesures). Un
//! sélecteur de thème clair/sombre/auto est disponible en haut.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::mpsc::{self, Receiver, Sender};
use std::time::{Duration, Instant};

use eframe::egui;
use egui_extras::{Column, TableBuilder};
use egui_plot::{HLine, Legend, Line, Plot, PlotPoints, Points};

use crate::config::{self, SavedState, TraceConfig};
use crate::diagnosis::{Finding, Severity};
use crate::engine::{self, EngineCmd, EngineMsg, ProbeProtocol};
use crate::stats::{self, HopView, ReportMeta, fmt_ms};

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

/// Couleur et pictogramme associés à une gravité de diagnostic.
fn severity_style(sev: Severity) -> (egui::Color32, &'static str) {
    match sev {
        Severity::Ok => (egui::Color32::from_rgb(90, 180, 110), "✔"),
        Severity::Info => (egui::Color32::from_rgb(120, 160, 210), "ℹ"),
        Severity::Warning => (egui::Color32::from_rgb(235, 140, 40), "⚠"),
        Severity::Critical => (egui::Color32::from_rgb(225, 80, 80), "⛔"),
    }
}

/// Intervalles prédéfinis (libellé, secondes) — du temps réel à la veille longue.
const INTERVAL_PRESETS: [(&str, f32); 8] = [
    ("0,5 s", 0.5),
    ("1 s", 1.0),
    ("2,5 s", 2.5),
    ("5 s", 5.0),
    ("15 s", 15.0),
    ("1 min", 60.0),
    ("5 min", 300.0),
    ("15 min", 900.0),
];

fn fmt_interval(secs: f32) -> String {
    if secs >= 60.0 {
        format!("{:.0} min", secs / 60.0)
    } else {
        format!("{secs} s")
    }
}

/// Dessine la plage min–max d'un saut (trait fin) et sa moyenne (pastille),
/// à l'échelle `scale_ms` commune à tout le tableau.
fn latency_bar(ui: &mut egui::Ui, hop: &HopView, scale_ms: f64, color: egui::Color32) {
    let (rect, _) = ui.allocate_exact_size(
        egui::vec2(ui.available_width().max(40.0), 12.0),
        egui::Sense::hover(),
    );
    let Some(avg) = hop.avg() else { return };
    if scale_ms <= 0.0 {
        return;
    }
    let x = |ms: f64| rect.left() + (ms / scale_ms).clamp(0.0, 1.0) as f32 * rect.width();
    let y = rect.center().y;
    let p = ui.painter();
    p.line_segment(
        [egui::pos2(x(hop.best), y), egui::pos2(x(hop.worst), y)],
        egui::Stroke::new(2.0, color.gamma_multiply(0.55)),
    );
    p.circle_filled(egui::pos2(x(avg), y), 3.5, color);
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
    /// Cache DNS inverse de la trace (adresse → nom).
    names: HashMap<IpAddr, String>,
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
            names: HashMap::new(),
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
        let dot = if self.running { "⏺ " } else { "" };
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

    /// Constats du diagnostic automatique pour l'état courant.
    fn findings(&self) -> Vec<Finding> {
        stats::findings(&self.hops, self.final_ttl.is_some())
    }

    /// Nom affichable de la cible (résolue si possible, sinon la saisie).
    fn target_name(&self) -> String {
        self.resolved
            .as_ref()
            .map(|(t, _)| t.clone())
            .unwrap_or_else(|| self.target_input.trim().to_string())
    }

    /// Rapport texte : en-tête, tableau aligné, diagnostic.
    fn text_report(&self) -> String {
        let meta = ReportMeta {
            target: self.target_name(),
            addr: self.resolved.as_ref().map(|(_, a)| *a),
            protocol: self.protocol.describe(self.port),
            interval_secs: self.interval_secs,
            elapsed_secs: self.x,
        };
        stats::text_report(&meta, &self.hops, self.final_ttl.is_some())
    }

    /// Réglages mémorisables de cet onglet.
    fn to_config(&self) -> TraceConfig {
        TraceConfig {
            target: self.target_input.trim().to_string(),
            protocol: self.protocol,
            port: self.port,
            interval_secs: self.interval_secs,
            max_hops: self.max_hops,
            prefer_v6: self.prefer_v6,
            alerts_on: self.alerts_on,
            alert_latency: self.alert_latency,
            alert_loss: self.alert_loss,
        }
    }

    fn from_config(ctx: &egui::Context, c: &TraceConfig) -> Self {
        let mut s = Session::new(ctx, c.target.clone());
        s.protocol = c.protocol;
        s.port = c.port;
        s.interval_secs = c.interval_secs;
        s.max_hops = c.max_hops;
        s.prefer_v6 = c.prefer_v6;
        s.alerts_on = c.alerts_on;
        s.alert_latency = c.alert_latency;
        s.alert_loss = c.alert_loss;
        s
    }

    fn start(&mut self) {
        let target = self.target_input.trim().to_string();
        if target.is_empty() {
            self.error = Some("Indique une cible (nom d'hôte ou adresse IP).".into());
            return;
        }
        self.error = None;
        self.hops.clear();
        self.names.clear();
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
                    stats::apply_round(&mut self.hops, &self.names, self.x, final_ttl, &samples);
                    if let Some(ft) = final_ttl {
                        // Le saut final peut encore reculer aux tours suivants
                        // (réponse de la destination perdue au premier tour) :
                        // une sélection devenue hors limites suit la destination.
                        let last = (ft as usize).saturating_sub(1);
                        if self.selected.is_none_or(|i| i >= self.hops.len()) {
                            self.selected = Some(last.min(self.hops.len().saturating_sub(1)));
                        }
                    }
                }
                EngineMsg::HopName { addr, name } => {
                    stats::apply_name(&mut self.hops, &mut self.names, addr, name);
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
                    .range(0.2..=3600.0)
                    .speed(0.05)
                    .suffix(" s"),
            )
            .on_hover_text("Pris en compte au prochain démarrage");
            egui::ComboBox::from_id_salt("interval_preset")
                .selected_text(fmt_interval(self.interval_secs))
                .width(70.0)
                .show_ui(ui, |ui| {
                    for (label, secs) in INTERVAL_PRESETS {
                        ui.selectable_value(&mut self.interval_secs, secs, label);
                    }
                });
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
                .add_enabled(has, egui::Button::new("💾 Résumé CSV"))
                .on_hover_text("Exporter le tableau actuel (une ligne par saut)")
                .clicked()
            {
                self.export_summary();
            }
            if ui
                .add_enabled(has, egui::Button::new("💾 Historique CSV"))
                .on_hover_text("Exporter toute la série temporelle (tour × saut)")
                .clicked()
            {
                self.export_history();
            }
            if ui
                .add_enabled(has, egui::Button::new("📋 Copier le rapport"))
                .on_hover_text(
                    "Copie un rapport texte (tableau + diagnostic) prêt à coller \
                     dans un ticket de support ou un e-mail",
                )
                .clicked()
            {
                ui.ctx().copy_text(self.text_report());
                self.status = "Rapport copié dans le presse-papiers.".to_string();
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
        let findings = self.findings();
        if !findings.is_empty() {
            ui.add_space(2.0);
            egui::CollapsingHeader::new(egui::RichText::new("Diagnostic").strong())
                .default_open(true)
                .show(ui, |ui| {
                    for f in &findings {
                        let (color, icon) = severity_style(f.severity);
                        ui.horizontal_wrapped(|ui| {
                            ui.colored_label(color, icon);
                            let resp = ui.add(
                                egui::Label::new(&f.text).sense(egui::Sense::click()),
                            );
                            if let Some(ttl) = f.ttl {
                                if resp
                                    .on_hover_text(format!("Clique pour afficher le saut #{ttl}"))
                                    .clicked()
                                {
                                    self.selected = Some(ttl as usize - 1);
                                }
                            }
                        });
                    }
                });
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
        // Destination non atteinte : on masque la traîne de sauts muets.
        let shown = stats::visible_len(&self.hops, self.final_ttl.is_some());
        let hops = &self.hops[..shown];
        let mut new_sel = self.selected;
        // Échelle commune des barres : pire latence du chemin (les routeurs
        // anormalement lents écrasent sinon tout le reste → plafonnée).
        let dest_worst = hops.last().map(|h| h.worst).unwrap_or(0.0);
        let scale_ms = hops
            .iter()
            .map(|h| h.worst)
            .fold(0.0, f64::max)
            .min((dest_worst * 3.0).max(50.0));

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
            .column(Column::exact(130.0))
            .header(row_h, |mut h| {
                for t in [
                    "#", "Adresse", "Nom", "Perte", "Dern.", "Moy.", "Min.", "Max.", "Gigue",
                    "Min — moy — max",
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
                            if hop.route_changes > 0 {
                                let seen = hop
                                    .addrs
                                    .iter()
                                    .map(|a| a.to_string())
                                    .collect::<Vec<_>>()
                                    .join("\n");
                                ui.label(egui::RichText::new("🔀").weak()).on_hover_text(format!(
                                    "Route instable : {} changement(s) d'adresse à ce saut.\n\
                                     Adresses vues :\n{seen}",
                                    hop.route_changes
                                ));
                            }
                        });
                        row.col(|ui| {
                            let s = hop
                                .name
                                .clone()
                                .or_else(|| hop.addr.map(|a| a.to_string()))
                                .unwrap_or_else(|| {
                                    if hop.sent >= 3 { "(ne répond pas)" } else { "(en attente)" }
                                        .into()
                                });
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
                            ui.label(fmt_ms(hop.min()));
                        });
                        row.col(|ui| {
                            ui.label(fmt_ms(hop.max()));
                        });
                        row.col(|ui| {
                            ui.label(fmt_ms(hop.jitter()));
                        });
                        row.col(|ui| {
                            let color = if alerting.contains(&hop.ttl) {
                                egui::Color32::from_rgb(235, 140, 40)
                            } else {
                                loss_color(hop.loss_pct())
                            };
                            latency_bar(ui, hop, scale_ms, color);
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
            "hop,address,hostname,sent,recv,loss_pct,last_ms,avg_ms,min_ms,max_ms,jitter_ms,route_changes\n",
        );
        for h in &self.hops {
            let addr = h.addr.map(|a| a.to_string()).unwrap_or_default();
            let name = h.name.clone().unwrap_or_default();
            out.push_str(&format!(
                "{},{},{},{},{},{:.2},{},{},{},{},{},{}\n",
                h.ttl,
                csv_escape(&addr),
                csv_escape(&name),
                h.sent,
                h.recv,
                h.loss_pct(),
                f(h.last),
                f(h.avg()),
                f(h.min()),
                f(h.max()),
                f(h.jitter()),
                h.route_changes,
            ));
        }
        out
    }

    /// CSV « historique » : une ligne par (instant, saut), format long ;
    /// `elapsed_s` = secondes écoulées depuis le démarrage de la trace.
    fn history_csv(&self) -> String {
        let mut out = String::from("elapsed_s,hop,address,rtt_ms\n");
        for h in &self.hops {
            let addr = csv_escape(&h.addr.map(|a| a.to_string()).unwrap_or_default());
            for (x, y) in &h.history {
                let rtt = y.map(|v| format!("{v:.3}")).unwrap_or_default();
                out.push_str(&format!("{x:.3},{},{},{}\n", h.ttl, addr, rtt));
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
        let target = self.target_name();
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
    Overview,
}

pub struct App {
    sessions: Vec<Session>,
    active: usize,
    /// Affiche la vue d'ensemble (toutes les cibles) au lieu d'une trace.
    overview: bool,
    theme: egui::ThemePreference,
    /// Mémoriser les onglets à la fermeture (désactivé quand des cibles ont
    /// été passées en ligne de commande : lancement ponctuel).
    persist: bool,
}

impl App {
    /// `targets` : cibles passées en ligne de commande. Elles démarrent
    /// d'elles-mêmes ; à partir de deux, on ouvre sur la vue d'ensemble.
    pub fn new(ctx: &egui::Context, targets: Vec<String>) -> Self {
        let mut sessions: Vec<Session> = targets
            .iter()
            .map(|target| {
                let mut session = Session::new(ctx, target.clone());
                // La cible spéciale « demo » (aucun privilège requis) reçoit
                // des alertes pré-réglées pour illustrer la fonction.
                if target.eq_ignore_ascii_case("demo") {
                    session.alerts_on = true;
                    session.alert_latency = 55.0;
                    session.alert_loss = 8.0;
                }
                session.start();
                session
            })
            .collect();
        // Sans cible explicite : on rouvre les onglets de la dernière fois
        // (sans les démarrer — aucune sonde ne part sans action de ta part).
        let mut theme = egui::ThemePreference::System;
        let restore = sessions.is_empty();
        if let Some(saved) = config::load() {
            theme = match saved.theme.as_str() {
                "light" => egui::ThemePreference::Light,
                "dark" => egui::ThemePreference::Dark,
                _ => egui::ThemePreference::System,
            };
            ctx.set_theme(theme);
            if restore {
                sessions = saved.traces.iter().map(|c| Session::from_config(ctx, c)).collect();
            }
        }
        if sessions.is_empty() {
            sessions.push(Session::new(ctx, "1.1.1.1".to_string()));
        }
        Self {
            overview: sessions.len() > 1,
            sessions,
            active: 0,
            theme,
            persist: restore,
        }
    }

    /// État à mémoriser (les onglets « demo » ou vides sont ignorés).
    fn saved_state(&self) -> SavedState {
        SavedState {
            theme: match self.theme {
                egui::ThemePreference::Light => "light",
                egui::ThemePreference::Dark => "dark",
                egui::ThemePreference::System => "system",
            }
            .to_string(),
            traces: self
                .sessions
                .iter()
                .map(Session::to_config)
                .filter(|c| !c.target.is_empty() && !c.target.eq_ignore_ascii_case("demo"))
                .collect(),
        }
    }

    fn apply_tab_action(&mut self, action: TabAction, ctx: &egui::Context) {
        match action {
            TabAction::Select(i) => {
                self.active = i;
                self.overview = false;
            }
            TabAction::Overview => self.overview = true,
            TabAction::Add => {
                self.overview = false;
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

    /// Tableau de synthèse : une ligne par cible. Renvoie l'index de la
    /// session à ouvrir si une ligne a été cliquée.
    fn overview_table(&mut self, ui: &mut egui::Ui) -> Option<usize> {
        let mut open = None;
        let row_h = egui::TextStyle::Body.resolve(ui.style()).size + 10.0;
        TableBuilder::new(ui)
            .striped(true)
            .sense(egui::Sense::click())
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::initial(180.0).at_least(120.0))
            .column(Column::exact(80.0))
            .column(Column::exact(60.0))
            .column(Column::exact(60.0))
            .column(Column::exact(70.0))
            .column(Column::exact(70.0))
            .column(Column::exact(70.0))
            .column(Column::remainder().at_least(200.0))
            .header(row_h, |mut h| {
                for t in ["Cible", "État", "Proto.", "Sauts", "Perte", "Moy.", "Gigue", "Diagnostic"] {
                    h.col(|ui| {
                        ui.strong(t);
                    });
                }
            })
            .body(|mut body| {
                for (i, s) in self.sessions.iter().enumerate() {
                    let dest = s.final_ttl.and(s.hops.last());
                    let findings = s.findings();
                    body.row(row_h, |mut row| {
                        row.col(|ui| {
                            ui.strong(s.target_name());
                        });
                        row.col(|ui| {
                            if s.running {
                                ui.colored_label(loss_color(0.0), "⏺ en cours");
                            } else if s.error.is_some() {
                                ui.colored_label(loss_color(100.0), "erreur");
                            } else {
                                ui.weak("arrêtée");
                            }
                        });
                        row.col(|ui| {
                            ui.label(s.protocol.label());
                        });
                        row.col(|ui| {
                            ui.label(if s.hops.is_empty() {
                                "—".to_string()
                            } else {
                                s.hops.len().to_string()
                            });
                        });
                        row.col(|ui| match dest {
                            Some(d) => {
                                let pct = d.loss_pct();
                                ui.colored_label(loss_color(pct), format!("{pct:.1} %"));
                            }
                            None => {
                                ui.label("—");
                            }
                        });
                        row.col(|ui| {
                            ui.label(fmt_ms(dest.and_then(|d| d.avg())));
                        });
                        row.col(|ui| {
                            ui.label(fmt_ms(dest.and_then(|d| d.jitter())));
                        });
                        row.col(|ui| {
                            if let Some(err) = &s.error {
                                let first = err.lines().next().unwrap_or_default();
                                ui.add(
                                    egui::Label::new(
                                        egui::RichText::new(first).color(loss_color(100.0)),
                                    )
                                    .truncate(),
                                )
                                .on_hover_text(err);
                            } else if let Some(f) = findings.first() {
                                let (color, icon) = severity_style(f.severity);
                                ui.colored_label(color, icon);
                                ui.add(egui::Label::new(&f.text).truncate())
                                    .on_hover_text(&f.text);
                            } else {
                                ui.weak("—");
                            }
                        });
                        if row.response().clicked() {
                            open = Some(i);
                        }
                    });
                }
            });
        open
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
                if ui
                    .selectable_label(self.overview, "📊 Vue d'ensemble")
                    .on_hover_text("État de toutes les cibles en un coup d'œil")
                    .clicked()
                {
                    action = Some(TabAction::Overview);
                }
                ui.separator();
                for i in 0..self.sessions.len() {
                    let selected = !self.overview && self.active == i;
                    if ui
                        .selectable_label(selected, self.sessions[i].tab_label())
                        .clicked()
                    {
                        action = Some(TabAction::Select(i));
                    }
                    if ui.small_button("❌").on_hover_text("Fermer cette trace").clicked() {
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

impl Drop for App {
    fn drop(&mut self) {
        if self.persist {
            let _ = config::save(&self.saved_state());
        }
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

        if self.overview {
            let mut open: Option<usize> = None;
            egui::CentralPanel::default().show(ui, |ui| open = self.overview_table(ui));
            if let Some(i) = open {
                self.active = i;
                self.overview = false;
            }
            if any_running {
                ui.ctx().request_repaint_after(Duration::from_millis(200));
            }
            return;
        }

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
    use crate::stats::HopView;

    fn hop_with_samples() -> HopView {
        let mut h = HopView::new(1);
        let ip = IpAddr::from([10, 0, 0, 1]);
        h.record(1.0, &HopSample { ttl: 1, addr: Some(ip), rtt_ms: Some(10.0) });
        h.record(2.0, &HopSample { ttl: 1, addr: Some(ip), rtt_ms: None }); // perte
        h.record(3.0, &HopSample { ttl: 1, addr: Some(ip), rtt_ms: Some(20.0) });
        h.name = Some("routeur.local".to_string());
        h
    }

    #[test]
    fn summary_csv_header_and_stats() {
        let mut s = Session::new(&egui::Context::default(), "x".into());
        s.hops.push(hop_with_samples());
        let lines: Vec<String> = s.summary_csv().lines().map(String::from).collect();
        assert_eq!(
            lines[0],
            "hop,address,hostname,sent,recv,loss_pct,last_ms,avg_ms,min_ms,max_ms,jitter_ms,route_changes"
        );
        // 3 envoyés, 2 reçus → perte 33,33 % ; min 10 / max 20 / moy 15 / gigue 10
        assert_eq!(
            lines[1],
            "1,10.0.0.1,routeur.local,3,2,33.33,20.000,15.000,10.000,20.000,10.000,0"
        );
    }

    #[test]
    fn history_csv_marks_timeouts_empty() {
        let mut s = Session::new(&egui::Context::default(), "x".into());
        s.hops.push(hop_with_samples());
        let lines: Vec<String> = s.history_csv().lines().map(String::from).collect();
        assert_eq!(lines[0], "elapsed_s,hop,address,rtt_ms");
        assert_eq!(lines[1], "1.000,1,10.0.0.1,10.000");
        assert_eq!(lines[2], "2.000,1,10.0.0.1,"); // timeout → champ RTT vide
        assert_eq!(lines[3], "3.000,1,10.0.0.1,20.000");
    }

    #[test]
    fn csv_escape_quotes_commas() {
        assert_eq!(csv_escape("ab"), "ab");
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
        assert_eq!(csv_escape("a\"b"), "\"a\"\"b\"");
    }
}
