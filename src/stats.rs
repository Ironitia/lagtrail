//! Agrégation des mesures par saut et rapport texte.
//!
//! Partagé par l'interface graphique et le mode terminal (`--report`) :
//! aucune dépendance à egui ici.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

use crate::diagnosis::{self, Finding, HopStat, Severity};
use crate::engine::HopSample;

/// Nombre d'échantillons conservés par saut pour le graphe.
pub const HISTORY: usize = 600;
/// Nombre maximal d'adresses distinctes mémorisées par saut.
const MAX_ADDRS: usize = 8;

/// État agrégé d'un saut (cumule les tours successifs).
pub struct HopView {
    pub ttl: u8,
    pub addr: Option<IpAddr>,
    pub name: Option<String>,
    pub sent: u64,
    pub recv: u64,
    pub last: Option<f64>,
    pub best: f64,
    pub worst: f64,
    sum: f64,
    prev: Option<f64>,
    jitter_sum: f64,
    jitter_n: u64,
    /// Adresses distinctes ayant répondu à ce TTL (ordre d'apparition).
    pub addrs: Vec<IpAddr>,
    /// Nombre de fois où l'adresse répondante a changé (route instable).
    pub route_changes: u32,
    /// (x = secondes écoulées, y = RTT en ms ; None = timeout)
    pub history: VecDeque<(f64, Option<f64>)>,
}

impl HopView {
    pub fn new(ttl: u8) -> Self {
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
            addrs: Vec::new(),
            route_changes: 0,
            history: VecDeque::new(),
        }
    }

    pub fn loss_pct(&self) -> f64 {
        if self.sent == 0 {
            0.0
        } else {
            (self.sent - self.recv) as f64 / self.sent as f64 * 100.0
        }
    }

    pub fn avg(&self) -> Option<f64> {
        (self.recv > 0).then(|| self.sum / self.recv as f64)
    }

    pub fn jitter(&self) -> Option<f64> {
        (self.jitter_n > 0).then(|| self.jitter_sum / self.jitter_n as f64)
    }

    pub fn min(&self) -> Option<f64> {
        self.best.is_finite().then_some(self.best)
    }

    pub fn max(&self) -> Option<f64> {
        (self.worst > 0.0).then_some(self.worst)
    }

    /// Enregistre un échantillon. Renvoie `true` si l'adresse répondante a
    /// changé (première réponse comprise).
    pub fn record(&mut self, x: f64, s: &HopSample) -> bool {
        let mut changed = false;
        if let Some(a) = s.addr {
            if self.addr != Some(a) {
                if self.addr.is_some() {
                    self.route_changes += 1;
                }
                if !self.addrs.contains(&a) && self.addrs.len() < MAX_ADDRS {
                    self.addrs.push(a);
                }
                self.addr = Some(a);
                changed = true;
            }
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
        changed
    }
}

pub fn fmt_ms(v: Option<f64>) -> String {
    match v {
        Some(x) if x.is_finite() => format!("{x:.1}"),
        _ => "—".to_string(),
    }
}

/// Intègre un tour de mesures. `names` = cache DNS inverse (adresse → nom).
pub fn apply_round(
    hops: &mut Vec<HopView>,
    names: &HashMap<IpAddr, String>,
    x: f64,
    final_ttl: Option<u8>,
    samples: &[HopSample],
) {
    for s in samples {
        let idx = (s.ttl as usize).saturating_sub(1);
        while hops.len() <= idx {
            let ttl = (hops.len() + 1) as u8;
            hops.push(HopView::new(ttl));
        }
        let hop = &mut hops[idx];
        if hop.record(x, s) {
            // Nouvelle adresse à ce TTL : le nom affiché doit suivre.
            hop.name = hop.addr.and_then(|a| names.get(&a).cloned());
        }
    }
    if let Some(ft) = final_ttl {
        hops.truncate(ft as usize);
    }
}

/// Intègre un nom issu du DNS inverse.
pub fn apply_name(
    hops: &mut [HopView],
    names: &mut HashMap<IpAddr, String>,
    addr: IpAddr,
    name: String,
) {
    for h in hops.iter_mut().filter(|h| h.addr == Some(addr)) {
        h.name = Some(name.clone());
    }
    names.insert(addr, name);
}

/// Statistiques par saut au format attendu par le diagnostic.
pub fn hop_stats(hops: &[HopView]) -> Vec<HopStat> {
    hops.iter()
        .map(|h| HopStat {
            ttl: h.ttl,
            sent: h.sent,
            loss_pct: h.loss_pct(),
            avg_ms: h.avg(),
            jitter_ms: h.jitter(),
            route_changes: h.route_changes,
        })
        .collect()
}

/// Constats du diagnostic automatique.
pub fn findings(hops: &[HopView], reached: bool) -> Vec<Finding> {
    diagnosis::diagnose(&hop_stats(hops), reached)
}

/// Nombre de sauts utiles à afficher. Tant que la destination n'est pas
/// atteinte, les sondes vont jusqu'au TTL maximal : on masque la longue
/// traîne de sauts muets, en n'en gardant qu'un après le dernier répondant.
pub fn visible_len(hops: &[HopView], reached: bool) -> usize {
    if reached {
        return hops.len();
    }
    match hops.iter().rposition(|h| h.addr.is_some()) {
        Some(last) => (last + 2).min(hops.len()),
        None => hops.len().min(1),
    }
}

/// En-tête d'un rapport texte.
pub struct ReportMeta {
    pub target: String,
    pub addr: Option<IpAddr>,
    /// Ex. « ICMP » ou « TCP port 443 ».
    pub protocol: String,
    pub interval_secs: f32,
    pub elapsed_secs: f64,
}

/// Rapport texte : en-tête, tableau aligné, diagnostic.
pub fn text_report(meta: &ReportMeta, hops: &[HopView], reached: bool) -> String {
    let mut out = format!("lagtrail — rapport de trace vers {}", meta.target);
    if let Some(addr) = meta.addr {
        out.push_str(&format!(" ({addr})"));
    }
    let tours = hops.iter().map(|h| h.sent).max().unwrap_or(0);
    out.push_str(&format!(
        "\nProtocole : {} — {tours} tours, intervalle {} s — durée {:.0} s\n\n",
        meta.protocol, meta.interval_secs, meta.elapsed_secs
    ));
    out.push_str(&format!(
        "{:>3}  {:<39}  {:>6}  {:>8}  {:>8}  {:>8}  {:>8}  {}\n",
        "#", "Adresse", "Perte", "Moy.", "Min.", "Max.", "Gigue", "Nom"
    ));
    let shown = visible_len(hops, reached);
    for h in &hops[..shown] {
        let mut name = h.name.clone().unwrap_or_default();
        if h.route_changes > 0 {
            if !name.is_empty() {
                name.push(' ');
            }
            name.push_str(&format!("[route : {} changements]", h.route_changes));
        }
        out.push_str(&format!(
            "{:>3}  {:<39}  {:>5.1}%  {:>8}  {:>8}  {:>8}  {:>8}  {}\n",
            h.ttl,
            h.addr.map(|a| a.to_string()).unwrap_or_else(|| "*".into()),
            h.loss_pct(),
            fmt_ms(h.avg()),
            fmt_ms(h.min()),
            fmt_ms(h.max()),
            fmt_ms(h.jitter()),
            name,
        ));
    }
    if shown < hops.len() {
        out.push_str(&format!(
            "     … aucune réponse au-delà ({} sauts sondés)\n",
            hops.len()
        ));
    }
    let findings = findings(hops, reached);
    if !findings.is_empty() {
        out.push_str("\nDiagnostic :\n");
        for f in &findings {
            let tag = match f.severity {
                Severity::Ok => "OK",
                Severity::Info => "info",
                Severity::Warning => "ATTENTION",
                Severity::Critical => "CRITIQUE",
            };
            out.push_str(&format!("  [{tag}] {}\n", f.text));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(ttl: u8, ip: [u8; 4], rtt: Option<f64>) -> HopSample {
        HopSample { ttl, addr: Some(IpAddr::from(ip)), rtt_ms: rtt }
    }

    #[test]
    fn route_changes_are_counted_and_names_follow() {
        let a = IpAddr::from([10, 0, 0, 1]);
        let b = IpAddr::from([10, 0, 0, 2]);
        let mut hops = Vec::new();
        let mut names = HashMap::new();
        apply_round(&mut hops, &names, 1.0, None, &[sample(1, [10, 0, 0, 1], Some(5.0))]);
        apply_name(&mut hops, &mut names, a, "a.example".into());
        assert_eq!(hops[0].name.as_deref(), Some("a.example"));
        assert_eq!(hops[0].route_changes, 0);

        // Bascule vers b (nom encore inconnu), puis retour vers a (nom en cache).
        apply_round(&mut hops, &names, 2.0, None, &[sample(1, [10, 0, 0, 2], Some(6.0))]);
        assert_eq!(hops[0].name, None);
        apply_round(&mut hops, &names, 3.0, None, &[sample(1, [10, 0, 0, 1], Some(5.0))]);
        assert_eq!(hops[0].name.as_deref(), Some("a.example"));
        assert_eq!(hops[0].route_changes, 2);
        assert_eq!(hops[0].addrs, vec![a, b]);
    }

    #[test]
    fn final_ttl_truncates_extra_hops() {
        let mut hops = Vec::new();
        let names = HashMap::new();
        let round: Vec<HopSample> = (1..=5).map(|t| sample(t, [10, 0, 0, t], Some(1.0))).collect();
        apply_round(&mut hops, &names, 1.0, None, &round);
        assert_eq!(hops.len(), 5);
        apply_round(&mut hops, &names, 2.0, Some(3), &round[..3]);
        assert_eq!(hops.len(), 3);
    }

    #[test]
    fn unreached_path_hides_trailing_silent_hops() {
        let mut hops = Vec::new();
        let names = HashMap::new();
        let mut round = vec![sample(1, [10, 0, 0, 1], Some(1.0)), sample(2, [10, 0, 0, 2], Some(2.0))];
        round.extend((3..=30).map(|ttl| HopSample { ttl, addr: None, rtt_ms: None }));
        apply_round(&mut hops, &names, 1.0, None, &round);
        assert_eq!(hops.len(), 30);
        assert_eq!(visible_len(&hops, false), 3);
        assert_eq!(visible_len(&hops, true), 30);
        let meta = ReportMeta {
            target: "x".into(),
            addr: None,
            protocol: "ICMP".into(),
            interval_secs: 1.0,
            elapsed_secs: 1.0,
        };
        assert!(text_report(&meta, &hops, false).contains("aucune réponse au-delà (30 sauts sondés)"));
    }

    #[test]
    fn text_report_contains_table_and_diagnosis() {
        let mut hops = Vec::new();
        let names = HashMap::new();
        for i in 0..12 {
            apply_round(&mut hops, &names, i as f64, Some(1), &[sample(1, [10, 0, 0, 1], Some(5.0))]);
        }
        let meta = ReportMeta {
            target: "exemple.net".into(),
            addr: None,
            protocol: "ICMP".into(),
            interval_secs: 1.0,
            elapsed_secs: 12.0,
        };
        let r = text_report(&meta, &hops, true);
        assert!(r.starts_with("lagtrail — rapport de trace vers exemple.net"));
        assert!(r.contains("10.0.0.1"));
        assert!(r.contains("[OK] Chemin sain"));
    }
}
