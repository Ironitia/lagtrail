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

    /// 95ᵉ centile de la latence sur l'historique conservé : ce que vaut la
    /// latence « dans les mauvais moments », que la moyenne masque.
    pub fn p95(&self) -> Option<f64> {
        let mut v: Vec<f64> = self.history.iter().filter_map(|p| p.1).collect();
        if v.is_empty() {
            return None;
        }
        v.sort_by(f64::total_cmp);
        let rank = (v.len() as f64 * 0.95).ceil() as usize;
        Some(v[rank.clamp(1, v.len()) - 1])
    }

    /// Retient l'adresse qui a répondu, sans toucher aux statistiques.
    /// Renvoie `true` si elle a changé (première réponse comprise).
    pub fn note_addr(&mut self, addr: Option<IpAddr>) -> bool {
        let Some(a) = addr else { return false };
        if self.addr == Some(a) {
            return false;
        }
        if self.addr.is_some() {
            self.route_changes += 1;
        }
        if !self.addrs.contains(&a) && self.addrs.len() < MAX_ADDRS {
            self.addrs.push(a);
        }
        self.addr = Some(a);
        true
    }

    /// Enregistre un échantillon. Renvoie `true` si l'adresse répondante a
    /// changé (première réponse comprise).
    pub fn record(&mut self, x: f64, s: &HopSample) -> bool {
        let changed = self.note_addr(s.addr);
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

/// Formate une durée écoulée : `+MM:SS` ou `+H:MM:SS`.
pub fn fmt_elapsed(secs: f64) -> String {
    let t = secs.max(0.0) as u64;
    let (h, m, s) = (t / 3600, t / 60 % 60, t % 60);
    if h > 0 {
        format!("+{h}:{m:02}:{s:02}")
    } else {
        format!("+{m:02}:{s:02}")
    }
}

/// Événement daté du journal d'une trace.
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    /// Secondes écoulées depuis le démarrage de la trace.
    pub t: f64,
    pub severity: Severity,
    pub text: String,
}

/// Nombre maximal d'événements conservés.
const MAX_EVENTS: usize = 500;
/// Pertes consécutives à destination à partir desquelles on parle de coupure.
const OUTAGE_STREAK: u32 = 3;
/// Changements de route journalisés par saut avant de se taire (alternance).
const ROUTE_LOG_LIMIT: u32 = 3;
/// Délai minimal entre deux pics de latence journalisés (s).
const SPIKE_COOLDOWN: f64 = 10.0;

/// Journal des événements marquants : coupures, pics, changements de route.
/// Répond à « que s'est-il passé, et quand ? » sur une longue surveillance.
#[derive(Default)]
pub struct Journal {
    pub events: Vec<Event>,
    /// Nombre total d'événements émis (y compris ceux déjà évincés).
    pub total: u64,
    dest_streak: u32,
    streak_start: f64,
    in_outage: bool,
    last_spike: Option<f64>,
    route_logged: HashMap<u8, u32>,
    outage_count: u32,
    /// Durée cumulée et plus longue durée des coupures terminées (s).
    downtime: f64,
    longest: f64,
}

/// Bilan des coupures à destination sur la durée d'une trace.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Outages {
    pub count: u32,
    pub downtime_s: f64,
    pub longest_s: f64,
    /// Une coupure est en cours au moment du bilan.
    pub ongoing: bool,
    /// Part du temps où la destination répondait (hors coupures).
    pub availability_pct: f64,
}

impl Outages {
    /// Phrase de bilan, ex. « 2 coupures, 14 s cumulées (la plus longue : 9 s) ».
    pub fn describe(&self) -> String {
        if self.count == 0 {
            return "aucune coupure à destination".to_string();
        }
        let mut out = format!(
            "disponibilité {:.1} % — {} coupure{}, {:.0} s cumulées",
            self.availability_pct,
            self.count,
            if self.count > 1 { "s" } else { "" },
            self.downtime_s
        );
        if self.count > 1 {
            out.push_str(&format!(" (la plus longue : {:.0} s)", self.longest_s));
        }
        if self.ongoing {
            out.push_str(", coupure en cours");
        }
        out
    }
}

impl Journal {
    /// Bilan des coupures à l'instant `now` (secondes depuis le démarrage).
    pub fn outages(&self, now: f64) -> Outages {
        let current = if self.in_outage { (now - self.streak_start).max(0.0) } else { 0.0 };
        let downtime_s = self.downtime + current;
        Outages {
            count: self.outage_count,
            downtime_s,
            longest_s: self.longest.max(current),
            ongoing: self.in_outage,
            availability_pct: if now > 0.0 {
                (100.0 * (1.0 - downtime_s / now)).clamp(0.0, 100.0)
            } else {
                100.0
            },
        }
    }

    pub fn push(&mut self, t: f64, severity: Severity, text: String) {
        if self.events.len() >= MAX_EVENTS {
            self.events.remove(0);
        }
        self.events.push(Event { t, severity, text });
        self.total += 1;
    }

    fn route_change(&mut self, t: f64, ttl: u8, from: IpAddr, to: IpAddr) {
        let n = self.route_logged.entry(ttl).or_insert(0);
        *n += 1;
        let n = *n;
        if n <= ROUTE_LOG_LIMIT {
            self.push(t, Severity::Info, format!("Saut #{ttl} : route modifiée, {from} → {to}"));
        } else if n == ROUTE_LOG_LIMIT + 1 {
            self.push(
                t,
                Severity::Info,
                format!("Saut #{ttl} : la route alterne régulièrement (suite non journalisée)"),
            );
        }
    }

    /// Suit la destination : coupures (pertes consécutives) et pics de latence.
    fn destination(&mut self, t: f64, rtt: Option<f64>, avg: Option<f64>, samples: u64) {
        match rtt {
            None => {
                if self.dest_streak == 0 {
                    self.streak_start = t;
                }
                self.dest_streak += 1;
                if self.dest_streak == OUTAGE_STREAK && !self.in_outage {
                    self.in_outage = true;
                    self.outage_count += 1;
                    let since = fmt_elapsed(self.streak_start);
                    self.push(
                        t,
                        Severity::Critical,
                        format!("Destination injoignable depuis {since} ({OUTAGE_STREAK} pertes d'affilée)"),
                    );
                }
            }
            Some(rtt) => {
                if self.in_outage {
                    let lasted = t - self.streak_start;
                    self.downtime += lasted;
                    self.longest = self.longest.max(lasted);
                    self.push(
                        t,
                        Severity::Ok,
                        format!(
                            "Destination rétablie après {:.0} s de coupure ({} paquets perdus)",
                            t - self.streak_start,
                            self.dest_streak
                        ),
                    );
                }
                self.in_outage = false;
                self.dest_streak = 0;
                if let Some(avg) = avg {
                    let spike = samples >= 10 && rtt > avg * 3.0 && rtt > avg + 50.0;
                    let cooled = self.last_spike.is_none_or(|l| t - l >= SPIKE_COOLDOWN);
                    if spike && cooled {
                        self.last_spike = Some(t);
                        self.push(
                            t,
                            Severity::Warning,
                            format!("Pic de latence à destination : {rtt:.0} ms (moyenne {avg:.0} ms)"),
                        );
                    }
                }
            }
        }
    }
}

/// Intègre un tour de mesures. `names` = cache DNS inverse (adresse → nom).
/// Variante sans journal ni tour de découverte (tests, usages simples).
#[cfg(test)]
pub fn apply_round(
    hops: &mut Vec<HopView>,
    names: &HashMap<IpAddr, String>,
    x: f64,
    final_ttl: Option<u8>,
    samples: &[HopSample],
) {
    apply_round_ex(hops, names, &mut Journal::default(), x, final_ttl, samples, false);
}

/// Intègre un tour de mesures et alimente le journal.
///
/// `warmup` : tour de découverte — on retient les adresses (le chemin
/// s'affiche tout de suite) mais pas les mesures, faussées par la rafale de
/// sondes reçue par la destination.
pub fn apply_round_ex(
    hops: &mut Vec<HopView>,
    names: &HashMap<IpAddr, String>,
    journal: &mut Journal,
    x: f64,
    final_ttl: Option<u8>,
    samples: &[HopSample],
    warmup: bool,
) {
    for s in samples {
        let idx = (s.ttl as usize).saturating_sub(1);
        while hops.len() <= idx {
            let ttl = (hops.len() + 1) as u8;
            hops.push(HopView::new(ttl));
        }
        let hop = &mut hops[idx];
        let before = hop.addr;
        let changed = if warmup { hop.note_addr(s.addr) } else { hop.record(x, s) };
        if changed {
            // Nouvelle adresse à ce TTL : le nom affiché doit suivre.
            hop.name = hop.addr.and_then(|a| names.get(&a).cloned());
            if let (Some(from), Some(to)) = (before, hop.addr) {
                journal.route_change(x, hop.ttl, from, to);
            }
        }
    }
    if let Some(ft) = final_ttl {
        hops.truncate(ft as usize);
        if !warmup {
            if let (Some(dest), Some(s)) = (hops.last(), samples.iter().find(|s| s.ttl == ft)) {
                journal.destination(x, s.rtt_ms, dest.avg(), dest.recv);
            }
        }
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

/// État d'une cible pour la comparaison entre cibles (`compare_targets`).
pub fn target_health(name: &str, hops: &[HopView], reached: bool) -> diagnosis::TargetHealth {
    diagnosis::TargetHealth {
        name: name.to_string(),
        severity: diagnosis::worst(&findings(hops, reached)),
        reached,
        path: hops.iter().map(|h| h.addr).collect(),
    }
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
pub fn text_report(
    meta: &ReportMeta,
    hops: &[HopView],
    reached: bool,
    journal: &Journal,
) -> String {
    let events = &journal.events[..];
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
        "{:>3}  {:<39}  {:>6}  {:>8}  {:>8}  {:>8}  {:>8}  {:>8}  {}\n",
        "#", "Adresse", "Perte", "Moy.", "Min.", "Max.", "P95", "Gigue", "Nom"
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
            "{:>3}  {:<39}  {:>5.1}%  {:>8}  {:>8}  {:>8}  {:>8}  {:>8}  {}\n",
            h.ttl,
            h.addr.map(|a| a.to_string()).unwrap_or_else(|| "*".into()),
            h.loss_pct(),
            fmt_ms(h.avg()),
            fmt_ms(h.min()),
            fmt_ms(h.max()),
            fmt_ms(h.p95()),
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
    if reached || journal.outage_count > 0 {
        let o = journal.outages(meta.elapsed_secs);
        out.push_str(&format!("\nCoupures : {}\n", o.describe()));
    }
    if !events.is_empty() {
        const SHOWN: usize = 30;
        out.push_str("\nÉvénements :\n");
        if events.len() > SHOWN {
            out.push_str(&format!("  … {} plus anciens omis\n", events.len() - SHOWN));
        }
        for e in &events[events.len().saturating_sub(SHOWN)..] {
            out.push_str(&format!("  {:>8}  {}\n", fmt_elapsed(e.t), e.text));
        }
    }
    out
}

/// Horodatage UTC ISO 8601 (`2026-11-12T08:15:02Z`), sans dépendance.
pub fn fmt_utc(t: std::time::SystemTime) -> String {
    let secs = t
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Jours depuis l'époque → date civile (algorithme de H. Hinnant).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    )
}

/// Chaîne JSON échappée, guillemets compris.
pub fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn json_num(v: Option<f64>) -> String {
    match v {
        Some(x) if x.is_finite() => format!("{x:.3}"),
        _ => "null".to_string(),
    }
}

fn severity_key(s: Severity) -> &'static str {
    match s {
        Severity::Ok => "ok",
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::Critical => "critical",
    }
}

/// Rapport JSON (mêmes données que le rapport texte), pour les scripts.
pub fn json_report(
    meta: &ReportMeta,
    hops: &[HopView],
    reached: bool,
    journal: &Journal,
) -> String {
    let events = &journal.events[..];
    let o = journal.outages(meta.elapsed_secs);
    let outages = format!(
        "{{\"count\": {}, \"downtime_s\": {:.1}, \"longest_s\": {:.1}, \"ongoing\": {}, \
         \"availability_pct\": {:.2}}}",
        o.count, o.downtime_s, o.longest_s, o.ongoing, o.availability_pct
    );
    let findings = findings(hops, reached);
    let opt_str = |v: Option<String>| v.map(|s| json_str(&s)).unwrap_or_else(|| "null".into());
    let hop_rows: Vec<String> = hops[..visible_len(hops, reached)]
        .iter()
        .map(|h| {
            format!(
                "    {{\"hop\": {}, \"address\": {}, \"hostname\": {}, \"sent\": {}, \"recv\": {}, \
                 \"loss_pct\": {:.2}, \"avg_ms\": {}, \"min_ms\": {}, \"max_ms\": {}, \
                 \"p95_ms\": {}, \"jitter_ms\": {}, \"route_changes\": {}}}",
                h.ttl,
                opt_str(h.addr.map(|a| a.to_string())),
                opt_str(h.name.clone()),
                h.sent,
                h.recv,
                h.loss_pct(),
                json_num(h.avg()),
                json_num(h.min()),
                json_num(h.max()),
                json_num(h.p95()),
                json_num(h.jitter()),
                h.route_changes,
            )
        })
        .collect();
    let finding_rows: Vec<String> = findings
        .iter()
        .map(|f| {
            format!(
                "    {{\"severity\": \"{}\", \"hop\": {}, \"text\": {}}}",
                severity_key(f.severity),
                f.ttl.map(|t| t.to_string()).unwrap_or_else(|| "null".into()),
                json_str(&f.text),
            )
        })
        .collect();
    let event_rows: Vec<String> = events
        .iter()
        .map(|e| {
            format!(
                "    {{\"t_s\": {:.1}, \"severity\": \"{}\", \"text\": {}}}",
                e.t,
                severity_key(e.severity),
                json_str(&e.text),
            )
        })
        .collect();
    let block = |rows: Vec<String>| {
        if rows.is_empty() {
            "[]".to_string()
        } else {
            format!("[\n{}\n  ]", rows.join(",\n"))
        }
    };
    format!(
        "{{\n  \"target\": {},\n  \"address\": {},\n  \"protocol\": {},\n  \"rounds\": {},\n  \
         \"interval_s\": {},\n  \"elapsed_s\": {:.1},\n  \"reached\": {},\n  \"verdict\": \"{}\",\n  \
         \"outages\": {},\n  \"hops\": {},\n  \"findings\": {},\n  \"events\": {}\n}}",
        json_str(&meta.target),
        opt_str(meta.addr.map(|a| a.to_string())),
        json_str(&meta.protocol),
        hops.iter().map(|h| h.sent).max().unwrap_or(0),
        meta.interval_secs,
        meta.elapsed_secs,
        reached,
        severity_key(diagnosis::worst(&findings)),
        outages,
        block(hop_rows),
        block(finding_rows),
        block(event_rows),
    )
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
        assert!(text_report(&meta, &hops, false, &Journal::default()).contains("aucune réponse au-delà (30 sauts sondés)"));
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
        let r = text_report(&meta, &hops, true, &Journal::default());
        assert!(r.starts_with("lagtrail — rapport de trace vers exemple.net"));
        assert!(r.contains("10.0.0.1"));
        assert!(r.contains("[OK] Chemin sain"));
    }

    fn feed(j: &mut Journal, hops: &mut Vec<HopView>, t: f64, rtt: Option<f64>, warmup: bool) {
        let names = HashMap::new();
        apply_round_ex(hops, &names, j, t, Some(1), &[sample(1, [10, 0, 0, 1], rtt)], warmup);
    }

    #[test]
    fn journal_records_outage_and_recovery() {
        let (mut j, mut hops) = (Journal::default(), Vec::new());
        for t in 0..5 {
            feed(&mut j, &mut hops, t as f64, Some(10.0), false);
        }
        for t in 5..9 {
            feed(&mut j, &mut hops, t as f64, None, false);
        }
        feed(&mut j, &mut hops, 9.0, Some(10.0), false);
        assert_eq!(j.events.len(), 2);
        assert_eq!(j.events[0].severity, Severity::Critical);
        assert_eq!(j.events[0].t, 7.0); // troisième perte d'affilée
        assert!(j.events[0].text.contains("depuis +00:05"));
        assert!(j.events[1].text.contains("rétablie après 4 s de coupure (4 paquets perdus)"));
        let o = j.outages(20.0);
        assert_eq!((o.count, o.downtime_s, o.longest_s, o.ongoing), (1, 4.0, 4.0, false));
        assert_eq!(o.availability_pct, 80.0);
        assert_eq!(o.describe(), "disponibilité 80.0 % — 1 coupure, 4 s cumulées");
    }

    #[test]
    fn p95_ignores_losses_and_catches_the_tail() {
        let mut h = HopView::new(1);
        assert_eq!(h.p95(), None);
        for i in 0..100 {
            let rtt = if i == 50 { None } else { Some(f64::from(i)) };
            h.record(f64::from(i), &HopSample { ttl: 1, addr: None, rtt_ms: rtt });
        }
        assert_eq!(h.p95(), Some(95.0)); // 99 mesures : rang 95 → valeur 95
    }

    #[test]
    fn outages_count_the_ongoing_one() {
        let (mut j, mut hops) = (Journal::default(), Vec::new());
        assert_eq!(j.outages(0.0).describe(), "aucune coupure à destination");
        feed(&mut j, &mut hops, 0.0, Some(10.0), false);
        for t in 1..6 {
            feed(&mut j, &mut hops, t as f64, None, false);
        }
        let o = j.outages(10.0);
        assert_eq!((o.count, o.downtime_s, o.ongoing), (1, 9.0, true));
        assert!(o.describe().ends_with("coupure en cours"));
    }

    #[test]
    fn journal_records_spike_once_per_cooldown() {
        let (mut j, mut hops) = (Journal::default(), Vec::new());
        for t in 0..12 {
            feed(&mut j, &mut hops, t as f64, Some(10.0), false);
        }
        feed(&mut j, &mut hops, 12.0, Some(300.0), false);
        feed(&mut j, &mut hops, 13.0, Some(300.0), false); // dans le délai : ignoré
        assert_eq!(j.events.len(), 1);
        assert!(j.events[0].text.starts_with("Pic de latence"));
    }

    #[test]
    fn journal_limits_route_change_noise() {
        let (mut j, mut hops) = (Journal::default(), Vec::new());
        let names = HashMap::new();
        for t in 0..20u8 {
            let ip = [10, 0, 0, 1 + t % 2];
            apply_round_ex(&mut hops, &names, &mut j, t as f64, None, &[sample(1, ip, Some(1.0))], false);
        }
        // 3 changements détaillés + 1 ligne « alterne régulièrement ».
        assert_eq!(j.events.len(), 4);
        assert!(j.events[0].text.contains("10.0.0.1 → 10.0.0.2"));
        assert!(j.events[3].text.contains("alterne"));
    }

    #[test]
    fn warmup_round_reveals_path_without_stats() {
        let (mut j, mut hops) = (Journal::default(), Vec::new());
        feed(&mut j, &mut hops, 0.0, None, true); // sonde perdue dans la rafale
        assert_eq!(hops[0].sent, 0);
        assert!(hops[0].addr.is_some());
        feed(&mut j, &mut hops, 1.0, Some(5.0), false);
        assert_eq!((hops[0].sent, hops[0].recv), (1, 1));
        assert_eq!(hops[0].loss_pct(), 0.0);
    }

    #[test]
    fn elapsed_format() {
        assert_eq!(fmt_elapsed(5.4), "+00:05");
        assert_eq!(fmt_elapsed(3725.0), "+1:02:05");
    }

    #[test]
    fn utc_timestamp() {
        use std::time::{Duration, UNIX_EPOCH};
        assert_eq!(fmt_utc(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        assert_eq!(fmt_utc(UNIX_EPOCH + Duration::from_secs(1_700_000_000)), "2023-11-14T22:13:20Z");
        // 29 février d'une année bissextile.
        assert_eq!(fmt_utc(UNIX_EPOCH + Duration::from_secs(1_709_210_096)), "2024-02-29T12:34:56Z");
    }

    #[test]
    fn json_strings_are_escaped() {
        assert_eq!(json_str("a\"b\\c\nd\u{1}"), "\"a\\\"b\\\\c\\nd\\u0001\"");
        assert_eq!(json_num(None), "null");
        assert_eq!(json_num(Some(1.5)), "1.500");
    }
}
