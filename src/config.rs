//! Mémorisation des onglets et réglages entre deux lancements.
//!
//! Format texte volontairement simple (pas de dépendance) : une ligne
//! `theme=…`, puis une ligne `trace=…` par onglet, champs séparés par des
//! tabulations, la cible en dernier.

use std::path::PathBuf;

use crate::engine::ProbeProtocol;

#[derive(Debug, Clone, PartialEq)]
pub struct TraceConfig {
    pub target: String,
    pub protocol: ProbeProtocol,
    pub port: u16,
    pub interval_secs: f32,
    pub max_hops: u8,
    pub prefer_v6: bool,
    pub alerts_on: bool,
    pub alert_latency: f32,
    pub alert_loss: f32,
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct SavedState {
    /// « system », « light » ou « dark ».
    pub theme: String,
    pub traces: Vec<TraceConfig>,
}

fn proto_key(p: ProbeProtocol) -> &'static str {
    match p {
        ProbeProtocol::Icmp => "icmp",
        ProbeProtocol::Udp => "udp",
        ProbeProtocol::Tcp => "tcp",
    }
}

fn parse_trace(line: &str) -> Option<TraceConfig> {
    let f: Vec<&str> = line.splitn(9, '\t').collect();
    if f.len() != 9 {
        return None;
    }
    let target = f[8].trim();
    if target.is_empty() {
        return None;
    }
    Some(TraceConfig {
        protocol: match f[0] {
            "udp" => ProbeProtocol::Udp,
            "tcp" => ProbeProtocol::Tcp,
            _ => ProbeProtocol::Icmp,
        },
        port: f[1].parse().ok().filter(|p| *p != 0)?,
        interval_secs: f[2].parse::<f32>().ok()?.clamp(0.2, 3600.0),
        max_hops: f[3].parse::<u8>().ok()?.clamp(1, 64),
        prefer_v6: f[4] == "1",
        alerts_on: f[5] == "1",
        alert_latency: f[6].parse::<f32>().ok()?.clamp(1.0, 10000.0),
        alert_loss: f[7].parse::<f32>().ok()?.clamp(0.0, 100.0),
        target: target.to_string(),
    })
}

impl SavedState {
    pub fn to_text(&self) -> String {
        let mut out = format!("# lagtrail — onglets mémorisés\ntheme={}\n", self.theme);
        for t in &self.traces {
            // La cible ne doit pas casser le format ligne/tabulation.
            let target: String = t.target.chars().filter(|c| !c.is_control()).collect();
            out.push_str(&format!(
                "trace={}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                proto_key(t.protocol),
                t.port,
                t.interval_secs,
                t.max_hops,
                t.prefer_v6 as u8,
                t.alerts_on as u8,
                t.alert_latency,
                t.alert_loss,
                target,
            ));
        }
        out
    }

    /// Lecture tolérante : les lignes inconnues ou invalides sont ignorées.
    pub fn from_text(text: &str) -> Self {
        let mut state = SavedState { theme: "system".into(), traces: Vec::new() };
        for line in text.lines() {
            if let Some(v) = line.strip_prefix("theme=") {
                if matches!(v.trim(), "system" | "light" | "dark") {
                    state.theme = v.trim().to_string();
                }
            } else if let Some(v) = line.strip_prefix("trace=") {
                if let Some(t) = parse_trace(v) {
                    state.traces.push(t);
                }
            }
        }
        state
    }
}

/// Emplacement du fichier : `$XDG_CONFIG_HOME` ou `~/.config` (Unix),
/// `%APPDATA%` (Windows), sous-dossier `lagtrail`.
pub fn path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("APPDATA").map(PathBuf::from))
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join("lagtrail").join("session.conf"))
}

pub fn load() -> Option<SavedState> {
    let text = std::fs::read_to_string(path()?).ok()?;
    Some(SavedState::from_text(&text))
}

pub fn save(state: &SavedState) -> std::io::Result<()> {
    let Some(p) = path() else { return Ok(()) };
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(p, state.to_text())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let s = SavedState {
            theme: "dark".into(),
            traces: vec![
                TraceConfig {
                    target: "exemple.com".into(),
                    protocol: ProbeProtocol::Tcp,
                    port: 443,
                    interval_secs: 2.5,
                    max_hops: 30,
                    prefer_v6: true,
                    alerts_on: true,
                    alert_latency: 80.0,
                    alert_loss: 2.5,
                },
                TraceConfig {
                    target: "2001:db8::1".into(),
                    protocol: ProbeProtocol::Icmp,
                    port: 443,
                    interval_secs: 60.0,
                    max_hops: 20,
                    prefer_v6: false,
                    alerts_on: false,
                    alert_latency: 100.0,
                    alert_loss: 5.0,
                },
            ],
        };
        assert_eq!(SavedState::from_text(&s.to_text()), s);
    }

    #[test]
    fn garbage_is_ignored_and_values_clamped() {
        let s = SavedState::from_text(
            "n'importe quoi\ntheme=fluo\ntrace=tcp\t443\n\
             trace=udp\t33434\t99999\t200\t0\t1\t50\t3\thote.test\n",
        );
        assert_eq!(s.theme, "system");
        assert_eq!(s.traces.len(), 1);
        assert_eq!(s.traces[0].interval_secs, 3600.0);
        assert_eq!(s.traces[0].max_hops, 64);
        assert_eq!(s.traces[0].target, "hote.test");
    }
}
