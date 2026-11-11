//! Diagnostic automatique d'un chemin réseau.
//!
//! Lire un traceroute est piégeux : un routeur intermédiaire qui affiche 30 %
//! de perte est le plus souvent *sain* — il limite simplement ses réponses
//! ICMP. Ce qui compte, c'est ce qui **se propage jusqu'à la destination**.
//! Ce module applique ces règles de lecture et produit des constats en clair.
//!
//! Tout est pur (aucune E/S) pour être testable.

/// Statistiques d'un saut, telles que vues par le diagnostic.
#[derive(Debug, Clone, PartialEq)]
pub struct HopStat {
    pub ttl: u8,
    pub sent: u64,
    pub loss_pct: f64,
    pub avg_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
}

impl HopStat {
    /// Le saut n'a jamais répondu (routeur muet / filtré).
    fn silent(&self) -> bool {
        self.avg_ms.is_none()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Ok,
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Finding {
    pub severity: Severity,
    /// Saut concerné (le cas échéant) — permet à l'IHM de le sélectionner.
    pub ttl: Option<u8>,
    pub text: String,
}

/// Nombre minimal de tours avant de conclure quoi que ce soit.
pub const MIN_SAMPLES: u64 = 10;

/// Perte à destination considérée comme significative (%).
const DEST_LOSS_WARN: f64 = 2.0;
const DEST_LOSS_CRIT: f64 = 10.0;
/// Nombre minimal de paquets perdus à destination pour parler de perte.
const MIN_LOST: f64 = 3.0;
/// Perte d'un saut intermédiaire méritant une mention (%).
const HOP_LOSS_NOTE: f64 = 5.0;
/// Saut de latence méritant une mention (ms).
const LATENCY_STEP: f64 = 30.0;
const DEST_LATENCY_WARN: f64 = 150.0;

fn finding(severity: Severity, ttl: Option<u8>, text: String) -> Finding {
    Finding { severity, ttl, text }
}

fn list(ttls: &[u8]) -> String {
    ttls.iter().map(|t| format!("#{t}")).collect::<Vec<_>>().join(", ")
}

/// Pire gravité d'un ensemble de constats.
pub fn worst(findings: &[Finding]) -> Severity {
    findings.iter().map(|f| f.severity).max().unwrap_or(Severity::Ok)
}

/// Analyse le chemin. `hops` est ordonné par TTL croissant ; `reached` indique
/// si la destination a été atteinte (le dernier saut est alors la destination).
pub fn diagnose(hops: &[HopStat], reached: bool) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(dest) = hops.last() else {
        return out;
    };
    if dest.sent < MIN_SAMPLES {
        out.push(finding(
            Severity::Info,
            None,
            format!(
                "Mesures en cours ({} / {MIN_SAMPLES} tours) — diagnostic dans un instant.",
                dest.sent
            ),
        ));
        return out;
    }

    // ── Destination injoignable ──────────────────────────────────────────
    if !reached {
        let last = hops.iter().rev().find(|h| !h.silent());
        let text = match last {
            Some(h) => format!(
                "La destination ne répond pas. Dernier équipement visible : saut #{} — \
                 la coupure (ou un pare-feu) se situe juste après. Essaie un autre \
                 protocole (TCP 443) pour distinguer filtrage et panne.",
                h.ttl
            ),
            None => "Aucun équipement ne répond, pas même la passerelle : vérifie la \
                     connexion locale (câble, Wi-Fi, interface)."
                .to_string(),
        };
        out.push(finding(Severity::Critical, last.map(|h| h.ttl), text));
        return out;
    }

    let n = hops.len();

    // ── Perte de paquets ─────────────────────────────────────────────────
    // On remonte depuis la destination tant que la perte « tient » : le
    // premier saut de cette série est l'origine probable du problème.
    let mut in_run = vec![false; n];
    // Un ou deux paquets perdus sur un petit échantillon ne prouvent rien.
    let dest_lost = (dest.loss_pct / 100.0 * dest.sent as f64).round();
    if dest.loss_pct >= DEST_LOSS_WARN && dest_lost >= MIN_LOST {
        let floor = (dest.loss_pct * 0.5).max(1.0);
        let mut origin = n - 1;
        for i in (0..n).rev() {
            let h = &hops[i];
            if h.silent() {
                continue; // muet : ne confirme ni n'infirme, on passe au travers
            }
            if h.loss_pct >= floor {
                origin = i;
                in_run[i] = true;
            } else {
                break;
            }
        }
        let sev = if dest.loss_pct >= DEST_LOSS_CRIT {
            Severity::Critical
        } else {
            Severity::Warning
        };
        let ttl = hops[origin].ttl;
        let text = if origin == n - 1 {
            format!(
                "{:.0} % de perte à la destination seulement (saut #{ttl}) : les sauts \
                 précédents sont propres. La cible elle-même est en cause — surcharge, \
                 ou limitation volontaire de ses réponses.",
                dest.loss_pct
            )
        } else if origin == 0 {
            format!(
                "{:.0} % de perte jusqu'à la destination, présente dès le saut #{ttl} : \
                 le problème est au plus près de toi (Wi-Fi, câble, box/passerelle).",
                dest.loss_pct
            )
        } else {
            format!(
                "{:.0} % de perte jusqu'à la destination, apparue au saut #{ttl} et \
                 maintenue ensuite : le problème se situe à ce saut ou sur le lien \
                 qui y mène.",
                dest.loss_pct
            )
        };
        out.push(finding(sev, Some(ttl), text));
    }

    // Pertes intermédiaires non répercutées → faux positifs classiques.
    let benign: Vec<u8> = hops[..n - 1]
        .iter()
        .enumerate()
        .filter(|(i, h)| !h.silent() && !in_run[*i] && h.loss_pct >= HOP_LOSS_NOTE)
        .map(|(_, h)| h.ttl)
        .collect();
    if !benign.is_empty() {
        let (subj, verb) = if benign.len() == 1 {
            ("Le saut", "affiche")
        } else {
            ("Les sauts", "affichent")
        };
        out.push(finding(
            Severity::Info,
            benign.first().copied(),
            format!(
                "{subj} {} {verb} de la perte qui ne se retrouve pas en aval : \
                 limitation des réponses par le routeur, sans impact sur ton trafic.",
                list(&benign)
            ),
        ));
    }
    let mute: Vec<u8> = hops[..n - 1].iter().filter(|h| h.silent()).map(|h| h.ttl).collect();
    if !mute.is_empty() {
        out.push(finding(
            Severity::Info,
            None,
            format!(
                "{} muet(s) : routeur(s) configuré(s) pour ne pas répondre — normal \
                 tant que la destination répond.",
                list(&mute)
            ),
        ));
    }

    // ── Latence ──────────────────────────────────────────────────────────
    if let Some(dest_avg) = dest.avg_ms {
        // Plus grande marche de latence qui se maintient jusqu'au bout.
        let answering: Vec<(usize, f64)> = hops
            .iter()
            .enumerate()
            .filter_map(|(i, h)| h.avg_ms.map(|a| (i, a)))
            .collect();
        let mut best: Option<(usize, f64)> = None; // (index du saut, marche en ms)
        let mut prev = 0.0;
        for (k, &(i, avg)) in answering.iter().enumerate() {
            let step = avg - prev;
            let floor_after = answering[k..]
                .iter()
                .map(|&(_, a)| a)
                .fold(f64::INFINITY, f64::min);
            let sustained = floor_after >= prev + step * 0.6;
            if step >= LATENCY_STEP && sustained && best.is_none_or(|(_, s)| step > s) {
                best = Some((i, step));
            }
            prev = prev.max(avg.min(dest_avg));
        }
        if let Some((i, step)) = best {
            let ttl = hops[i].ttl;
            let high = dest_avg >= DEST_LATENCY_WARN;
            let text = if i == 0 {
                format!(
                    "Latence élevée dès le saut #{ttl} (~{step:.0} ms) : le lien local \
                     (Wi-Fi saturé, box, ligne d'accès) est le facteur limitant."
                )
            } else if high {
                format!(
                    "La latence gagne ~{step:.0} ms au saut #{ttl} et le reste jusqu'à la \
                     destination ({dest_avg:.0} ms) : congestion ou long trajet à partir \
                     de ce saut."
                )
            } else {
                format!(
                    "L'essentiel de la latence (~{step:.0} ms sur {dest_avg:.0}) apparaît \
                     au saut #{ttl} et se maintient : typique d'un lien longue distance, \
                     pas forcément un défaut."
                )
            };
            let sev = if high || i == 0 { Severity::Warning } else { Severity::Info };
            out.push(finding(sev, Some(ttl), text));
        } else if dest_avg >= DEST_LATENCY_WARN {
            out.push(finding(
                Severity::Warning,
                Some(dest.ttl),
                format!(
                    "Latence élevée à destination ({dest_avg:.0} ms), montée \
                     progressivement le long du chemin, sans saut fautif net."
                ),
            ));
        }

        // Routeurs lents à répondre mais sans effet en aval.
        let slow: Vec<u8> = hops[..n - 1]
            .iter()
            .filter(|h| h.avg_ms.is_some_and(|a| a > dest_avg * 2.0 + 20.0))
            .map(|h| h.ttl)
            .collect();
        if !slow.is_empty() {
            out.push(finding(
                Severity::Info,
                slow.first().copied(),
                format!(
                    "{} : latence plus haute qu'à destination — le routeur répond \
                     lentement aux sondes (faible priorité), le trafic traversant \
                     n'est pas ralenti.",
                    list(&slow)
                ),
            ));
        }

        // Instabilité.
        if let Some(j) = dest.jitter_ms {
            if j >= 30.0 && j >= dest_avg * 0.5 {
                out.push(finding(
                    Severity::Warning,
                    Some(dest.ttl),
                    format!(
                        "Latence instable à destination (gigue {j:.0} ms pour {dest_avg:.0} ms \
                         de moyenne) : gênant pour la voix, la visio et le jeu."
                    ),
                ));
            }
        }

        if worst(&out) < Severity::Warning {
            out.insert(
                0,
                finding(
                    Severity::Ok,
                    None,
                    format!(
                        "Chemin sain : {} sauts, {dest_avg:.0} ms en moyenne et {:.1} % de \
                         perte à destination.",
                        n, dest.loss_pct
                    ),
                ),
            );
        }
    }

    // Du plus grave au plus bénin ; le verdict « sain » reste en tête.
    out.sort_by_key(|f| match f.severity {
        Severity::Ok => 0,
        Severity::Critical => 1,
        Severity::Warning => 2,
        Severity::Info => 3,
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hop(ttl: u8, loss: f64, avg: Option<f64>) -> HopStat {
        HopStat { ttl, sent: 100, loss_pct: loss, avg_ms: avg, jitter_ms: Some(1.0) }
    }

    fn path(spec: &[(f64, Option<f64>)]) -> Vec<HopStat> {
        spec.iter()
            .enumerate()
            .map(|(i, &(l, a))| hop(i as u8 + 1, l, a))
            .collect()
    }

    #[test]
    fn healthy_path_is_ok() {
        let p = path(&[(0.0, Some(1.0)), (0.0, Some(8.0)), (0.0, Some(12.0))]);
        let f = diagnose(&p, true);
        assert_eq!(worst(&f), Severity::Ok);
        assert!(f[0].text.starts_with("Chemin sain"));
    }

    #[test]
    fn waits_for_enough_samples() {
        let mut p = path(&[(0.0, Some(1.0))]);
        p[0].sent = 3;
        let f = diagnose(&p, true);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Info);
    }

    #[test]
    fn intermediate_loss_not_propagated_is_benign() {
        // Saut 2 : 40 % de perte, mais destination propre → limitation ICMP.
        let p = path(&[(0.0, Some(1.0)), (40.0, Some(9.0)), (0.0, Some(12.0))]);
        let f = diagnose(&p, true);
        assert!(worst(&f) <= Severity::Info);
        assert!(f.iter().any(|x| x.ttl == Some(2) && x.text.contains("limitation")));
    }

    #[test]
    fn propagated_loss_blames_first_hop_of_run() {
        let p = path(&[
            (0.0, Some(1.0)),
            (0.0, Some(8.0)),
            (12.0, Some(15.0)),
            (100.0, None), // muet : traversé
            (11.0, Some(20.0)),
            (12.0, Some(21.0)),
        ]);
        let f = diagnose(&p, true);
        assert_eq!(f[0].severity, Severity::Critical);
        assert_eq!(f[0].ttl, Some(3));
    }

    #[test]
    fn loss_from_first_hop_points_to_local_network() {
        let p = path(&[(6.0, Some(3.0)), (5.0, Some(9.0)), (6.0, Some(14.0))]);
        let f = diagnose(&p, true);
        assert_eq!(f[0].severity, Severity::Warning);
        assert_eq!(f[0].ttl, Some(1));
        assert!(f[0].text.contains("au plus près de toi"));
    }

    #[test]
    fn loss_only_at_destination() {
        let p = path(&[(0.0, Some(1.0)), (0.0, Some(8.0)), (20.0, Some(12.0))]);
        let f = diagnose(&p, true);
        assert_eq!(f[0].ttl, Some(3));
        assert!(f[0].text.contains("destination seulement"));
    }

    #[test]
    fn a_single_lost_packet_is_not_a_problem() {
        // 1 paquet perdu sur 20 = 5 %, mais statistiquement insignifiant.
        let mut p = path(&[(0.0, Some(1.0)), (5.0, Some(12.0))]);
        p.iter_mut().for_each(|h| h.sent = 20);
        assert_eq!(worst(&diagnose(&p, true)), Severity::Ok);
    }

    #[test]
    fn unreachable_reports_last_visible_hop() {
        let p = path(&[(0.0, Some(1.0)), (0.0, Some(8.0)), (100.0, None), (100.0, None)]);
        let f = diagnose(&p, false);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Critical);
        assert_eq!(f[0].ttl, Some(2));
    }

    #[test]
    fn sustained_latency_step_is_located() {
        let p = path(&[
            (0.0, Some(1.0)),
            (0.0, Some(9.0)),
            (0.0, Some(180.0)),
            (0.0, Some(184.0)),
            (0.0, Some(186.0)),
        ]);
        let f = diagnose(&p, true);
        assert_eq!(f[0].severity, Severity::Warning);
        assert_eq!(f[0].ttl, Some(3));
    }

    #[test]
    fn slow_router_alone_is_benign() {
        // Saut 2 répond en 200 ms mais la destination est à 12 ms.
        let p = path(&[(0.0, Some(1.0)), (0.0, Some(200.0)), (0.0, Some(12.0))]);
        let f = diagnose(&p, true);
        assert!(worst(&f) <= Severity::Info);
        assert!(f.iter().any(|x| x.ttl == Some(2) && x.text.contains("faible priorité")));
    }

    #[test]
    fn unstable_destination_is_flagged() {
        let mut p = path(&[(0.0, Some(1.0)), (0.0, Some(40.0))]);
        p[1].jitter_ms = Some(35.0);
        let f = diagnose(&p, true);
        assert!(f.iter().any(|x| x.severity == Severity::Warning && x.text.contains("gigue")));
    }
}
