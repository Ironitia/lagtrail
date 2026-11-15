//! Rapport HTML autonome (un seul fichier, sans script ni ressource externe) :
//! verdict, graphe de latence en SVG, tableau des sauts, diagnostic, journal.
//! Pensé pour être joint à un ticket de support ou archivé.

use crate::diagnosis::{self, Severity};
use crate::stats::{self, HopView, Journal, ReportMeta, fmt_elapsed, fmt_ms};

/// Échappe un texte pour l'insérer dans du HTML (contenu ou attribut).
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

fn severity_class(s: Severity) -> &'static str {
    match s {
        Severity::Ok => "ok",
        Severity::Info => "info",
        Severity::Warning => "warn",
        Severity::Critical => "crit",
    }
}

/// Pas « rond » (1, 2, 5 × 10ⁿ) donnant au plus `max_ticks` graduations.
fn nice_step(range: f64, max_ticks: usize) -> f64 {
    let raw = (range / max_ticks.max(1) as f64).max(1e-9);
    let mag = 10f64.powf(raw.log10().floor());
    [1.0, 2.0, 5.0, 10.0]
        .iter()
        .map(|m| m * mag)
        .find(|s| *s >= raw)
        .unwrap_or(10.0 * mag)
}

/// Graphe SVG de la latence d'un saut dans le temps ; les pertes sont des
/// traits rouges sur l'axe. Chaîne vide s'il n'y a rien à tracer.
fn latency_svg(hop: &HopView) -> String {
    const W: f64 = 920.0;
    const H: f64 = 260.0;
    const LEFT: f64 = 52.0;
    const RIGHT: f64 = 12.0;
    const TOP: f64 = 12.0;
    const BOTTOM: f64 = 28.0;

    let (Some(first), Some(last)) = (hop.history.front(), hop.history.back()) else {
        return String::new();
    };
    let (x0, x1) = (first.0, last.0.max(first.0 + 1.0));
    let peak = hop.history.iter().filter_map(|p| p.1).fold(0.0f64, f64::max);
    if peak <= 0.0 {
        return String::new();
    }
    let step = nice_step(peak * 1.1, 5);
    let y_max = (peak * 1.1 / step).ceil() * step;
    let px = |x: f64| LEFT + (x - x0) / (x1 - x0) * (W - LEFT - RIGHT);
    let py = |y: f64| H - BOTTOM - y / y_max * (H - TOP - BOTTOM);

    let mut svg = format!(
        "<svg viewBox=\"0 0 {W} {H}\" role=\"img\" aria-label=\"Latence dans le temps\">\n"
    );
    // Graduations horizontales (ms).
    let mut y = 0.0;
    while y <= y_max + step * 0.01 {
        svg.push_str(&format!(
            "<line class=\"grid\" x1=\"{LEFT}\" x2=\"{:.1}\" y1=\"{:.1}\" y2=\"{:.1}\"/>\
             <text class=\"tick\" x=\"{:.1}\" y=\"{:.1}\" text-anchor=\"end\">{} ms</text>\n",
            W - RIGHT,
            py(y),
            py(y),
            LEFT - 6.0,
            py(y) + 4.0,
            y
        ));
        y += step;
    }
    // Repères de temps.
    for i in 0..=4 {
        let x = x0 + (x1 - x0) * f64::from(i) / 4.0;
        let anchor = match i {
            0 => "start",
            4 => "end",
            _ => "middle",
        };
        svg.push_str(&format!(
            "<text class=\"tick\" x=\"{:.1}\" y=\"{:.1}\" text-anchor=\"{anchor}\">{}</text>\n",
            px(x),
            H - 8.0,
            fmt_elapsed(x)
        ));
    }
    // Pertes : traits rouges au pied du graphe.
    for (x, _) in hop.history.iter().filter(|p| p.1.is_none()) {
        svg.push_str(&format!(
            "<line class=\"loss\" x1=\"{0:.1}\" x2=\"{0:.1}\" y1=\"{1:.1}\" y2=\"{2:.1}\"/>\n",
            px(*x),
            H - BOTTOM,
            H - BOTTOM - 14.0
        ));
    }
    // Courbe, interrompue à chaque perte ; une mesure isolée devient un point.
    let mut run: Vec<(f64, f64)> = Vec::new();
    let flush = |run: &mut Vec<(f64, f64)>, svg: &mut String| {
        match run.len() {
            0 => {}
            1 => svg.push_str(&format!(
                "<circle class=\"dot\" cx=\"{:.1}\" cy=\"{:.1}\" r=\"2\"/>\n",
                run[0].0, run[0].1
            )),
            _ => {
                let pts: Vec<String> =
                    run.iter().map(|(x, y)| format!("{x:.1},{y:.1}")).collect();
                svg.push_str(&format!(
                    "<polyline class=\"curve\" points=\"{}\"/>\n",
                    pts.join(" ")
                ));
            }
        }
        run.clear();
    };
    for (x, rtt) in &hop.history {
        match rtt {
            Some(r) => run.push((px(*x), py(*r))),
            None => flush(&mut run, &mut svg),
        }
    }
    flush(&mut run, &mut svg);
    svg.push_str("</svg>\n");
    svg
}

const STYLE: &str = "\
:root{--bg:#fbfbfa;--fg:#1d1f23;--muted:#666b75;--line:#dfe1e5;--card:#fff;\
--ok:#1a7f4b;--info:#2f6fb7;--warn:#a86400;--crit:#c0392b;--curve:#2f6fb7}\
@media(prefers-color-scheme:dark){:root{--bg:#16181c;--fg:#e6e8eb;--muted:#9aa0aa;\
--line:#30343b;--card:#1d2026;--ok:#4cc38a;--info:#6aa9ec;--warn:#e0a03a;--crit:#f0705f;\
--curve:#6aa9ec}}\
*{box-sizing:border-box}\
body{margin:0;padding:24px 16px;background:var(--bg);color:var(--fg);\
font:15px/1.5 system-ui,-apple-system,'Segoe UI',sans-serif}\
main{max-width:980px;margin:0 auto}\
h1{font-size:1.4rem;margin:0 0 4px}h2{font-size:1.05rem;margin:28px 0 8px}\
.meta{color:var(--muted);margin:0 0 16px}\
.verdict{display:inline-block;padding:4px 12px;border-radius:999px;font-weight:600;\
color:#fff;margin-bottom:8px}\
.verdict.ok{background:var(--ok)}.verdict.info{background:var(--info)}\
.verdict.warn{background:var(--warn)}.verdict.crit{background:var(--crit)}\
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px}\
.scroll{overflow-x:auto}\
svg{width:100%;height:auto;display:block}\
.grid{stroke:var(--line);stroke-width:1}.tick{fill:var(--muted);font-size:11px}\
.curve{fill:none;stroke:var(--curve);stroke-width:1.6;stroke-linejoin:round}\
.dot{fill:var(--curve)}.loss{stroke:var(--crit);stroke-width:2}\
table{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums}\
th,td{padding:5px 10px;text-align:right;border-bottom:1px solid var(--line);white-space:nowrap}\
th{color:var(--muted);font-weight:600;font-size:.85rem}\
td.l,th.l{text-align:left}td.name{white-space:normal;color:var(--muted)}\
td.bad{color:var(--crit);font-weight:600}\
ul{list-style:none;margin:0;padding:0}\
li{padding:6px 0 6px 12px;border-left:4px solid var(--line);margin-bottom:6px}\
li.ok{border-color:var(--ok)}li.info{border-color:var(--info)}\
li.warn{border-color:var(--warn)}li.crit{border-color:var(--crit)}\
.t{font-family:ui-monospace,monospace;color:var(--muted);margin-right:10px}\
.cap::first-letter{text-transform:uppercase}\
footer{color:var(--muted);font-size:.85rem;margin-top:28px}";

/// Rapport HTML complet. `generated` = horodatage affiché en pied de page.
pub fn html_report(
    meta: &ReportMeta,
    hops: &[HopView],
    reached: bool,
    journal: &Journal,
    generated: &str,
) -> String {
    let findings = stats::findings(hops, reached);
    let worst = diagnosis::worst(&findings);
    let verdict = match worst {
        Severity::Critical => "Problème critique",
        Severity::Warning => "À surveiller",
        _ if !reached => "Destination non atteinte",
        _ => "Chemin sain",
    };
    let target = esc(&meta.target);
    let rounds = hops.iter().map(|h| h.sent).max().unwrap_or(0);
    let mut out = format!(
        "<!doctype html>\n<html lang=\"fr\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n\
         <title>lagtrail — {target}</title>\n<style>{STYLE}</style>\n</head>\n<body>\n<main>\n\
         <span class=\"verdict {}\">{verdict}</span>\n<h1>Trace vers {target}{}</h1>\n\
         <p class=\"meta\">{} · {rounds} tours · intervalle {} s · durée {}</p>\n",
        severity_class(worst),
        meta.addr.map(|a| format!(" ({a})")).unwrap_or_default(),
        esc(&meta.protocol),
        meta.interval_secs,
        fmt_elapsed(meta.elapsed_secs).trim_start_matches('+'),
    );

    let shown = &hops[..stats::visible_len(hops, reached)];
    // Graphe : la destination si elle est atteinte, sinon le dernier saut visible.
    let graphed = if reached {
        hops.last()
    } else {
        shown.iter().rev().find(|h| h.recv > 0)
    };
    if let Some(h) = graphed {
        let svg = latency_svg(h);
        if !svg.is_empty() {
            let what = if reached {
                "destination".to_string()
            } else {
                format!("saut #{}", h.ttl)
            };
            out.push_str(&format!(
                "<h2>Latence dans le temps — {what}</h2>\n<div class=\"card\">\n{svg}</div>\n\
                 <p class=\"meta\">Traits rouges : sondes restées sans réponse. \
                 {} dernières mesures au plus.</p>\n",
                stats::HISTORY
            ));
        }
    }

    out.push_str(
        "<h2>Sauts</h2>\n<div class=\"card scroll\">\n<table>\n<tr><th>#</th>\
         <th class=\"l\">Adresse</th><th>Perte</th><th>Moy.</th><th>Min.</th><th>Max.</th>\
         <th>P95</th><th>Gigue</th><th class=\"l\">Nom</th></tr>\n",
    );
    for h in shown {
        let mut name = esc(h.name.as_deref().unwrap_or(""));
        if h.route_changes > 0 {
            name.push_str(&format!(" [route : {} changements]", h.route_changes));
        }
        let loss = h.loss_pct();
        out.push_str(&format!(
            "<tr><td>{}</td><td class=\"l\">{}</td><td{}>{loss:.1} %</td><td>{}</td><td>{}</td>\
             <td>{}</td><td>{}</td><td>{}</td><td class=\"l name\">{}</td></tr>\n",
            h.ttl,
            h.addr.map(|a| a.to_string()).unwrap_or_else(|| "*".into()),
            if loss >= 2.0 { " class=\"bad\"" } else { "" },
            fmt_ms(h.avg()),
            fmt_ms(h.min()),
            fmt_ms(h.max()),
            fmt_ms(h.p95()),
            fmt_ms(h.jitter()),
            name.trim(),
        ));
    }
    out.push_str("</table>\n</div>\n<p class=\"meta\">Latences en millisecondes.");
    if shown.len() < hops.len() {
        out.push_str(&format!(
            " Aucune réponse au-delà ({} sauts sondés).",
            hops.len()
        ));
    }
    out.push_str("</p>\n");

    if !findings.is_empty() {
        out.push_str("<h2>Diagnostic</h2>\n<ul>\n");
        for f in &findings {
            out.push_str(&format!(
                "<li class=\"{}\">{}</li>\n",
                severity_class(f.severity),
                esc(&f.text)
            ));
        }
        out.push_str("</ul>\n");
    }

    let outages = journal.outages(meta.elapsed_secs);
    if reached || outages.count > 0 {
        out.push_str(&format!(
            "<h2>Coupures</h2>\n<p class=\"cap\">{}</p>\n",
            esc(&outages.describe())
        ));
    }

    if !journal.events.is_empty() {
        out.push_str("<h2>Événements</h2>\n<ul>\n");
        for e in &journal.events {
            out.push_str(&format!(
                "<li class=\"{}\"><span class=\"t\">{}</span>{}</li>\n",
                severity_class(e.severity),
                fmt_elapsed(e.t),
                esc(&e.text)
            ));
        }
        out.push_str("</ul>\n");
    }

    out.push_str(&format!(
        "<footer>Généré par lagtrail le {} (UTC). Les temps « +MM:SS » sont comptés \
         depuis le début de la trace.</footer>\n</main>\n</body>\n</html>\n",
        esc(generated)
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::HopSample;
    use std::net::IpAddr;

    fn meta(target: &str) -> ReportMeta {
        ReportMeta {
            target: target.to_string(),
            addr: None,
            protocol: "ICMP".to_string(),
            interval_secs: 1.0,
            elapsed_secs: 20.0,
        }
    }

    fn trace(rtts: &[Option<f64>]) -> (Vec<HopView>, Journal) {
        let (mut hops, mut journal) = (Vec::new(), Journal::default());
        for (i, rtt) in rtts.iter().enumerate() {
            let s = HopSample { ttl: 1, addr: Some(IpAddr::from([10, 0, 0, 1])), rtt_ms: *rtt };
            stats::apply_round_ex(
                &mut hops,
                &Default::default(),
                &mut journal,
                i as f64,
                Some(1),
                &[s],
                false,
            );
        }
        (hops, journal)
    }

    #[test]
    fn escapes_markup_in_target() {
        let (hops, journal) = trace(&[Some(10.0); 12]);
        let html = html_report(&meta("<script>x</script>"), &hops, true, &journal, "now");
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;x&lt;/script&gt;"));
        assert!(html.contains("Chemin sain"));
    }

    #[test]
    fn graph_breaks_on_loss_and_marks_it() {
        let (hops, _) = trace(&[Some(10.0), Some(12.0), None, Some(11.0), None, Some(9.0), Some(9.5)]);
        let svg = latency_svg(&hops[0]);
        assert_eq!(svg.matches("<polyline").count(), 2);
        assert_eq!(svg.matches("<circle").count(), 1);
        assert_eq!(svg.matches("class=\"loss\"").count(), 2);
    }

    #[test]
    fn graph_is_empty_without_any_reply() {
        let (hops, _) = trace(&[None, None]);
        assert!(latency_svg(&hops[0]).is_empty());
    }

    #[test]
    fn nice_steps_are_round() {
        assert_eq!(nice_step(100.0, 5), 20.0);
        assert_eq!(nice_step(7.0, 5), 2.0);
        assert_eq!(nice_step(330.0, 5), 100.0);
    }
}
