# Journal des modifications

## 0.2.0 — non publié

### Ajouts
- Journal d'événements par trace : coupures, rétablissements, pics de latence,
  changements de route, alertes.
- Bilan des coupures : disponibilité, nombre, durée cumulée et plus longue.
- Mode `--watch` : surveillance continue dans le terminal, lignes horodatées en
  UTC, `--log fichier`, `--exec commande` à chaque événement, `--json` (une
  ligne JSON par événement), plusieurs cibles en parallèle, arrêt propre par
  Ctrl-C ou SIGTERM avec bilan.
- Mode `--report` : sortie `--json`, rapport `--html` autonome avec graphe,
  plusieurs cibles mesurées en parallèle avec synthèse.
- Comparaison entre cibles (« ma connexion ou le site ? ») dans la synthèse et
  dans la vue d'ensemble de l'interface.
- 95ᵉ centile de latence par saut (P95).
- Graphe : destination superposée en gris au saut sélectionné, mesures isolées
  dessinées comme des points.
- `--version`.

### Corrections
- Deux traces simultanées (onglets, rapport multi-cibles) pouvaient s'attribuer
  les réponses l'une de l'autre : identifiant ICMP désormais propre à chaque
  trace, réponses UDP reconnues à leur port source.
- Le premier tour, qui découvre le chemin, n'entre plus dans les statistiques
  (il faussait la perte affichée à destination).
- La progression `tour N/M` ne s'affiche plus hors terminal.

## 0.1.0

- Traceroute visuel continu ICMP/UDP/TCP, IPv4 et IPv6, onglets multiples,
  graphe de latence, alertes, export CSV, diagnostic automatique, rapport
  texte, mode `--report`, onglets et thème mémorisés.
