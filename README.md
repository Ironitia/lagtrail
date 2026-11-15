# lagtrail

**Traceroute visuel continu** — ping + latence par saut, tracée dans le temps.
Interface graphique native (egui/eframe), multi-plateforme (Linux + Windows).

Outil de diagnostic réseau **original**, écrit en Rust à partir de zéro. Il n'est
dérivé d'aucun binaire propriétaire : il réimplémente le *concept* public du
traceroute à TTL croissant (RFC 792, comme `traceroute`/`mtr`).

## Principe

À chaque tour, `lagtrail` envoie une requête *Echo* ICMP vers la cible avec un
TTL = 1, 2, 3… Chaque routeur qui décrémente le TTL à zéro renvoie un message
*Time Exceeded* : on obtient son adresse et la latence jusqu'à lui. Quand le TTL
est assez grand pour atteindre la cible, celle-ci répond *Echo Reply* : on connaît
alors la longueur du chemin. On recommence en boucle pour suivre l'évolution de la
latence et des pertes, saut par saut.

Le numéro de séquence ICMP encode `(tour, TTL)`, ce qui permet d'apparier chaque
réponse (y compris la copie du paquet d'origine citée dans les messages d'erreur
ICMP) à la sonde exacte qui l'a déclenchée.

**Protocoles de sonde** (choisis dans l'IHM) :

| Mode | Émission | Appariement | Cible atteinte quand… |
|------|----------|-------------|-----------------------|
| **ICMP/ICMPv6** | Echo fabriqué, envoyé sur le socket raw | (ident, seq) | Echo Reply reçu |
| **UDP** | socket DGRAM noyau, port dest. encode la sonde | port dest. cité dans l'erreur ICMP | Port Unreachable |
| **TCP** | `connect()` non-bloquant (SYN du noyau) | port source cité dans l'erreur ICMP | connexion ouverte (SYN-ACK) ou refusée (RST) |

TCP/UDP n'exigent **aucun** calcul de checksum (le noyau construit les paquets) ;
seul l'Echo ICMP est fabriqué à la main. La réception des erreurs ICMP se fait
toujours sur un socket raw ICMP(v6) → privilèges requis quel que soit le mode.
Le mode **TCP** est précieux pour les hôtes qui bloquent le ping (sonder `:443`).

## Compilation

```sh
cargo build --release
# binaire : target/release/lagtrail  (ou $CARGO_TARGET_DIR/release/lagtrail)
```

## Privilèges (important)

L'envoi/réception ICMP brut exige des privilèges.

- **Linux** — autorise le binaire une fois pour toutes :
  ```sh
  sudo setcap cap_net_raw+ep target/release/lagtrail
  ```
  (ou lance-le avec `sudo`).
- **Windows** — exécute-le **en administrateur**.

Sans privilèges, l'appli affiche un message clair et ne plante pas.

## Utilisation

```sh
lagtrail                 # interface graphique (cible par défaut : 1.1.1.1)
lagtrail exemple.com     # GUI, la trace démarre aussitôt
lagtrail box.local 1.1.1.1 exemple.com   # plusieurs cibles : un onglet chacune + vue d'ensemble
lagtrail demo            # GUI en mode démonstration (données synthétiques, SANS privilèges)
lagtrail --help

# Rapport sans interface, pour un script, une tâche cron ou une supervision :
lagtrail --report exemple.com                       # 20 tours ICMP, tableau + diagnostic
lagtrail --report exemple.com tcp 443 --rounds 60 --interval 0.5
#   code de sortie : 0 = sain, 1 = attention, 2 = critique, 3 = erreur
lagtrail --report exemple.com --json                # même rapport en JSON (sauts, coupures, constats, événements)
lagtrail --report exemple.com 1.1.1.1 9.9.9.9 --rounds 30   # plusieurs cibles en parallèle :
#   un rapport par cible puis une synthèse ; code de sortie = celui de la pire cible
#   la synthèse compare les cibles : toutes dégradées = cause commune (réseau local,
#   box, FAI, avec les sauts partagés) ; une seule = problème propre à cette cible.
#   La vue d'ensemble de l'interface affiche la même conclusion.
#   (--json rend un tableau, --html écrit un fichier par cible, suffixé par son nom)
lagtrail --report exemple.com --html rapport.html   # page autonome : graphe, tableau, diagnostic, événements
#   (un seul fichier sans script, à joindre à un ticket de support ; marche aussi avec --watch,
#   écrit à l'arrêt ; même export par le bouton « Rapport HTML » de l'interface)

# Surveillance continue dans le terminal (serveur, session SSH) :
lagtrail --watch exemple.com --log trace.log
#   une ligne horodatée en UTC par événement (coupure, rétablissement, pic,
#   changement de route) et un point d'état par minute ; Ctrl-C (ou --rounds N)
#   arrête avec un bilan : disponibilité, nombre et durée des coupures, diagnostic
lagtrail --watch exemple.com --exec 'notify-send "lagtrail $LAGTRAIL_SEVERITY" "$LAGTRAIL_EVENT"'
#   --exec lance une commande à chaque événement ; celui-ci est transmis par les
#   variables LAGTRAIL_TARGET, LAGTRAIL_SEVERITY (CRITIQUE, ATTENTION, OK, info)
#   et LAGTRAIL_EVENT

lagtrail --watch exemple.com 1.1.1.1 --json --log trace.jsonl
#   plusieurs cibles surveillées en parallèle (comparées dans le bilan) ; --json écrit
#   une ligne JSON par événement : {"time", "target", "kind", "text"}, avec kind parmi
#   note, info, warning, critical, recovered, status, summary, error

# Diagnostic terminal (sans GUI). Protocole et port optionnels :
lagtrail --selftest 8.8.8.8            # ICMP
lagtrail --selftest exemple.com tcp 443
lagtrail --selftest exemple.com udp
```

Le **mode démo** (`lagtrail demo`, ou cible `demo` dans l'IHM) génère une trace
synthétique sans réseau ni privilèges — pratique pour découvrir l'interface.

Dans la barre de contrôle : choix du **protocole** (ICMP / UDP / TCP), **port**
(TCP/UDP), case **IPv6**. Protocole/port/IPv6 s'appliquent au prochain démarrage.

Dans l'interface : saisis une cible, « Démarrer ». Le tableau liste les sauts
(adresse, nom inverse, perte %, dernier/moyen/min/max RTT, gigue). Clique un saut
pour afficher sa courbe de latence dans le temps (panneau du bas).

- **Plusieurs traces** : « ➕ Nouvelle trace » ouvre un onglet ; chaque trace
  tourne en parallèle (son propre thread) et continue même en arrière-plan.
  « ✕ » ferme l'onglet.
- **Thème** : sélecteur Auto / Clair / Sombre en haut.
- **Export CSV** : deux boutons — *Résumé* (une ligne par saut : perte, min/moy/max,
  gigue) et *Historique* (série temporelle complète, une ligne par tour × saut,
  timeouts en champ vide). Ouvre un dialogue « Enregistrer sous ».

### Surveillance permanente (service systemd)

`--watch` convient à un service utilisateur. Exemple
`~/.config/systemd/user/lagtrail-watch.service` :

```ini
[Unit]
Description=lagtrail — surveillance de la connexion
After=network-online.target

[Service]
ExecStart=%h/.cargo/bin/lagtrail --watch 1.1.1.1 exemple.com --interval 5 --log %h/lagtrail.log
Restart=on-failure

[Install]
WantedBy=default.target
```

Puis `systemctl --user enable --now lagtrail-watch`. Le binaire doit avoir la
capacité `cap_net_raw` (voir « Privilèges »). L'arrêt du service (SIGTERM)
écrit le bilan final dans le journal, comme Ctrl-C.

## Diagnostic automatique

Un traceroute se lit mal à l'œil nu : un routeur intermédiaire à 30 % de perte
est le plus souvent **sain** (il limite ses réponses ICMP). lagtrail applique
les règles de lecture à ta place et affiche des constats en clair :

- une perte (ou une marche de latence) **qui se propage jusqu'à la destination**
  est attribuée au premier saut où elle apparaît — avec le cas particulier du
  saut n° 1 (réseau local : Wi-Fi, câble, box) et de la destination seule ;
- une perte ou une latence élevée **non répercutée en aval** est signalée comme
  bénigne (limitation de débit / faible priorité des réponses du routeur) ;
- destination injoignable : dernier équipement visible ; gigue excessive ;
  rien n'est conclu avant 10 tours ni sur moins de 3 paquets perdus.

Cliquer un constat sélectionne le saut concerné. **📋 Copier le rapport** place
dans le presse-papiers un rapport texte (tableau aligné + diagnostic) prêt à
coller dans un ticket de support. La **vue d'ensemble** résume toutes les
cibles ouvertes (état, perte, latence, verdict) ; un clic ouvre la trace.

**Changements de route** : quand l'adresse qui répond à un saut change, le
tableau l'indique (🔀, avec la liste des adresses vues) et le diagnostic
distingue une alternance régulière (répartition de charge) d'une bascule
ponctuelle. La colonne `route_changes` figure dans le CSV résumé.

**Journal d'événements** : l'onglet « Journal » du panneau du bas date ce qui
s'est passé depuis le démarrage — destination injoignable (3 pertes d'affilée)
puis rétablie, pic de latence, changement de route, entrée et sortie d'alerte.
Utile sur une longue surveillance pour répondre à « quand est-ce arrivé ? ».
Les derniers événements figurent aussi dans le rapport texte et `--report`.

**Graphe** : quand le saut sélectionné n'est pas la destination, la courbe de
celle-ci est superposée en gris — on voit si les à-coups d'un routeur se
retrouvent au bout du chemin ou non. Une mesure isolée entre deux pertes est
dessinée comme un point.

**Tour de découverte** : le premier tour sert à révéler le chemin ; ses
mesures ne comptent pas, car toutes les sondes au-delà du dernier saut
frappent alors la destination en rafale et faussaient la perte affichée.

**Onglets mémorisés** : lancé sans argument, lagtrail rouvre les onglets et le
thème de la dernière fois (cibles, protocole, intervalle, seuils d'alerte),
sans démarrer aucune trace. Fichier : `~/.config/lagtrail/session.conf`
(`%APPDATA%\lagtrail` sous Windows). Un lancement avec des cibles en argument
ne modifie pas ce fichier.

## Architecture

| Fichier         | Rôle                                                          |
|-----------------|---------------------------------------------------------------|
| `src/icmp.rs`   | Encodage/décodage ICMPv4 + parsing IPv4 (fait main, portable). Tests unitaires de la somme de contrôle et de l'appariement. |
| `src/engine.rs` | Moteur de sonde : socket raw, boucle de tours, résolution DNS directe/inverse. Tourne dans un thread, communique par canaux. |
| `src/diagnosis.rs` | Diagnostic automatique du chemin (fonctions pures, testées). |
| `src/stats.rs`  | Agrégation par saut, changements de route, rapport texte (partagé GUI / `--report`). |
| `src/config.rs` | Mémorisation des onglets et du thème (format texte, sans dépendance). |
| `src/app.rs`    | Interface egui : barre de contrôle, tableau des sauts, graphe de latence. |
| `src/html.rs`   | Rapport HTML autonome (graphe SVG, tableau, diagnostic, journal). |
| `src/main.rs`   | Point d'entrée : GUI par défaut, modes `--report`, `--watch` et `--selftest` sans interface. |

Le moteur et l'IHM sont découplés par deux canaux `mpsc` (`EngineCmd` ↔ `EngineMsg`),
donc le réseau ne bloque jamais le rendu.

## Cross-compilation vers Windows (depuis Linux)

```sh
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
```

(Le code réseau est déjà conditionné pour les deux plateformes via `socket2`.)

## Fonctions

Multi-traces en onglets · thème clair/sombre/auto · protocoles ICMP/UDP/TCP ·
IPv4 **et** IPv6 · alertes sur seuils (latence/perte) · graphe latence/temps avec
marqueurs de perte · export CSV (résumé + historique) · DNS inverse · mode démo · **diagnostic
automatique** · rapport texte copiable · vue d'ensemble multi-cibles · barre
min/moy/max par saut · intervalles de 0,2 s à 60 min (veille longue) ·
détection des changements de route · mode `--report` scriptable · onglets
mémorisés entre deux lancements · journal d'événements daté · sortie JSON ·
mode surveillance `--watch` · comparaison saut/destination sur le graphe ·
bilan des coupures (disponibilité, durée cumulée) · commande sur événement `--exec` ·
rapport HTML autonome avec graphe · rapport multi-cibles en parallèle ·
comparaison entre cibles (« ma connexion ou le site ? ») ·
surveillance multi-cibles et sortie JSON Lines · 95ᵉ centile de latence par saut (P95).

## Limites actuelles / pistes

- **Validation réelle** : ICMP, UDP et TCP ont été vérifiés en IPv4 sur un vrai
  chemin Internet, avec des latences concordantes avec `mtr`. **IPv6 n'a pas
  pu être validé** (pas de route IPv6 sur la machine d'essai) : seul le parsing
  ICMPv6 est couvert par des tests unitaires.
- **Traces simultanées** (plusieurs onglets, rapport multi-cibles) : chaque
  trace a son propre identifiant ICMP et, en UDP, reconnaît ses sondes à leur
  port source, pour ne pas s'attribuer les réponses d'une autre. Couvert par
  des tests unitaires, pas encore revérifié sur un vrai réseau.
- Une cible qui limite fortement ses réponses (fréquent en UDP) peut encore
  afficher un peu de perte fictive sur les tours qui suivent la découverte.
- En TCP, la latence de la destination est mesurée à environ 1 ms près.
- Les mesures elles-mêmes ne sont pas rechargées d'une session à l'autre
  (seuls les réglages le sont) ; export image : à faire.
- Le dialogue d'export utilise GTK3 sous Linux (headers requis à la compilation).

## Tests

```sh
cargo test        # encodage ICMP, appariement des réponses, exports, règles de diagnostic
```
