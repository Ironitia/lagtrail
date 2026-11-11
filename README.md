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

## Architecture

| Fichier         | Rôle                                                          |
|-----------------|---------------------------------------------------------------|
| `src/icmp.rs`   | Encodage/décodage ICMPv4 + parsing IPv4 (fait main, portable). Tests unitaires de la somme de contrôle et de l'appariement. |
| `src/engine.rs` | Moteur de sonde : socket raw, boucle de tours, résolution DNS directe/inverse. Tourne dans un thread, communique par canaux. |
| `src/diagnosis.rs` | Diagnostic automatique du chemin (fonctions pures, testées). |
| `src/app.rs`    | Interface egui : barre de contrôle, tableau des sauts, graphe de latence. |
| `src/main.rs`   | Point d'entrée : GUI par défaut, mode `--selftest` headless.   |

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
min/moy/max par saut · intervalles de 0,2 s à 60 min (veille longue).

## Limites actuelles / pistes

- **Les modes réseau (ICMP/UDP/TCP, IPv4/IPv6) n'ont pas encore été validés en
  conditions réelles dans cet environnement** (manque de `CAP_NET_RAW`) : le
  parsing des paquets est couvert par des tests unitaires, mais le chemin
  socket mérite une passe de validation live. Le mode démo, lui, est validé.
- Sauvegarde/chargement de session et export image : à faire.
- Le dialogue d'export utilise GTK3 sous Linux (headers requis à la compilation).

## Tests

```sh
cargo test        # encodage ICMP, appariement des réponses, exports, règles de diagnostic
```
