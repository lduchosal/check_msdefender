---
wiki:
  sections:
    - id: cli
      title: CLI
    - id: core
      title: Core
    - id: services
      title: Services
    - id: quality
      title: Quality & Release
---

# Architecture

`check_msdefender` est un plugin Nagios qui interroge l'API Microsoft
Defender for Endpoint et convertit les réponses en statuts
OK/WARNING/CRITICAL/UNKNOWN avec perfdata.

## CLI (`check_msdefender/cli/`)

Groupe Click avec une commande par check : `alerts`, `incidents`,
`lastseen`, `onboarding`, `vulnerabilities`, `machines`, `products`,
`detail`. Chaque commande porte ses seuils par défaut (`-w`/`-c`),
charge la configuration, construit le `DefenderClient` (avec le timeout
de `[settings]`) et délègue au service via `NagiosPlugin`.

## Core (`check_msdefender/core/`)

- `config.py` — localisation et lecture du `check_msdefender.ini`
  (répertoire courant puis `/usr/local/etc/nagios`), accès typé aux
  réglages (`get_timeout`, défaut 30 s).
- `auth.py` — credentials Azure AD (client secret ou certificat).
- `defender.py` — `DefenderClient`, client HTTP de l'API Defender
  (machines, alertes paginées OData, vulnérabilités TVM, produits).
- `path_probe.py` — `CommandPathProbe`, l'oracle « ce chemin
  existe-t-il encore sur l'hôte ? » : une commande configurable
  (`[verify] command`, gabarit `{host}`, lancée sans shell), les chemins
  sur stdin, un verdict `PRESENT`/`ABSENT`/`DENIED`/`ERROR` par ligne.
  Toute panne lève `PathProbeError` — « pas de réponse » ne doit jamais
  ressembler à « rien trouvé ».
- `nagios.py` — `NagiosPlugin` et `DefenderScalarContext` : évaluation
  des seuils (les seuils numériques sont passés en chaîne à
  `nagiosplugin`, sinon un 0 falsy serait avalé), sortie détaillée et
  perfdata.

## Services (`check_msdefender/services/`)

Un service par check, interface commune `get_result()` →
`{"value": int, "details": [str]}`. La valeur alimente les seuils
Nagios ; les détails forment la sortie multiligne. Les alertes et
incidents ignorent le statut `Resolved` par design.

`products_verifier.py` date les entrées de l'export Defender contre le
disque réel de la machine (`products --verify-paths`) : une entrée ne
sort du score que si l'hôte ne la confirme plus **sans ambiguïté**
(tous les chemins absents, ou fichier présent en version supérieure).
Chemin illisible, sonde en échec, entrée sans chemin ⇒ produit compté.
Le score brut, ce qui a été retiré et le nombre de non-vérifiés partent
en perfdata (`raw`/`stale`/`unverified`) à côté du score comparé aux
seuils. La sortie annonce toujours la vérification
(`path verification: N paths, A absent, U unreadable`) et annote chaque
chemin affiché du verdict de la sonde, les `PRESENT` en tête : le chemin
lu est celui qui maintient le produit au score.

## Quality & Release

`publish.sh` orchestre le pipeline : formatage (ruff, docformatter),
typage (pyright), lint (flake8, refurb, vulture, interrogate), tests
pytest avec couverture, ratchet de métriques (`doc/quality-history.csv`),
tests d'intégration, gate SonarCloud, puis bump de version, build,
publication PyPI, tag et push.
