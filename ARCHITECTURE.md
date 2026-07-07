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
- `nagios.py` — `NagiosPlugin` et `DefenderScalarContext` : évaluation
  des seuils (les seuils numériques sont passés en chaîne à
  `nagiosplugin`, sinon un 0 falsy serait avalé), sortie détaillée et
  perfdata.

## Services (`check_msdefender/services/`)

Un service par check, interface commune `get_result()` →
`{"value": int, "details": [str]}`. La valeur alimente les seuils
Nagios ; les détails forment la sortie multiligne. Les alertes et
incidents ignorent le statut `Resolved` par design.

## Quality & Release

`publish.sh` orchestre le pipeline : formatage (ruff, docformatter),
typage (pyright), lint (flake8, refurb, vulture, interrogate), tests
pytest avec couverture, ratchet de métriques (`doc/quality-history.csv`),
tests d'intégration, gate SonarCloud, puis bump de version, build,
publication PyPI, tag et push.
