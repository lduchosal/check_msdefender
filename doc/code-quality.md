# Code quality — standard lduchosal

check_msdefender suit le standard qualité établi dans le projet kenboard.
Le pipeline est piloté par `publish.sh` (et `pdm run check` en local) ;
chaque étape doit être verte avant publication.

## Outils

| Étape            | Outil                         | `pdm run …`     |
|------------------|-------------------------------|-----------------|
| Imports absolus  | absolufy-imports              | `absolufy`      |
| Tri des imports  | ruff (`--select I`)           | `isort`         |
| Formatage        | ruff format                   | `format`        |
| Docstrings (fmt) | docformatter                  | `docformatter`  |
| Typage           | pyright (strict)              | `typecheck`     |
| Docstrings (lint)| flake8 + flake8-docstrings(-complete) | `flake8` |
| Couverture docs  | interrogate (≥ 95 %)          | `interrogate`   |
| Qualité code     | refurb                        | `refurb`        |
| Lint             | ruff                          | `lint`          |
| Code mort        | vulture                       | `vulture`       |
| Tests + coverage | pytest + coverage             | `test` / `test-ci` |
| **Gate bloquant**| scripts/quality_metrics.py    | `metrics-gate`  |
| Gate SonarCloud  | scripts/sonar_gate.py         | `sonar-gate`    |

> Le formatage reste sur **ruff** (unifié isort+format) — choix check_msdefender,
> au lieu du couple black+isort de kenboard.

## Gate bloquant (métriques + cliquet)

`scripts/quality_metrics.py --gate` applique, sur `check_msdefender/` :

- des **plafonds/planchers absolus** (`GATE_MAX` / `GATE_MIN`) ;
- un **cliquet best-ever** (`RATCHET_DOWN` / `RATCHET_UP`) lu dans
  `doc/quality-history.csv` : aucune métrique suivie ne peut régresser
  au-delà de sa meilleure valeur historique.

Les règles dont la donnée est absente (pas de `.coverage`) sont **sautées**,
pas échouées — d'où l'ordre « tests → gate » dans `publish.sh`.

### Procédure des paliers

Le gate matérialise un **palier courant**. Dès qu'il est vert :

1. enregistrer un snapshot — `pdm run metrics-record` ;
2. **resserrer** un ou plusieurs seuils (`GATE_MAX`/`GATE_MIN`) au palier
   suivant et committer.

Un gate vert n'est jamais un état stable : on resserre jusqu'aux cibles
finales. On ne **détend** JAMAIS un seuil sans décision humaine explicite.

### Palier 1 (état initial, 2026-06-25, v1.3.0)

Calé sur l'état mesuré à l'introduction du gate :
`max_func_lines=212`, `c901_over_10=2`, `test_cov≈62 %`, `min_file_cov=0`
(`integration.py` = stub d'entrée non couvert), `docstring_cov=100 %`,
`pyright/vulture/refurb/ruff_debt=0`.

Cibles de resserrage envisagées : `max_func_lines` → 50, `c901_over_10` → 0,
`test_cov` → 85 %+, `min_file_cov` → 50 %+ (couvrir `integration.py` /
`config.py` / `machines_service` / `products_service`).

## SonarCloud

`sonar-project.properties` (clé `lduchosal_check_msdefender`, org
`lduchosal`) + le job `sonarcloud` de `.github/workflows/python-package.yml`
poussent l'analyse à chaque push sur `master`. `publish.sh` pousse le commit
puis attend le quality gate via `scripts/sonar_gate.py`.

**Setup requis (une fois)** : créer le projet sur sonarcloud.io, ajouter le
secret `SONAR_TOKEN` au dépôt GitHub, et exporter `SONAR_TOKEN` en local pour
activer le gate dans `publish.sh` (sinon l'étape se saute proprement).
