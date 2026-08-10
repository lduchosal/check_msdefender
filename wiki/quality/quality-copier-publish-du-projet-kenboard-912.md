---
id: 912
title: "QUALITY / copier publish du projet kenboard"
status: done
who: "Claude"
due_date: 
classified_at: 2026-07-07T14:22:54
classified_by: "key:7fb06ba1-e6a3-42cd-bb9b-f5170d50c484"
section: quality
section_title: "Quality & Release"
---

# #912 — QUALITY / copier publish du projet kenboard

La qualité du projet check_msdefender devrait être upgradée pour respecter les standards lduchosal établis dans le projet kenboard.

Comparer le publish.sh de check_msdefender avec celui de ../2113.ch/kenboard/publish.sh et aligner check_msdefender sur le standard kenboard.

---

## Résolution

Stack de formatage conservée sur **ruff** (décision utilisateur). Les 4 gates kenboard portés, adaptés au layout check_msdefender (check_msdefender/, pyright, branche master, pdm-bump). Code mis au niveau pour passer les nouveaux gates (gate VERT day-1, philosophie cliquet).

### Modifications
- publish.sh réécrit : ajout des étapes absolufy / flake8 / **metrics-gate** / **SonarCloud gate**, + 'git pull --rebase' en début de process (publish-only) pour éviter le rejet du push final. 26 étapes en publish, 17 en --quality.
- scripts/quality_metrics.py : gate bloquant (plafonds/planchers absolus + cliquet best-ever vs doc/quality-history.csv). Palier 1 calé sur l'état mesuré.
- scripts/sonar_gate.py + sonar-project.properties (clé lduchosal_check_msdefender, branche master).
- .github/workflows/python-package.yml : coverage.xml + job SonarCloud.
- pyproject.toml : deps dev (absolufy-imports, flake8(-docstrings(-complete)), certifi) ; scripts absolufy/flake8/metrics(-record/-gate)/sonar-gate ; test/test-ci/test-cov émettent coverage.xml ; 'check' converti en {composite=[...]} (bug pré-existant : array nu = cmd+args).
- doc/code-quality.md (politique gate + paliers), doc/quality-history.csv (1er snapshot).
- Code : imports absolus (absolufy, 10 fichiers) ; sections Raises (DCO050) sur ~18 fonctions ; 2 docstrings __init__ ; 2 lignes >125 wrappées ; noqa vulture malformé remplacé par 'del results' (param d'interface nagiosplugin).
- Hygiène git : .coverage dé-tracké, .pdm-python (chemin runner CI commité par erreur) dé-tracké + gitignore (coverage.xml/.coverage/htmlcov/.scannerwork/.pdm-python).

### Comportements obtenus
- 'pdm run check' (composite complet) : VERT. 108 tests passent, 2 skip.
- flake8 / ruff / vulture(0) / refurb(0) / pyright(0 err) / interrogate(100%) : clean.
- metrics-gate (palier 1) : PASS. publish.sh : syntaxe OK.

### Garde-fous
- Gate cliquet : aucune métrique suivie ne peut régresser sous sa meilleure valeur historique ; règles coverage sautées si .coverage absent (ordre tests→gate).
- SonarCloud gate se saute proprement si SONAR_TOKEN absent (publish non brické avant câblage Sonar).
- SETUP REQUIS (utilisateur) : créer le projet sonarcloud.io, ajouter secret SONAR_TOKEN au repo + exporter en local. Sinon le gate Sonar est inactif.
- Suite : tâche #913 (modèles typés sérialisables dans quality_metrics.py) ; resserrer les paliers du gate (cf doc/code-quality.md).
---

[← retour à quality](index.md) · [voir log](../log/2026-07-07.md)
