---
id: 1103
title: "SONARCLOUD / 3 new issues"
status: done
who: "Claude"
due_date: 
updated_at: 2026-09-24T13:26:35
classified_at: 2026-09-16T10:20:19
classified_by: "key:7fb06ba1-e6a3-42cd-bb9b-f5170d50c484"
section: quality
section_title: "Quality & Release"
---

# #1103 — SONARCLOUD / 3 new issues

Fix the 3 new open SonarCloud issues for `lduchosal_check_msdefender`.

Source: https://sonarcloud.io/project/issues?issueStatuses=OPEN&id=lduchosal_check_msdefender

3 open code smells (API `issues/search`, statuses OPEN/CONFIRMED) — tous **python:S5778** (MAJOR) :
« Refactor this exception test to have only one invocation possibly throwing an exception. »

- **tests/unit/test_path_probe.py:103** — `test_empty_command_raises` (créé 2026-09-16)
- **tests/unit/test_machine_resolver.py:38** — `TestResolveMachine.test_neither_raises`
- **tests/unit/test_machine_resolver.py:73** — `TestResolveMachineId.test_neither_raises`

---

## Résolution

### Modifications
- `tests/unit/test_path_probe.py` — `CommandPathProbe("   ", 5)` construit **avant** le bloc `pytest.raises` ; seul `probe.probe(...)` reste dedans. Le constructeur ne lève rien : la validation du template vide a lieu dans `_build_argv`, appelé par `probe()` — l'assertion teste donc toujours le même chemin.
- `tests/unit/test_machine_resolver.py` — `defender = Mock()` sorti du bloc `pytest.raises` dans les deux `test_neither_raises` ; seul l'appel `resolve_machine(...)` / `resolve_machine_id(...)` reste dedans.

### Comportements obtenus
- Aucun code de production touché ; tests uniquement.
- `pytest tests/unit/test_path_probe.py tests/unit/test_machine_resolver.py` : 21 passed.
- `pdm run check` vert : 183 passed / 2 skipped, pyright 0, vulture 0, refurb 0, docstrings 100 %, gate palier 1 PASS.

### Garde-fous
- Les issues ne se fermeront sur SonarCloud qu'après une analyse de `master` contenant le correctif (push → job SonarCloud de `python-package.yml`).

### Addendum — commit & release
- Commit **`5d0a319`** poussé sur `master`, puis `publish.sh` complet (26/26, exit 0) : tests 183 passed, gate métriques PASS, 8/8 tests d'intégration OK, **gate SonarCloud PASSED**.
- Publié en **v1.4.16** (PyPI + tag `check-msdefender-1.4.16`, commit `dc26322`).
- Vérifié via l'API SonarCloud après l'analyse : **0 issue ouverte**.
---

[← retour à quality](index.md) · [voir log](../log/2026-09-16.md)
