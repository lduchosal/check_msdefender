---
id: 920
title: "Fix 11 open SonarCloud code smells"
status: done
who: ""
due_date: 
classified_at: 2026-07-07T14:22:57
classified_by: "key:7fb06ba1-e6a3-42cd-bb9b-f5170d50c484"
section: quality
section_title: "Quality & Release"
---

# #920 — Fix 11 open SonarCloud code smells

Fix open SonarCloud code smells for `lduchosal_check_msdefender`.

Source: https://sonarcloud.io/project/issues?issueStatuses=OPEN&id=lduchosal_check_msdefender

11 open code smells:

- **products_service.py:56** — S3776 Cognitive Complexity 45 → ≤15 (CRITICAL, refactor)
- **products_service.py:145** — S7504 unnecessary `list()` on already-iterable
- **machines_service.py:25** — S1172 unused param `dns_name`
- **machines_service.py:25** — S1172 unused param `machine_id`
- **auth.py:13** — S6546 use union type (`X | None`)
- **nagios.py:15,16,117,118,153** — S6546 use union type (5×)
- **nagios.py:142** — S5754 reraise exception instead of swallowing

Definition of done: all 11 issues resolved, `pdm run check` green.

---

## Résolution

### Modifications
- `services/products_service.py` — `get_result` éclaté en helpers (`_group_by_software`, `_count_by_severity`, `_build_details`, `_build_detail_object`) → complexité cognitive 45 → <15 (S3776) ; suppression du `list()` superflu (S7504) ; score de sévérité via table `_SEVERITY_SCORES` au lieu d'un if/elif.
- `core/nagios.py` — `Optional[Union[float,int]]`/`Union[int,float]` → syntaxe `X | Y | None` (S6546 ×5) ; le `except SystemExit` est remplacé par un `Runtime.run()` non-sortant (print + return exitcode) → plus aucun signal de terminaison avalé (S5754).
- `core/auth.py` — `Union[...]` → `X | Y`, import `Union` retiré (S6546).
- `services/machines_service.py` — `del machine_id, dns_name` (motif déjà utilisé dans `DefenderSummary.ok`) pour les params imposés par l'interface `get_result` (S1172 ×2).

### Comportements obtenus
- `pdm run check` vert : 132 passed / 2 skipped, pyright 0, refurb 0, vulture 0, docstrings 100 %, gate palier 1 PASS.
- Sortie Nagios et codes de retour inchangés (couverts par la suite existante).

### Garde-fous
- `nagiosplugin` n'expose aucun type → handle typé `Any` (cohérent avec `service: Any` du fichier).
- Seul `integration.py:main` (C901=12) reste au-dessus du seuil : pré-existant, hors périmètre, toléré par le gate.
---

[← retour à quality](index.md) · [voir log](../log/2026-07-07.md)
