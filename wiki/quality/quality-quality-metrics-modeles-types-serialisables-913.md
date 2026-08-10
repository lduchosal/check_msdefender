---
id: 913
title: "QUALITY / quality_metrics: modèles typés sérialisables"
status: done
who: "Claude"
due_date: 
classified_at: 2026-07-07T14:22:55
classified_by: "key:7fb06ba1-e6a3-42cd-bb9b-f5170d50c484"
section: quality
section_title: "Quality & Release"
---

# #913 — QUALITY / quality_metrics: modèles typés sérialisables

Dans scripts/quality_metrics.py, les structures internes utilisent des tuples positionnels moches et peu lisibles, ex: list[tuple[int, str, str]] pour les offenders (longueur, nom, localisation).

Remplacer par des modèles propres et auto-sérialisables (pydantic v2, ou dataclasses stdlib avec asdict — à trancher : pydantic ajoute une dépendance dev alors que check_msdefender n'en dépend pas en prod). Objectifs:
- offenders (fichiers/fonctions) et le snapshot de métriques en objets nommés
- sérialisation JSON/CSV dérivée des modèles (plus de dict ad-hoc)
- typage clair, lisible, sans tuples positionnels

Tâche issue du review de #912 (portage du standard qualité kenboard).
---

[← retour à quality](index.md) · [voir log](../log/2026-07-07.md)
