---
id: 914
title: "QUALITY / SonarCloud gate vert (coverage new code + duplication)"
status: done
who: "Claude"
due_date: 
classified_at: 2026-07-07T14:22:56
classified_by: "key:7fb06ba1-e6a3-42cd-bb9b-f5170d50c484"
section: quality
section_title: "Quality & Release"
---

# #914 — QUALITY / SonarCloud gate vert (coverage new code + duplication)

Gate SonarCloud ERROR (new_coverage 71.4%<80%, new_duplicated 3.2%>3%). Voie 1, seuils inchangés.

---

## Résolution — CONFIRMÉE (scan commit 8ac5333)
Quality gate SonarCloud = OK:
- new_coverage 71.4% → 86.3% (≥80) ✓
- new_duplicated_lines_density 3.2% → 0.0% (≤3) ✓
- ratings reliability/security/maintainability/hotspots = OK

### Modifications
- check_msdefender/services/machine_resolver.py : resolve_machine (→ id,dns) + resolve_machine_id (→ id). Les 6 services l'utilisent (alerts, incidents, products, lastseen, onboarding, vulnerabilities×2) → duplication 0%.
- Tests +24 (132 total): test_machine_resolver, test_products_service, test_machines_service, test_config.
- Effets qualité: test_cov 62→74%, max_func_lines 212→192, funcs_over_50 11→9, refurb/vulture/pyright=0. Snapshot enregistré (cliquet).
- CI verte (build 3.10-3.13 + SonarCloud). sonar_gate.py passe → publish.sh ne bloquera plus.

### Garde-fous
- Seuils SonarCloud NON modifiés (Clean as You Code par défaut).
- min_file_cov reste 0 (integration.py/cli/handlers.py non testés) — hors périmètre, à resserrer plus tard.
---

[← retour à quality](index.md) · [voir log](../log/2026-07-07.md)
