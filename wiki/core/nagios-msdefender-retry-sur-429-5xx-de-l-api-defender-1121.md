---
id: 1121
title: "NAGIOS / MSDEFENDER_* - retry sur 429/5xx de l'API Defender"
status: done
who: "Claude"
due_date: 
updated_at: 2026-09-24T13:44:31
classified_at: 2026-09-24T13:40:14
classified_by: "key:7fb06ba1-e6a3-42cd-bb9b-f5170d50c484"
section: core
section_title: "Core"
---

# #1121 — NAGIOS / MSDEFENDER_* - retry sur 429/5xx de l'API Defender

## TL;DR

Les 429/5xx passagers de l'API Defender sont rejoués (3 tentatives, backoff, Retry-After plafonné à 5 s, ≤ 10 s d'attente par appel) au lieu de laisser un UNKNOWN pendant 12 h. Les échecs résiduels sortent sur une ligne (`UNKNOWN: MS Defender API 503 … after 3 attempts: GET …`), sans trace Python. Release et déploiement : faits par l'autre agent.

## Constat (24.09.2026)

Vers 11:25, **~85 services MSDEFENDER_* sur 17 hôtes** passent UNKNOWN avec la même erreur :

```
UNKNOWN: Failed to query MS Defender API: 503 Server Error: Service Temporarily Unavailable
for url: https://api.security.microsoft.com/api/machines?$filter=computerDnsName eq '<host>'&$select=id
```

- Indisponibilité passagère **côté Microsoft** (503, pas 429 = pas un quota). Rien de notre côté.
- Tout en *soft 1/10* : pas de notification (`msdefender-service` : `check_interval 1440`, `retry_interval 720`, max 10 tentatives).
- Re-check forcé de `cloud-srv-cfr-01 / MSDEFENDER_DETAIL` à ~13:20 ⇒ **OK** : l'API est revenue.
- Effet de bord : les UNKNOWN restent dans `nagioscli problems` jusqu'à 12 h (prochain retry de chaque service). Pas de re-check forcé en masse : ~170 appels d'un coup ≈ limite de ~100 appels/min de l'API.

## Cause côté plugin

`check_msdefender` 1.4.18, `core/defender.py` : chaque appel fait `response.raise_for_status()` **sans aucun retry**. La moindre erreur 5xx passagère devient donc un UNKNOWN qui dure 12 h. De plus, `core/nagios.py:162` imprime la **trace Python complète** dans la sortie Nagios.

## À faire

1. **Retry avec backoff** sur 429/500/502/503/504 dans le client HTTP du plugin (`requests.adapters.HTTPAdapter` + `urllib3.util.Retry`, ~3 tentatives, `backoff_factor`, `respect_retry_after_header=True`, méthodes GET et POST du token). Pire cas total < `service_check_timeout` Nagios (60 s), sachant que `[settings] timeout = 30` et que certaines sous-commandes font 2 appels (résolution DNS→id puis endpoint).
2. **Sortie d'erreur HTTP propre** sur une ligne (`UNKNOWN: MS Defender API 503 … after N attempts`), la trace Python réservée aux exceptions inattendues.
3. Tests unitaires (retry puis succès, retry épuisé ⇒ UNKNOWN propre, 4xx non-retryable ⇒ pas de retry).
4. Release + montée de version sur arc-srv-monitor-02 via le rôle `nagios` (`roles/nagios/tasks/check_msdefender.yml`), comme en #570.

## Hors périmètre / déconseillé

- Raccourcir `retry_interval` : plus d'appels pendant une panne, gain purement cosmétique.
- Relever `max_check_attempts` ou masquer l'UNKNOWN : une vraie panne de l'API doit rester visible.

## Résolution (24.09.2026, non commité, non releasé)

- `core/defender.py` : le client passe par une `requests.Session` + `HTTPAdapter(Retry)` ; tous les GET passent par un seul `_get_json` (les 6 blocs try/except dupliqués ont disparu).
  - Rejoué : 429/500/502/503/504, **3 tentatives**, backoff 0 s puis 4 s, `Retry-After` respecté mais **plafonné à 5 s** (`retry_after_max`) ⇒ ≤ 10 s d'attente par appel, ≤ 20 s pour les sous-commandes à 2 appels.
  - **Pas** de retry sur les timeouts/erreurs de connexion : avec `timeout = 30`, un seul rejeu ferait sauter les 60 s de `service_check_timeout`.
  - 4xx (hors 429) : jamais rejoué.
  - Token : obtenu par `azure-identity` (pas par requests), dont le pipeline azure-core rejoue déjà 429/5xx. Rien à ajouter côté POST.
- Message d'une ligne : `UNKNOWN: MS Defender API 503 Service Unavailable after 3 attempts: GET https://…/api/machines?$filter=computerDnsName eq 'host'&$select=id`.
- `core/nagios.py` : `CheckMSDefenderError` ⇒ une ligne ; la trace Python reste pour les exceptions inattendues.
- `pyproject.toml` : `requests>=2.32`, `urllib3>=2.6.3` en dépendances directes (`retry_after_max` n'existe que depuis 2.6.3) ; `pdm.lock` rafraîchi (flake8 7.3→7.4.1 au passage).
- Tests : 4 tests de retry contre un vrai serveur HTTP local (le vrai adaptateur urllib3 : 503→200, 503 épuisé ⇒ ligne unique, 400 sans retry, 429 Retry-After plafonné) + 2 tests de sortie Nagios. 197 passed, ruff/pyright OK.
- Docs : README (Transient API errors) + ARCHITECTURE.

## Reste à faire (utilisateur)

Point 4 : release + montée de version sur arc-srv-monitor-02 via le rôle `nagios`. Pas fait : action externe.
---

[← retour à core](index.md) · [voir log](../log/2026-09-24.md)
