---
id: 1150
title: "INCIDENT / incident-detail via Graph + chronologie Advanced Hunting"
status: done
who: "Claude"
due_date: 
updated_at: 2026-10-08T11:37:58
classified_at: 2026-10-08T10:51:53
classified_by: "key:7fb06ba1-e6a3-42cd-bb9b-f5170d50c484"
section: services
section_title: "Services"
---

# #1150 — INCIDENT / incident-detail via Graph + chronologie Advanced Hunting

**TL;DR** — `incident-detail` ne voyait que l'API alertes MDE (ni en-tête d'incident, ni verdicts, ni histoire d'attaque) → lecture de l'incident sur Graph (`SecurityIncident.Read.All`) et chronologie Advanced Hunting (`ThreatHunting.Read.All`) en remplacement de l'histoire d'attaque, repli MDE, permissions Azure documentées ; publié en 1.4.24.

## Besoin
Suite de #1149. Les permissions Graph `SecurityIncident.Read.All` et `ThreatHunting.Read.All` sont accordées (vérifié le 2026-10-08). Faire de `incident-detail` un rapport aussi complet que le portail, histoire d'attaque comprise.

## Constaté (incident 199)
- `GET graph /v1.0/security/incidents/{id}?$expand=alerts` → 200 : en-tête de l'incident (displayName, classification/determination, assignedTo, priorityScore, resolvingComment, lastModifiedBy, summary, tags, incidentWebUrl) et alertes v2 (alertWebUrl, recommendedActions, productName/serviceSource).
- Preuves Graph : 20 par alerte (= portail), avec **verdict**, **remediationStatus**, detectedRoles/roles, tags. Fichiers avec md5, taille et éditeur ; processus avec l'exécutable du parent ; deviceEvidence et userEvidence = onglet Actifs.
- `POST graph /v1.0/security/runHuntingQuery` → 200 : tables AlertEvidence et Device*Events. Volume sur l'activité ±5 min : 2375 évènements fichier, 245 processus, 303 DeviceEvents, 222 registre, 89 chargements d'image, 40 logons, 19 réseau → il faut filtrer.
- Toujours inaccessibles : le journal d'activité de l'incident (onglet Activité) et `api.security.microsoft.com/api/incidents` (403).

## Pistes
- Client Graph : token `https://graph.microsoft.com/.default`, `get_security_incident(id)` (expand alerts) et `run_hunting_query(kql)` (POST ; retry à étendre au POST).
- Source principale = Graph ; repli sur l'API alertes MDE (comportement actuel) si 401/403.
- Section CHRONOLOGIE (≈ histoire d'attaque) via KQL, sur la fenêtre firstActivity−N min … lastActivity+N min (option `--window`, défaut 10 min), pour chaque machine de l'incident :
  - arbre de processus des processus en preuve (ancêtres + descendants)
  - activité réseau, logons, registre et DeviceEvents (AV, ASR, etc.) des processus concernés
  - fichiers : uniquement ceux créés ou modifiés par les processus concernés ou dont le hash est en preuve, plafonnés et signalés comme tronqués le cas échéant
  - un `--timeline-all` ou un plafond configurable pour tout prendre
- Rendu texte chronologique (une ligne par évènement : heure, table, action, processus, cible) ; `--json` brut inchangé.

## Critères
- tests (mock Graph + hunting), repli MDE testé, README mis à jour, validation en réel sur l'incident 199

## Résolution

### Modifications
- `core/graph.py` (nouveau) : `GraphClient` avec `get_security_incident` (`GET /security/incidents/{id}?$expand=alerts`) et `run_hunting_query` (`POST /security/runHuntingQuery`), token `graph.microsoft.com/.default`, retry 429/5xx étendu au POST.
- `core/defender.py` : `build_session(methods)` et `describe_failure(error, api, method)` rendus publics et paramétrés (partagés avec Graph).
- `services/incident_timeline.py` (nouveau) : `TimelineBuilder` (requêtes KQL), `render_timeline`, `parse_time` / `window` / `printable`.
- `services/incident_report.py` (nouveau) : tout le rendu texte, sorti du service (gate : fichier ≤ 500 lignes, fonctions ≤ 50 lignes).
- `services/incident_detail_service.py` : Graph en source principale avec repli MDE, aplatissement des preuves Graph, chronologie.
- `cli/commands/incident_detail.py` : options `--window` (10 min par défaut), `--timeline-limit` (500 ; 0 = pas de chronologie), `--no-graph`.
- `README.md` : section « Required API permissions » (WindowsDefenderATP et Microsoft Graph, permissions d'application, consentement admin, qui utilise quoi) et doc `incident-detail` à jour.
- Tests : `test_graph_client.py`, `test_incident_timeline.py`, `TestGraphPath`, nouvelles options CLI (251 passed).

### Comportements obtenus (réel, incident 199, ~3 s)
- En-tête : displayName, classification falsePositive/notMalicious, assignedTo, priorityScore 55, lastModifiedBy, lien vers le portail, description complète.
- Preuves : 22 distinctes, dont Device et User (onglet Actifs) ; `verdicts: {"suspicious/active": 22}` ; fichiers avec md5, taille et éditeur ; processus avec l'exécutable du parent.
- Chronologie (fenêtre 16:20:50 → 16:46:07, 156 processus suivis) : 180 processus, 1965 fichiers (500 gardés, « first 500 of 1965 »), 7 réseau, 48 registre, 62 DLL, 66 logons, 116 DeviceEvents. On y lit l'histoire : tâche planifiée (`svchost` 11500) → `powershell` 22420 → `choco upgrade all -y` → installeurs 7-Zip / Git / nvm / NVIDIA → `nvm-setup.tmp` → `cmd` → les scripts PowerShell signalés.
- `--no-graph` ou Graph refusé : rapport MDE comme en 1.4.23, la raison est indiquée ; un incident inconnu donne `UNKNOWN: No alert found` (exit 3).

### Garde-fous
- Chronologie bornée : fenêtre de temps (le PID 26596 avait été réutilisé plus tôt dans la journée), appareils de l'incident, clés `DeviceId:PID`, 3 générations de descendants, plafond par table avec le total réel.
- Une table KQL en échec est notée `unavailable` sans faire échouer le rapport ; Graph refusé → repli MDE.
- Caractères de contrôle échappés (`\x00` dans du REG_MULTI_SZ rendait le fichier « binaire » pour grep).
- ruff, pyright strict, flake8, interrogate, refurb, vulture et gate de métriques OK.

### Limite
- L'onglet « Activité » (historique statut/classification) n'est exposé par aucune API ; le rapport le dit.

### Correctif post-review
- CI rouge sous Python 3.10 : `parse_time` comptait les chiffres du décalage horaire (`+00:00`) comme fractions de seconde (décalage perdu ; Python 3.10 n'accepte que 3 ou 6 décimales). La fraction est désormais isolée par regex et ramenée à 6 chiffres ; test ajouté pour un fuseau non UTC ; suite complète validée sous 3.10 (commit `5006310`).
- Publié en **1.4.24** (tag `check-msdefender-1.4.24`).
---

[← retour à services](index.md) · [voir log](../log/2026-10-08.md)
