---
id: 1149
title: "INCIDENT / Détail d'un incident"
status: done
who: "Claude"
due_date: 
updated_at: 2026-10-08T11:37:57
classified_at: 2026-10-08T09:27:55
classified_by: "key:7fb06ba1-e6a3-42cd-bb9b-f5170d50c484"
section: services
section_title: "Services"
---

# #1149 — INCIDENT / Détail d'un incident

**TL;DR** — Besoin d'un dump complet d'un incident pour analyse LLM/debug → nouvelle commande `check_msdefender incident-detail <incidentId|alertId>` qui écrit un rapport texte (résumé, machines, preuves dédupliquées, alertes) ou le JSON brut.

## Besoin
Ajouter une commande qui récupère **tout le détail d'un incident** et l'écrit dans un **fichier texte** destiné à l'analyse par un modèle (LLM) et au debug.

## Contenu attendu
Pour un incident donné (id), rassembler :
- en-tête incident : id, titre, sévérité, statut, classification/determination, dates (first/last activity), machines concernées
- chaque alerte rattachée (`incidentId`) : titre, catégorie, sévérité, statut, detectionSource, MITRE techniques, description, recommandation
- **evidence** de chaque alerte (`/api/alerts?$expand=evidence` ou `/api/alerts/{id}`) :
  - processus (nom, ligne de commande, PID, parent, sha1/sha256, compte)
  - utilisateurs / comptes (accountName, domainName, SID, UPN)
  - fichiers (chemin, nom, hashes, taille)
  - IPs, URLs, domaines, clés de registre
  - verdicts / remediationStatus (suspicious, malicious, etc.)
- endpoints liés éventuels : `/api/alerts/{id}/files`, `/users`, `/ips`, `/domains`, `/machines`

## Pistes techniques
- Les incidents sont aujourd'hui dérivés des alertes (`incidents_service.py` groupe par `incidentId`) — même scope MDE, pas de dépendance au Graph security API.
- Nouvelle méthode(s) dans `core/defender.py` via `_get_json` (retry/pagination existants).
- Nouveau service `services/incident_detail_service.py` + commande CLI (ex. `incident-detail --id <incidentId> [--output fichier.txt]`), stdout par défaut.
- Format texte structuré, sections claires, sans troncature (contrairement aux détails Nagios), champs absents ignorés proprement ; option `--json` brut à considérer.
- Rappel : la politique Resolved des checks ne s'applique pas ici — on veut le détail même d'un incident résolu.

## Critères
- tests unitaires (mock API) pour le service et la commande
- doc README/wiki de la commande

## Résolution

### Modifications
- `check_msdefender/core/defender.py` : `get_incident_alerts` (`/api/alerts?$filter=incidentId eq N&$expand=evidence`, sans `$select`, paginé), `get_alert` (`/api/alerts/{id}?$expand=evidence`), `get_alert_related` (`/api/alerts/{id}/<entity>`).
- `check_msdefender/core/models.py` : protocole client étendu, `AlertDict.id`.
- `check_msdefender/services/incident_detail_service.py` : résolution de la référence, collecte, déduplication des preuves, rendu texte.
- `check_msdefender/cli/commands/incident_detail.py` + enregistrement : `incident-detail REF [-o fichier] [--json] [-c] [-v]`.
- Tests : `tests/unit/test_incident_detail_service.py`, `TestIncidentDetailRequests` (client), `TestIncidentDetailCommand` (CLI).
- `README.md` : section « Incident Detail Report ».

### Comportements obtenus
- REF = incidentId entier, ou id d'alerte (résolu vers son incident). Un GUID est refusé avec explication — le GUID `4b0cae28-…` signalé était l'`aadTenantId`.
- Rapport : SUMMARY (période, sévérités, statuts, classification, MITRE, machines, comptes, preuves par type) → MACHINES (fiche complète, 1 fois par machine) → EVIDENCE dédupliquée à l'échelle de l'incident, numérotée, avec `alerts: [..]` → ALERT i/n (tous les champs non vides, description entière, commentaires, `evidence: #…`, entités related).
- Incidents Resolved inclus. Sortie stdout par défaut, `-o` vers fichier, `--json` = données brutes.
- Réel, incident 199 : 2 alertes, 21 preuves distinctes / 39 brutes (portail : 20), 401 lignes.

### Garde-fous
- Un appel refusé (403…) sur machine/entité related est écrit `unavailable (...)` au lieu de faire échouer le rapport.
- Clé de déduplication sans hashes/SID/evidenceCreationTime (une copie peut les omettre) ; la fusion complète les champs manquants.
- Erreur globale → `UNKNOWN: …` sur stderr, exit 3 ; pas de pollution de stdout (logs sur stderr).
- 224 tests passent ; ruff, pyright strict, flake8, interrogate OK.

### Limites (permissions de l'app)
- `/api/alerts/{id}/user|files|ips|domains` → 403 : manquent `User.Read.All`, `File.Read.All`, `Ip.Read.All`, `URL.Read.All` (les preuves couvrent déjà l'essentiel).
- Onglets portail « activité », « résumé », « histoire d'attaque » : API incidents (`/api/incidents`, Graph `security/incidents`) → 403 ; nécessite `Incident.Read.All` / `SecurityIncident.Read.All`. Suite possible si la permission est accordée.

### Publication
- Publié en **1.4.23** (tag `check-msdefender-1.4.23`), après correction de 3 remarques refurb ; étendu par #1150 (1.4.24).
---

[← retour à services](index.md) · [voir log](../log/2026-10-08.md)
