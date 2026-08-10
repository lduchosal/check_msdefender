---
id: 1008
title: "CI / Publish Package: ReadTimeout sur vulnerabilities — le ini généré force timeout = 10"
status: done
who: "Claude"
due_date: 
classified_at: 2026-08-10T17:48:39
classified_by: "key:7fb06ba1-e6a3-42cd-bb9b-f5170d50c484"
section: quality
section_title: "Quality & Release"
---

# #1008 — CI / Publish Package: ReadTimeout sur vulnerabilities — le ini généré force timeout = 10

Le workflow planifié **Publish Package** (tous les lundis 9:00 UTC) échoue une semaine sur trois à
l'étape *Publish*, toujours au même endroit : les tests d'intégration, sur la commande
`vulnerabilities`.

## Symptôme

```
check_msdefender.core.exceptions.DefenderAPIError: Failed to query MS Defender API:
HTTPSConnectionPool(host='api.security.microsoft.com', port=443): Read timed out. (read timeout=10)
✗ Integration tests failed
```

Pile : `nagios.py:130 check` → `vulnerabilities_service.py:42 get_result` →
`defender.py:161 get_machine_vulnerabilities`.

## Historique — flake récurrent, pas une régression

Sur les 12 derniers runs planifiés, 4 échecs, **tous le même ReadTimeout sur
`/vulnerabilities`** :

| Run | Date | read timeout |
|---|---|---|
| 31377705401 | 2026-08-10 | 10 s |
| 30812500117 | 2026-08-03 | 10 s |
| 29247598154 | 2026-07-13 | 10 s |
| 27139135484 | 2026-06-08 | 15 s (avant le fix #974) |

## Cause

Déjà diagnostiquée dans **#974** : `GET /api/machines/{id}/vulnerabilities` est un endpoint TVM
lourd, calculé côté Microsoft, dont la latence croît avec la surface vulnérable de la machine.

Le fix de #974 (v1.4.4) a câblé `[settings] timeout` jusqu'à `DefenderClient` avec un défaut
généreux de 30 s — mais **`.github/workflows/publish.yml` génère un `check_msdefender.ini` qui
écrit en dur `timeout = 10`**. Ce 10 s était auparavant ignoré (le bug de #974) ; depuis qu'il est
correctement honoré, la CI interroge l'endpoint le plus lourd avec le budget le plus court. Le fix
de #974 a donc mécaniquement aggravé ce flake au lieu de le corriger : 15 s effectifs → 10 s.

Écarts de configuration constatés :

- `check_msdefender.ini.example` → `timeout = 30` (défaut documenté)
- `README.md` → `timeout = 30`
- `.github/workflows/publish.yml` → `timeout = 10`  ← seul point restant

## Fix

Aligner le `timeout` du ini généré en CI. La contrainte des 60 s de `service_check_timeout` Nagios
qui justifiait un défaut prudent côté plugin **ne s'applique pas en CI** : ici les tests
d'intégration sont un *gate de release*, un run plus lent coûte moins cher qu'un blocage de
publication une semaine sur trois.

## Reste à faire

Relancer le workflow (`workflow_dispatch`) pour publier la version que le run du 2026-08-10 n'a pas
pu sortir.

---

## Résolution

Commit `cf53ce9` — `.github/workflows/publish.yml` : `timeout = 10` → `timeout = 60` dans le
`check_msdefender.ini` généré à l'étape *Create config file*, avec un commentaire expliquant
pourquoi la CI s'écarte du défaut plugin de 30 s.

Aucun code Python touché : le câblage `settings.timeout` → `DefenderClient` était déjà correct
depuis #974 (`get_timeout()` dans `core/config.py`, utilisé par les 8 commandes). Le seul défaut
restant était la valeur écrite par la CI.

### Vérifications

- Heredoc rejoué hors CI avec des secrets factices → `configparser` lit bien
  `sections: ['auth', 'settings', 'integration']`, `timeout: 60`, et les commentaires placés avant
  `[settings]` ne cassent pas le parsing.
- YAML rechargé via `yaml.safe_load` → les 6 steps du job `publish` sont intacts.
- `python-package.yml` et `python-publish.yml` ne lancent pas de tests d'intégration : `publish.yml`
  était le seul point à corriger.
- Aucun test ne s'appuie sur le contenu du workflow.

### Reste à faire

- Relancer **Publish Package** en `workflow_dispatch` pour sortir la version que le run du
  2026-08-10 n'a pas pu publier (la 1.4.7 est le dernier tag).
- Le `check_msdefender.ini` local (gitignoré) porte encore `timeout = 10` : un `publish.sh` lancé
  depuis le poste peut donc rencontrer le même flake. À porter à 30-60 s si le cas se présente.

### Addendum — publication et état réel du dépôt

- Le clone local était **en retard** : `1.4.8` avait déjà été publiée le **2026-07-27** par le
  dernier run planifié réussi (30264757715), tag `check-msdefender-1.4.8`, présente sur PyPI. Les
  runs du 08-03 et du 08-10 n'ont donc pas bloqué un backlog : chacun a simplement **sauté une
  release patch hebdomadaire**.
- `git push` a d'abord été rejeté (divergence sur `master`). Rebase de la correction sur
  `origin/master` (`73fafa9`) → le commit final est **`cf53ce9`**, poussé sur `master`.
- `check_msdefender.ini` local (gitignoré) porté de `timeout = 10` à **60**, aligné sur la CI, pour
  que `publish.sh` lancé depuis le poste ne rencontre pas le même flake.
- `ken wiki lint` : 0 erreur / 0 warning (4 sections, 7 classifications) ; tâche classée `quality`.
---

[← retour à quality](index.md) · [voir log](../log/2026-08-10.md)
