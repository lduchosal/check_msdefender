---
id: 973
title: "fix(alerts): critical=0 ignoré par nagiosplugin — alerte High non résolue rend OK au lieu de CRITICAL"
status: done
who: ""
due_date: 
classified_at: 2026-07-07T14:22:58
classified_by: "key:7fb06ba1-e6a3-42cd-bb9b-f5170d50c484"
section: core
section_title: "Core"
---

# #973 — fix(alerts): critical=0 ignoré par nagiosplugin — alerte High non résolue rend OK au lieu de CRITICAL

# Bug : `alerts` retourne OK alors qu'une alerte High non résolue devrait donner CRITICAL

## Symptôme

```
(.venv) q@macbook check_msdefender % check_msdefender alerts -d batman.arcantel.ch
DEFENDER OK - Unresolved alerts for batman.arcantel.ch
2026-07-06T12:18:07.63Z - 'PowhidSubExec' malware was blocked on a Microsoft SQL server (New high) | alerts=1;1
```

1 alerte non résolue (severity **High**) → statut **OK** au lieu de **CRITICAL**.

## Cause racine (confirmée, reproduite)

Le CLI `alerts` fixe les seuils par défaut à `warning=1, critical=0`
(`check_msdefender/cli/commands/alerts.py:30-31`), avec l'intention « toute
alerte non résolue = CRITICAL ». Mais deux problèmes se combinent :

1. **`critical=0` est silencieusement détruit par nagiosplugin.**
   Dans `nagiosplugin/range.py`, `Range.__new__` fait `spec = spec or ''`.
   En Python `0` est falsy → `Range(0)` devient `Range('')` = *aucun seuil*
   (plage 0..∞, jamais violée). Preuve : la perfdata affichée est
   `alerts=1;1` — la partie critical est vide.

   ```python
   >>> from nagiosplugin import Range
   >>> Range(0)
   Range('')          # seuil perdu !
   >>> Range(0).match(1)
   True               # 1 alerte = "dans la plage" = OK
   >>> Range("0")     # en revanche la chaîne "0" fonctionne
   Range('0')         # plage 0:0 → 1 est hors plage → CRITICAL
   ```

2. **`warning=1` signifie plage Nagios `0:1`** → WARNING seulement si
   valeur > 1. Donc 1 alerte ne déclenche même pas WARNING.

Résultat : avec les défauts actuels, 1 alerte non résolue = OK.

Le contexte custom `DefenderScalarContext` (`check_msdefender/core/nagios.py:24`)
possède une logique `<=` corrigée, mais elle ne s'applique qu'au contexte
`found` (commande `detail`) — la commande `alerts` retombe sur la logique
standard de `ScalarContext`, donc sur le bug `Range(0)`.

## Également touché

- `incidents` : mêmes défauts `warning=1, critical=0`
  (`check_msdefender/cli/commands/incidents.py:30-31`) → même bug.
- Tout `-c 0` / `-w 0` passé explicitement par l'utilisateur sur n'importe
  quelle commande est ignoré de la même façon (0 falsy).

## Piste de correction

Convertir les seuils en chaîne avant de les passer à
`nagiosplugin.ScalarContext` (p.ex. dans `DefenderScalarContext.__init__` :
`str(warning) if warning is not None else None`, idem critical).
`Range("0")` est parsé correctement en plage `0:0`, contrairement à `Range(0)`.

À décider aussi : avec `critical=0` réparé, une alerte *Informational* non
résolue deviendra elle aussi CRITICAL (le service ne compte que
`len(unresolved_alerts)`, la sévérité n'influence pas la valeur —
`check_msdefender/services/alerts_service.py:84`). Confirmer si c'est voulu
ou si les alertes informational doivent être exclues du compte / pondérées.

## Tests attendus

- `alerts` avec 1 alerte High non résolue + défauts → exit code 2 (CRITICAL).
- `incidents` idem.
- `-c 0` explicite respecté (plage 0:0).
- perfdata affiche le seuil critical : `alerts=1;1;0`.


---

## Résolution

Résolu TDD (rouge → vert), commit `b96467f`, publié en **v1.4.3** (PyPI + tag `check-msdefender-1.4.3`).

### Modifications

- `check_msdefender/core/nagios.py` — `DefenderScalarContext.__init__` passe désormais les seuils en chaîne à `ScalarContext` (`str(warning)`/`str(critical)` si non-None) ; `Range("0")` est parsé en plage `0:0` au lieu d'être avalé par le `spec = spec or ''` de nagiosplugin. Les valeurs originales restent stockées pour la logique `<=` du contexte `found`.
- `tests/unit/test_nagios.py` — nouveau, 7 tests : seuils 0 (critical/warning) respectés, perfdata `alerts=1;1;0`, logique `found` inchangée, check end-to-end alerts (1 alerte → exit 2, 0 alerte → exit 0). 4 échouaient avant le fix.
- `tests/integration/test_cli_integration.py` — `test_detail_machine_not_found_warning` verrouillait le comportement bogué (`found=0;;1`) ; assertion mise à jour vers `found=0;0.0;1` (le `-W 0` explicite apparaît désormais dans la perfdata).

### Comportements obtenus

- `check_msdefender alerts -d batman.arcantel.ch` → `DEFENDER CRITICAL … | alerts=1;1;0`, exit code 2 (vérifié en réel contre l'API).
- `incidents` corrigé par le même chemin (mêmes défauts w=1/c=0, même contexte).
- Tout `-w 0` / `-c 0` explicite est maintenant respecté sur toutes les commandes.

### Garde-fous

- 143 tests verts (dont les 7 nouveaux), pipeline qualité 17/17 (pyright, ruff, refurb, vulture, interrogate 100 %, metrics-gate), gate SonarCloud PASSED.
- Question laissée ouverte (voulue ?) : une alerte *Informational* non résolue compte dans `len(unresolved_alerts)` et déclenche donc aussi CRITICAL — la sévérité ne pondère pas la valeur (`services/alerts_service.py:84`). À traiter dans une tâche séparée si indésirable.
---

[← retour à core](index.md) · [voir log](../log/2026-07-07.md)
