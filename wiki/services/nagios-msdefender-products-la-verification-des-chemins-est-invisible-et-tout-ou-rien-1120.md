---
id: 1120
title: "NAGIOS / MSDEFENDER_PRODUCTS - la verification des chemins est invisible et tout-ou-rien"
status: done
who: "luc.duchosal"
due_date: 
updated_at: 2026-09-24T13:53:37
classified_at: 2026-09-24T13:53:15
classified_by: "key:7fb06ba1-e6a3-42cd-bb9b-f5170d50c484"
section: services
section_title: "Services"
---

# #1120 — NAGIOS / MSDEFENDER_PRODUCTS - la verification des chemins est invisible et tout-ou-rien

## TL;DR

- **Problème** : la sonde `--verify-paths` tournait, mais la sortie ne le montrait pas. Chemins bruts et non triés, aucune mention de la sonde quand rien n'était retiré. L'opérateur voyait des chemins ABSENT, jamais la copie PRESENT qui garde le produit au score.
- **Livré en 1.4.19** : la première ligne annonce toujours `path verification: N paths, A absent, U unreadable`. Chaque chemin affiché porte son verdict (`[PRESENT 3.12.9]`, `[ABSENT]`…), les présents en tête.
- **Tranché** : la règle par produit reste du tout-ou-rien (une copie vulnérable présente = trouvaille réelle). Un binaire d'une autre architecture relève du registre d'exceptions #1368.
- Score, seuils et perfdata inchangés.

---

## Symptôme

`MSDEFENDER_PRODUCTS` sur `q.arcantel.dev` est CRITICAL (score 2163) et la sortie affiche,
pour le produit le plus cher (python 3.12.9.0, 442 pts), des chemins qui **n'existent plus
sur l'hôte** :

```
- c:\program files\jetbrains\jetbrains rider 2026.2.2\...\rust-lldb\win\x64\bin\python.exe
- c:\program files\jetbrains\jetbrains rider 2026.2.2\...\rust-lldb\win\x86\bin\pythonw.exe
```

Lecture naturelle de l'opérateur : *le check ne vérifie pas sur l'hôte distant*.

## Mesure (21.09.2026, sur q qui est le poste de l'opérateur)

La vérification **tourne bien** — ce n'est pas le bug :

- perfdata : `products=2163;500;2000 raw=2328 stale=165 unverified=0` ;
- 1 entrée réellement retirée : `openssl 3.6.3.0 — removed: c:\program files (x86)\microsoft\edgecore\152.0.4191.66\undocked_copilot\libcrypto-3-x64.dll` ;
- test local des chemins affichés : `rust-lldb\win\x64\bin\python.exe` et `...\x86\bin\pythonw.exe` = **ABSENT**, `rust-lldb\win\aarch64\bin\python.exe` = **PRESENT, ProductVersion 3.12.9** (exactement la version rapportée par MDE).

Donc : 5 des 6 chemins du produit ont disparu, **un seul survit** — un binaire **aarch64,
non exécutable sur un hôte x64** — et il suffit à maintenir 442 pts au score.

Parc au même instant : 6 hôtes en `path verification FAILED: ssh ... timed out` (postes
éteints) — comportement fail-closed attendu, score brut publié, pas un faux vert. Les autres
hôtes joignables sont à `stale=0 unverified=0`.

## Cause (check-msdefender 1.4.18, `services/products_verifier.py`)

1. **Règle tout-ou-rien par produit** : `_classify()` ne sort une entrée du score que si
   AUCUN chemin n'est `PRESENT` (motif `removed`), ou si tous les présents sont en version
   strictement supérieure (`upgraded`). Un seul fichier résiduel — fût-il d'une autre
   architecture — annule la preuve de suppression des cinq autres.
2. **La sortie n'annote pas les chemins** : `_build_detail()` imprime les 4 premiers chemins
   d'un `set` non trié, **bruts**, sans le verdict de la sonde. L'opérateur voit donc en
   priorité des chemins ABSENT et jamais celui qui justifie le comptage.
3. **Rien ne dit que la sonde a tourné** quand elle ne retire rien : la clause
   `(raw ..., N stale excluded: ...)` n'apparaît qu'en cas de périmé ; sinon la ligne est
   identique à celle d'un check sans `--verify-paths`. Seule la perfdata le dit.

## Pistes (à trancher)

- **Rendre la vérification visible** : toujours une mention dans la première ligne, même à
  zéro retrait (`path verification: 27 chemins, 5 absents, 0 illisibles`).
- **Annoter chaque chemin affiché** : `PRESENT 3.12.9` / `ABSENT`, et **trier les présents
  d'abord** — le chemin qui décide du score doit être celui qu'on lit.
- **Question de fond, à ne pas bâcler** : faut-il retirer les chemins ABSENT du faisceau et
  ne garder que les présents ? Cela ne change pas le score (le score est porté par le couple
  produit+version, pas par le chemin), mais cela change ce que l'opérateur croit voir.
  Le cas « binaire d'une autre architecture » relève plutôt du **registre d'exceptions
  (#1368)** que du filtre de périmé : le fichier est là, il ne peut simplement pas s'exécuter.
- Ne PAS relever les seuils (cf. MSDEFENDER_VULNERABILITIES #363, check rendu décoratif).

## Hors périmètre

Le plancher structurel de q (~2100 pts : openssl de git/php/openssl-win64/OneDrive, caches
teamcityagent, .venv python) est le sujet du registre d'exceptions #1368, pas celui-ci.

---

## Résolution

Commit `77864c1` — `feat(products): show the path verdicts and always announce the verification`.

### Modifications
- `services/products_verifier.py` : `VerificationOutcome.verdicts` conserve le verdict de chaque chemin soumis (chemin sans réponse ⇒ `ERROR`) ; propriétés `absent` / `unreadable`.
- `services/products_service.py` : la première ligne annonce toujours la sonde ; chaque chemin affiché porte son verdict, trié PRESENT → DENIED/ERROR → ABSENT, troncature à 4 appliquée après le tri ; sans `--verify-paths`, chemins simplement triés.
- `README.md`, `ARCHITECTURE.md` : règle par produit et nouvelle sortie documentées.
- Tests : `test_products_verifier.py`, `test_products_service_verify.py`.

### Comportements obtenus
```
2 vulnerable products, score: 105, path verification: 27 paths, 5 absent, 0 unreadable

python 3.12.9.0 (python) - Score: 442, ...
 - [PRESENT 3.12.9] c:\...\rust-lldb\win\aarch64\bin\python.exe
 - [ABSENT] c:\...\rust-lldb\win\x64\bin\python.exe
```
Le chemin lu en premier est celui qui maintient le produit au score.

### Question de fond — tranchée
- **Règle tout-ou-rien conservée** : une copie présente en version vulnérable est une vraie trouvaille ; la sortir du score serait un faux vert. Test dédié (5 ABSENT + 1 PRESENT ⇒ compté).
- **Chemins ABSENT gardés, en dernier** : les masquer cacherait que 5 copies sur 6 ont disparu. Le binaire d'une autre architecture relève du registre d'exceptions #1368.

### Garde-fous
- Score, seuils et perfdata inchangés ; échec de sonde toujours fail-closed (ligne `path verification FAILED` prioritaire).
- `pdm run check` : 190 passed, pyright 0, gate palier 1 PASS.
---

[← retour à services](index.md) · [voir log](../log/2026-09-24.md)
