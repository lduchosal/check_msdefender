---
id: 1168
title: "SEC / Bump gh-action-pypi-publish to 1.14.2+ (emSign CA)"
status: done
who: "Claude"
due_date: 
updated_at: 2026-11-02T16:35:59
classified_at: 2026-11-02T16:33:55
classified_by: "key:7fb06ba1-e6a3-42cd-bb9b-f5170d50c484"
section: quality
section_title: "Quality & Release"
---

# #1168 — SEC / Bump gh-action-pypi-publish to 1.14.2+ (emSign CA)

**TL;DR** — Le workflow de publication utilisait `pypa/gh-action-pypi-publish` v1.13.0, qui embarque le CA racine emSign compromis (GHSA-5xjx-3w67-w9x9) → passé à **v1.14.3** (`7245906f`), pin SHA conservé, commit `57da3cb`. Les repos check_bitdefender et kanban-tui (`@release/v1`, non pinnés) ne sont pas traités ici.

## Contexte
Alerte GitHub : `pypa/gh-action-pypi-publish` < 1.14.2 embarque, via `certifi`, le certificat racine emSign (eMudhra), dont la compromission externe est suivie sur https://emudhra.we-have-a-problem.com. Impact pire cas : *Certificate not properly validated*. Ce trust store sert à Sigstore pour le Trusted Publishing et les attestations numériques.

## Constat
`.github/workflows/python-publish.yml:68` :
`uses: pypa/gh-action-pypi-publish@ed0c53931b1dc9bd32cbe73a98c7f6766f8a527e # v1.13.0` → version affectée.

## À faire
- Passer à >= v1.14.2 (dernière release), en gardant le pin par SHA de commit + commentaire de version.
- Vérifier le changelog entre 1.13.0 et la cible (inputs renommés ou dépréciés).
- Vérifier qu'aucun autre workflow n'utilise l'action.
- Valider à la prochaine release (publication PyPI + attestations OK).

## Résolution
- `.github/workflows/python-publish.yml:68` : `@ed0c5393… # v1.13.0` → `@7245906fb61fa33a13554f9d5fb856fe61758086 # v1.14.3` (tag annoté déréférencé vers le commit ; identique à `release/v1` au 2026-11-02).
- v1.14.3 plutôt que 1.14.2 : c'est elle qui porte le fix GHSA-5xjx-3w67-w9x9 + hash-checking des dépendances internes (#420).
- Changelog 1.13.0 → 1.14.3 : seul changement visible = `verbose` et `print-hash` activés par défaut (1.14.0) ; logs plus bavards, aucun impact fonctionnel. Twine 7 (1.14.2).
- Seul usage de l'action dans ce repo.
- Autres repos (/Users/q/Projects) : `check_bitdefender/.github/workflows/python-publish.yml:68` et `kanban-tui/.github/workflows/ci.yaml:133` utilisent `@release/v1` (branche flottante) → déjà sur 1.14.3 au prochain run, mais non pinnés par SHA (risque supply-chain). Non modifiés ici.
- Commit : `57da3cb fix(ci): bump pypa/gh-action-pypi-publish to v1.14.3 #1168`.
- Non fait : le workflow GitHub ne tourne qu'au prochain événement release ; check_bitdefender / kanban-tui non modifiés.
---

[← retour à quality](index.md) · [voir log](../log/2026-11-02.md)
