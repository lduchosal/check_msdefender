---
id: 974
title: "CONFIG / TIMEOUT / not read"
status: done
who: "Claude"
due_date: 
classified_at: 2026-07-07T14:22:59
classified_by: "key:7fb06ba1-e6a3-42cd-bb9b-f5170d50c484"
section: core
section_title: "Core"
---

# #974 — CONFIG / TIMEOUT / not read

- vulnerabilities → GET /api/machines/{id}/vulnerabilities — endpoint TVM lourd, calculé côté Microsoft, dont la latence croît avec la surface vulnérable de la machine. Pour zarbi (9 produits,   
  ~110 CVE, des dizaines de chemins d'evidence), la réponse dépasse les 15 s → ReadTimeout.                                                                                                          
  - products → GET /api/machines/SoftwareVulnerabilitiesByMachine — rapide, d'où l'impression que « la CLI marche ».                                                                                 
                                                                                                                                                                                                     
  Preuve que Nagios n'y est pour rien : sur zarbi.arcantel.dev, les six autres checks MSDEFENDER (ALERTS, INCIDENTS, LASTSEEN, ONBOARDING, DETAIL, PRODUCTS) passent par la même venv et la même API 
  depuis Nagios et répondent tous — seul VULNERABILITIES est UNKNOWN. Et sur v-srv11 (1 seule CVE), VULNERABILITIES est OK : c'est bien le volume de données TVM de zarbi qui fait dépasser le seuil.
  Le traceback confirme d'ailleurs que le premier appel (résolution machine par DNS) réussit ; c'est le second qui expire.                                                                           
                                                                                                                                                                                                     
  Bug aggravant découvert dans le plugin                                                                                                                                                             
                                                                                                                                                                                                     
  En lisant le source 1.4.3 (sdist PyPI) : le timeout de la section [settings] du check_msdefender.ini est documenté mais jamais lu. Les 8 commandes CLI instancient DefenderClient(authenticator,   
  verbose_level=verbose) sans passer timeout, donc le défaut hard-codé de 15 s (DefenderClient.__init__) s'applique toujours. On ne peut donc pas corriger par la config sur monitor-02 — le fix est 
  côté plugin.                                                                                                                                                                                       
                                                                                                                                                                                                     
  Fix proposé (consigné sur la carte)                                                                                                                                                                
                                                                                                                                                                                                     
  1. check-msdefender 1.4.4 : câbler settings.timeout (et/ou une option --timeout) jusqu'à DefenderClient, avec un défaut plus généreux (~30 s). Contrainte : le check fait 2 appels séquentiels,    
  garder le pire cas sous le service_check_timeout Nagios (60 s).                                                                                                                                    
  2. Re-déployer la venv monitor-02 (nagios_check_msdefender.yml), puis nagioscli check + re-status sur zarbi pour confirmer.                                                                        
                                                                                                                                                                                                     
  Pour clore la démonstration, tu peux lancer dans ton shell root déjà ouvert sur monitor-02 : check_msdefender vulnerabilities -d zarbi.arcantel.ch — il devrait timeouter aussi en CLI. Dis-moi si 
  tu veux que j'ouvre la carte de fix du plugin.

---

## Résolution

Résolu TDD (rouge → vert), commit `58fbfc4`, publié en **v1.4.4** (PyPI + tag `check-msdefender-1.4.4`).

### Modifications

- `check_msdefender/core/config.py` — nouvelle fonction `get_timeout(config)` : lit `[settings] timeout`, fallback **30 s** (aligné sur le défaut documenté dans `check_msdefender.ini.example`).
- `check_msdefender/core/defender.py` — défaut `DefenderClient.timeout` 15 s → **30 s**.
- Les **8 commandes CLI** (alerts, incidents, lastseen, onboarding, vulnerabilities, machines, products, detail) passent désormais `timeout=get_timeout(cfg)` à `DefenderClient`.
- `README.md` — exemples `[settings] timeout = 5` → `30`.
- Tests : `test_config.py` (+3 : fallback sans section/sans clé, lecture de la valeur), `test_defender_client.py` (+1 : défaut 30 s), `test_cli_integration.py` (+2 : `timeout = 45` configuré atteint le client, défaut 30 sans `[settings]`). Les 12 mocks d'intégration qui renvoyaient un dict au lieu d'un `ConfigParser` ont été corrigés.

### Comportements obtenus

- `settings.timeout` du `check_msdefender.ini` est enfin honoré — corrigeable par config sur monitor-02 sans re-release.
- Sans config : 30 s au lieu de 15 s hard-codés. Pire cas des 2 appels séquentiels = 60 s ; avec la résolution DNS ~1 s, on reste sous le `service_check_timeout` Nagios en pratique (sinon abaisser via `timeout = 25`).
- Smoke test réel : `vulnerabilities -d batman.arcantel.ch` répond (WARNING de seuil légitime) en honorant le `timeout = 10` du ini local.

### Garde-fous

- 149 tests verts (dont 6 nouveaux), pipeline qualité 17/17, gate SonarCloud PASSED.

### Reste à faire (hors repo)

- Re-déployer la venv monitor-02 (`nagios_check_msdefender.yml`) en 1.4.4, poser `timeout = 45` dans le ini si besoin, puis `nagioscli check` + re-status sur zarbi pour confirmer la disparition du ReadTimeout.
---

[← retour à core](index.md) · [voir log](../log/2026-07-07.md)
