# Rapport d'Analyse — Typologie des Incidents de Production Diagnostiqués par EvidenceTool

**Date d'analyse :** 18 septembre 2026
**Version examinée :** 1.0.2 (`pyproject.toml`) / état du workspace
**Périmètre :** code source, providers, modèles, décision, policies, catalogues, CLI, tests, schéma JSON, documentation et contrôles qualité disponibles dans le workspace.

## 1. Objet et conclusion exécutive

EvidenceTool est un moteur de diagnostic opérationnel en lecture seule. Il collecte des observations auprès de providers, les transforme en preuves `PASS`, `FAIL` ou `UNKNOWN`, corrèle ces preuves avec des situations connues, puis applique une policy qui produit `ALLOW`, `BLOCK` ou `HUMAN_REVIEW`.

**Verdict exécutif :** le logiciel est **prêt pour un usage de production contrôlé comme outil de diagnostic et de garde-fou**, sur les domaines et environnements effectivement validés. Il n'est **pas prêt pour une remédiation autonome non supervisée ni pour une promesse de couverture générale des incidents**. Avant une mise en service critique, il reste à lever les incohérences contractuelles et à renforcer les contrôles de release décrits en section 8.

Le code décrit **64 situations cataloguées** dans huit catalogues YAML. Elles couvrent principalement :

- les pannes de service et de configuration Nginx, TLS et systemd ;
- la saturation et les états anormaux de processus Linux ;
- les ruptures de connectivité réseau, du DNS jusqu'à HTTP/TLS ;
- les indisponibilités et saturations PostgreSQL, MySQL, Redis et des dépendances HTTP ;
- les cascades de défaillance dans une architecture distribuée ;
- les arrêts, crash loops et health checks défaillants de conteneurs Docker ;
- les incidents de scheduling, image, mémoire, configuration et nœud Kubernetes.

La couverture est plus forte pour le diagnostic déterministe de signaux isolés et de scénarios de corrélation connus que pour une analyse générale de cause racine. Une situation ne constitue un diagnostic que si toute sa signature correspond exactement aux statuts attendus. Toute preuve manquante ou `UNKNOWN` pertinente rend l'état ambigu et conduit normalement à un blocage en policy V2.

Les contrôles exécutés pendant cette analyse donnent :

- `pytest tests/ -q` : **223 tests réussis** ;
- `ruff check src/ tests/` : **aucun problème** ;
- `mypy src/` : **aucune erreur** ;
- `bandit -r src/ -c pyproject.toml` : **aucun problème identifié** sur 5 871 lignes analysées ;
- `pip-audit` : **aucune alerte retournée** dans l'environnement courant.

Ces résultats attestent de la santé du workspace testé, mais ne remplacent pas les E2E sur les plateformes cibles ni les contrôles de déploiement et d'exploitation.

## 2. Méthode d'analyse et chaîne fonctionnelle

L'analyse a été menée par lecture croisée des providers, modèles, orchestrateur, catalogues, policies et tests. Les identifiants ci-dessous sont ceux présents dans le code et les fichiers YAML.

```text
Incident
  -> Providers de collecte
  -> Observation horodatée
  -> Evidence Evaluator: PASS / FAIL / UNKNOWN / STALE
  -> Corrélation déterministe: Situation / OperationalState
  -> Policy V2: allow / blocked_by / required_evidence
  -> Decision Engine: BLOCK > HUMAN_REVIEW > ALLOW
  -> Validation d'intégrité
  -> Recommendation advisory
```

Points structurants :

- `diagnose.py` détermine les namespaces requis par la policy et le catalogue, collecte uniquement ces providers, valide leur namespace de sortie et transforme les erreurs en observations `UNKNOWN`.
- `correlate_state()` combine les éléments d'une signature avec une logique AND. Il peut retourner plusieurs situations, conserver les écarts et marquer l'état `ambiguous`.
- En V2, `blocked_by` est évalué avant l'ambiguïté, puis les situations `allow` sont recherchées. Une situation autorisée avec `human_approval: true` aboutit à `HUMAN_REVIEW`; sinon à `ALLOW`.
- Les permissions de capabilities et la confiance des providers contrôlent la collecte, mais ne sont pas des typologies d'incidents. Un refus de capability produit une preuve `UNKNOWN` et une violation d'intégrité suivie par les métriques.
- La recommandation est informative et ne peut pas modifier la décision.

## 3. Typologies d'incidents par domaine

### 3.1 Nginx, TLS, systemd et filesystem

**Providers :** `nginx`, `tls`, `systemd`, `filesystem`  
**Catalogue :** `catalogs/nginx.yaml`  
**Policy :** `policies/nginx.yaml`, action `restart_nginx`, risque `LOW`

| Situation | Signature principale | Traitement policy |
|---|---|---|
| `NGINX_SERVICE_DOWN` | Service systemd installé mais inactif, configuration valide, TLS valide et espace disque disponible | `ALLOW` possible |
| `NGINX_CONFIG_INVALID` | `nginx.config_valid: FAIL` | `BLOCK` |
| `TLS_CERTIFICATE_MISSING` | `tls.certificate_exists: FAIL` | `BLOCK` |
| `TLS_CERTIFICATE_EXPIRED` | `tls.certificate_valid: FAIL` | `BLOCK` |
| `TLS_KEY_MISSING` | `tls.private_key_exists: FAIL` | `BLOCK` |
| `TLS_KEY_MISMATCH` | `tls.key_matches_certificate: FAIL` | `BLOCK` |
| `NGINX_SERVICE_NOT_INSTALLED` | `systemd.service_exists: FAIL` | `BLOCK` |
| `DISK_FULL` | `filesystem.disk_space_available: FAIL` | `BLOCK` |
| `DISK_PRESSURE` | `filesystem.disk_pressure: FAIL` | Cataloguée, non bloquée par cette policy |
| `NETWORK_UNREACHABLE` | `network.host_reachable: FAIL` | Cataloguée, non bloquée par cette policy |

Le provider Nginx valide la configuration en lecture seule. Le provider TLS vérifie l'existence, la validité temporelle et la correspondance de la clé privée avec le certificat. Systemd distingue notamment service absent et service inactif. Filesystem compare l'espace libre à un seuil configurable.

**Lecture opérationnelle :** le redémarrage n'est autorisé que pour un service identifié comme arrêté et après validation de préconditions de configuration, TLS, présence du service et stockage. La policy est fail-closed sur les preuves critiques (`on_unknown: BLOCK`), mais ignore l'incertitude sur l'état actif et l'espace disque lorsqu'elle ne suffit pas à établir une situation interdite.

### 3.2 Processus Linux

**Provider :** `process`  
**Catalogue :** `catalogs/process.yaml`  
**Policy :** `policies/process.yaml`, action `restart_process`, risque `MEDIUM`

| Situation | Signal | Traitement policy |
|---|---|---|
| `PROCESS_HEALTHY` | Présent, running, état nominal, non-zombie | `BLOCK` |
| `PROCESS_NOT_FOUND` | `process.exists: FAIL` | `ALLOW` possible |
| `PROCESS_CRASHED` | `process.running: FAIL` | `ALLOW` possible |
| `PROCESS_ZOMBIE` | `process.zombie: FAIL` | `ALLOW` possible |
| `PROCESS_IO_WAIT` | `process.state: FAIL`, état Linux `D` | `ALLOW` possible |
| `PROCESS_CPU_SATURATION` | `process.cpu_usage: FAIL` au-delà du seuil | Cataloguée, non reliée à `blocked_by` ou `allow` |
| `PROCESS_MEMORY_PRESSURE` | `process.memory_usage: FAIL` au-delà du seuil | Cataloguée, non reliée à une décision |
| `PROCESS_FD_EXHAUSTION` | `process.open_files: FAIL` près de la limite | Cataloguée, non reliée à une décision |

Le provider inspecte aussi `process.thread_count`, mais cette observation ne participe à aucune signature. Les seuils CPU, mémoire et descripteurs sont donc diagnostiqués au niveau de la collecte/evidence, sans parcours de décision complet dans la policy actuelle.

### 3.3 Réseau en chaîne de dépendances

**Provider :** `network`  
**Catalogue :** `catalogs/network.yaml`  
**Policy :** `policies/network.yaml`, action `restart_service`, risque `LOW`

| Situation | Signature de corrélation | Traitement policy |
|---|---|---|
| `NETWORK_HEALTHY` | DNS, route, hôte et port en `PASS` | `ALLOW` possible |
| `NETWORK_DNS_FAILURE` | DNS en échec, par exemple `NXDOMAIN` | `BLOCK` |
| `NETWORK_ROUTE_FAILURE` | DNS OK, route absente | `BLOCK` |
| `NETWORK_HOST_UNREACHABLE` | DNS OK, hôte inaccessible | `BLOCK` |
| `NETWORK_TCP_REFUSED` | Hôte OK, port refusé | `BLOCK` |
| `NETWORK_TLS_HANDSHAKE_FAILURE` | Port OK, négociation TLS en échec | `BLOCK` |
| `NETWORK_HTTP_5XX` | Transport OK, HTTP en erreur 5xx | `BLOCK` |

La chaîne différencie les couches DNS, routage, hôte, TCP, TLS et HTTP. Les sondes TLS et HTTP sont conditionnelles au contexte de diagnostic. Les détails d'erreur comme `CONNECTION_REFUSED`, `TIMEOUT`, `NXDOMAIN` et `NO_ROUTE_TO_HOST` sont collectés, mais ne sont pas tous des situations distinctes.

### 3.4 Données, middleware et dépendance HTTP

**Providers :** `postgres`, `mysql`, `redis`, `dependency`  
**Catalogue :** `catalogs/data.yaml`  
**Policy :** `policies/data.yaml`, action `restart_application`, risque `HIGH`

#### PostgreSQL

- `POSTGRES_HEALTHY` : instance joignable, connexions acceptées et pool nominal ; situation autorisable.
- `POSTGRES_UNREACHABLE` : `postgres.reachable: FAIL` ; bloquant.
- `POSTGRES_POOL_EXHAUSTED` : instance joignable mais pool saturé ; bloquant.
- `POSTGRES_READ_ONLY_REPLICA` : nœud en recovery/read-only alors qu'un primaire est attendu ; bloquant.

#### MySQL

- `MYSQL_HEALTHY` : instance joignable, ping réussi et connexions disponibles ; situation autorisable.
- `MYSQL_TOO_MANY_CONNECTIONS` : limite atteinte, notamment erreur 1040 ; bloquant.

`mysql.read_only` et `mysql.latency_ms` sont collectées mais ne sont pas utilisées dans une situation actuelle.

#### Redis

- `REDIS_HEALTHY` : serveur joignable, PING réussi et pression mémoire nominale ; situation autorisable.
- `REDIS_UNREACHABLE` : serveur ou port inaccessible ; bloquant.
- `REDIS_AUTH_FAILURE` : authentification rejetée ; bloquant.
- `REDIS_OOM_MAXMEMORY` : plafond `maxmemory` atteint ; bloquant.
- `REDIS_REPLICATION_BROKEN` : lien de réplication perdu ; cataloguée, mais absente de `blocked_by`.

#### Dépendance HTTP

- `UPSTREAM_DEPENDENCY_DOWN` : statut HTTP en échec, 5xx ou échec de connexion ; bloquant.
- `UPSTREAM_LATENCY_DEGRADATION` : HTTP disponible, mais budget SLA dépassé ; bloquant.

Les providers de données réalisent surtout disponibilité, handshake, ping, capacité de connexions, rôle, mémoire et latence. Ils ne constituent pas une analyse SQL ou applicative complète. Redis distant authentifié peut produire `UNKNOWN` lorsque le secret ne peut pas être transmis de manière sûre à la CLI.

### 3.5 Incidents distribués et cascades multi-signaux

**Providers :** `dependency`, `postgres`, `redis`, `network`  
**Catalogue/policy :** `catalogs/distributed.yaml`, `policies/distributed.yaml`  
**Action :** `restart_application`, risque `HIGH`

| Situation | Lecture de la signature | Traitement |
|---|---|---|
| `DISTRIBUTED_HEALTHY` | HTTP, PostgreSQL, Redis et port réseau opérationnels | `ALLOW` possible |
| `DATABASE_CONNECTIVITY_FAILURE` | HTTP en échec, PostgreSQL et port en échec, Redis sain | `BLOCK` |
| `DATABASE_POOL_EXHAUSTION_CASCADE` | SLA dégradé, pool PostgreSQL épuisé, PostgreSQL joignable, Redis sain | `BLOCK` |
| `CACHE_FAILURE_DATABASE_OVERLOAD` | Pression mémoire Redis et latence PostgreSQL dégradée | `BLOCK` |
| `UPSTREAM_MICROSERVICE_OUTAGE` | HTTP et circuit breaker en échec, base et cache sains | `BLOCK` |
| `DISTRIBUTED_SPLIT_BRAIN_OR_READ_ONLY` | PostgreSQL en recovery/read-only, Redis sain | `BLOCK` |
| `TOTAL_NETWORK_PARTITION` | Port réseau, PostgreSQL et Redis tous injoignables | `BLOCK` |

Ces situations sont des signatures explicites, pas un calcul probabiliste de cause racine. Elles exigent souvent des combinaisons précises; un symptôme partiel ou une preuve inconnue ne permet pas de conclure à la situation correspondante.

### 3.6 Docker et conteneurs

**Provider :** enregistré sous `docker` et `container`  
**Catalogue/policy :** `catalogs/docker.yaml`, `policies/docker.yaml`  
**Action :** `restart_container`, risque `LOW`

| Situation | Signature | Traitement |
|---|---|---|
| `CONTAINER_HEALTHY` | Existe, tourne, health check et code de sortie nominaux | Situation saine, non autorisée comme cible de redémarrage |
| `CONTAINER_STOPPED` | Existe mais ne tourne pas | `ALLOW` possible |
| `CONTAINER_CRASH_LOOP` | Redémarrages répétés | `ALLOW` possible |
| `CONTAINER_UNHEALTHY` | Tourne mais health check en échec | `ALLOW` possible |
| `CONTAINER_NOT_FOUND` | Conteneur absent | `BLOCK` |

Les logs et le code de sortie sont des preuves complémentaires. La situation `CONTAINER_CRASH_LOOP` ne requiert toutefois que `container.restarting: FAIL`; les logs et le code de sortie n'affinent pas actuellement la signature. Les états health `starting`, inconnus ou les erreurs du daemon deviennent `UNKNOWN` et peuvent bloquer.

### 3.7 Kubernetes

**Provider :** enregistré sous `k8s` et `kubernetes`  
**Catalogue/policy :** `catalogs/kubernetes.yaml`, `policies/kubernetes.yaml`  
**Action :** `restart_deployment`, risque `HIGH`

| Situation | Signature | Traitement |
|---|---|---|
| `K8S_POD_HEALTHY` | Pod running, containers prêts, pod schedulé, nœud prêt | `ALLOW` possible |
| `K8S_CRASH_LOOP_BACKOFF` | CrashLoopBackOff répété | `BLOCK` |
| `K8S_OOM_KILLED` | OOMKilled ou code 137 | `BLOCK` |
| `K8S_IMAGE_PULL_FAILURE` | ImagePullBackOff ou ErrImagePull | `BLOCK` |
| `K8S_CONFIG_OR_SECRET_MISSING` | ConfigMap/Secret ou variable requise absente | `BLOCK` |
| `K8S_INSUFFICIENT_CLUSTER_RESOURCES` | Pod Pending/Unschedulable | `BLOCK` |
| `K8S_NODE_NOT_READY_OR_PRESSURE` | Pod schedulé mais nœud NotReady ou sous pression | `BLOCK` |

L'implémentation utilise `kubectl` en lecture seule avec confinement de namespace. La policy exige explicitement phase, readiness et scheduling; les situations cataloguées qui demandent d'autres preuves ne peuvent pas matcher si ces signaux ne sont pas disponibles. Une mention historique de non-support Kubernetes subsiste dans `PRODUCT_CONTRACT.md`, en contradiction avec le code, le README, le catalogue, la policy et les tests actuels.

## 4. Synthèse de la couverture décisionnelle

Les catalogues contiennent des situations observables qui ne sont pas toutes reliées à une décision :

- `DISK_PRESSURE` et `NETWORK_UNREACHABLE` figurent dans le catalogue Nginx sans être dans `policies/nginx.yaml`.
- `PROCESS_CPU_SATURATION`, `PROCESS_MEMORY_PRESSURE` et `PROCESS_FD_EXHAUSTION` sont collectées et cataloguées, mais absentes des listes `allow` et `blocked_by` de la policy processus.
- `REDIS_REPLICATION_BROKEN` est cataloguée mais absente de `policies/data.yaml`.
- `mysql.read_only`, `mysql.latency_ms`, `process.thread_count`, les logs de conteneurs et plusieurs mesures de latence sont utiles pour l'explication mais n'activent pas, à eux seuls, une situation décisionnelle.
- Le catalogue `system.yaml` contient des situations transverses de disque, réseau et processus, sans policy dédiée correspondante.

La différence est importante : « provider capable d'observer » ne signifie pas « incident capable de modifier la décision ». Une policy V2 ne peut autoriser que les situations listées dans `allow`, et bloque une situation explicitement présente dans `blocked_by`; faute de match, elle bloque par absence de situation autorisée.

## 5. Principaux invariants de sûreté

1. **Fail-closed sur l'incertitude pertinente :** `UNKNOWN` est distinct de `FAIL`, mais la policy décide si l'inconnu est bloquant. Le défaut contractuel est `BLOCK`.
2. **Priorité des décisions :** `BLOCK > HUMAN_REVIEW > ALLOW`.
3. **Pas d'influence de la recommandation :** le texte de recommandation est produit après la décision et reste advisory.
4. **Séparation des responsabilités :** les providers collectent; ils ne connaissent ni les policies ni la décision.
5. **Validation de namespace :** un provider ne peut pas émettre librement des observations dans le namespace d'un autre provider.
6. **Lecture seule :** les sondes inspectent l'environnement; l'exécution d'une remédiation reste à la charge de l'appelant ou de l'agent.
7. **Contrôle d'accès agent :** les capabilities limitent providers, opérations réseau, cibles, ports et budget de sondes; les providers dynamiques peuvent être soumis à une vérification de confiance/hash.

## 6. Couverture par les tests

Les tests présents couvrent notamment :

- les scénarios Nginx/TLS/systemd/filesystem : configuration invalide, certificats absents ou expirés, mismatch de clé, service et disque ;
- la chaîne réseau, avec distinctions DNS, route, hôte, refus TCP, TLS et HTTP ;
- les états de processus, y compris zombie et attente I/O, ainsi que les métriques CPU/mémoire/descripteurs au niveau provider ;
- les providers PostgreSQL, MySQL, Redis et dépendance HTTP ;
- les six scénarios distribués anormaux annoncés par les tests ;
- les états Docker et Kubernetes ;
- les invariants d'architecture, l'intégrité de décision, les capabilities, le transport SSH et la confiance des providers.

Les limites de couverture à garder en tête sont :

- certaines situations saines complètes et certaines corrélations cataloguées ont une couverture moins directe que les scénarios d'échec ;
- les chemins Linux/Docker E2E ne sont pas équivalents à une exécution locale Windows et nécessitent leur environnement représentatif ;
- les situations non reliées à une policy n'ont pas de parcours décisionnel complet ;
- la collecte distante, les capabilities refusées et les preuves `UNKNOWN` sont surtout des comportements de sûreté, pas des preuves de cause racine.

## 7. Évaluation de la readiness production

### 7.1 Points qui permettent un usage contrôlé

- Le chemin critique est déterministe et fail-closed sur les preuves bloquantes et l'ambiguïté.
- La décision est séparée de la recommandation, et l'intégrité de la décision est vérifiée à chaque diagnostic.
- Les providers sont read-only dans le périmètre testé; la CLI valide notamment les hôtes SSH et les ports.
- Les observations portent leur provenance, leurs timestamps et leurs données sensibles sont redigées lors de la sérialisation.
- Les capabilities, le budget de sondes, la confiance des providers et le hash des plugins externes fournissent une base exploitable pour un harnais d'agent.
- Le dépôt possède une couverture unitaire large et des scénarios d'intégration pour les domaines principaux.

### 7.2 Conditions et bloqueurs avant usage critique ou autonome

1. **Contrat documentaire incohérent :** `PRODUCT_CONTRACT.md` indique encore que Kubernetes n'est pas supporté, alors que le provider, le catalogue, la policy, le README et les tests le couvrent. Il faut choisir le périmètre officiel et aligner le contrat avant release.
2. **Couverture décisionnelle incomplète :** plusieurs situations sont observables et cataloguées mais orphelines d'une policy (`DISK_PRESSURE`, `NETWORK_UNREACHABLE`, plusieurs saturations processus, `REDIS_REPLICATION_BROKEN`). Elles ne doivent pas être interprétées comme des autorisations ou des blocages métier sans policy explicite.
3. **Validation du contrat JSON à industrialiser :** le schéma `schemas/diagnosis-result.schema.json` existe et la sérialisation CLI est structurée, mais une validation CI systématique de chaque sortie E2E contre ce schéma doit être garantie avant publication.
4. **Dépendance à l'environnement :** la suite locale réussit sous Windows/Python 3.13, mais les providers Linux, systemd, Nginx, Docker, Kubernetes, SSH et les permissions TLS doivent être validés dans les environnements de production cibles.
5. **Sécurité opérationnelle :** l'accès au socket Docker équivaut pratiquement à root sur l'hôte; les clés TLS et les identifiants de bases exigent ACL, secret management, isolation et rotation adaptés. Le moteur ne doit jamais être confondu avec un exécuteur de remédiation.
6. **Résilience d'exploitation à prouver :** les SLO documentés, la surveillance des métriques, les timeouts, les limites de sondes, les logs et la gestion des sorties `UNKNOWN` doivent être testés en conditions de panne et intégrés à la procédure d'astreinte.

### 7.3 Classement de readiness

| Dimension | Évaluation | Commentaire |
|---|---|---|
| Fonctionnalité déterministe | **Prête sous périmètre** | 64 situations, 12 domaines de providers et 223 tests verts. |
| Sécurité du chemin de décision | **Bonne base** | Fail-closed, intégrité, capabilities et séparation read-only. |
| Couverture de diagnostic | **Partielle** | Les signatures connues sont solides, mais la cause racine hors catalogue n'est pas déduite. |
| Contrat et gouvernance | **À corriger avant release critique** | Contradiction Kubernetes et couverture policy incomplète. |
| Exploitation multi-environnements | **À valider sur cible** | Les tests locaux ne suffisent pas pour les dépendances Linux et les transports réels. |
| Remédiation autonome | **Non prête / hors périmètre** | Une intégration doit conserver `BLOCK` et `HUMAN_REVIEW` tels quels et refaire un diagnostic frais. |

## 8. Conclusion et recommandations

EvidenceTool diagnostique efficacement une famille structurée d'incidents d'infrastructure et de dépendances grâce à des signatures explicites et auditables. Sa force est la prudence décisionnelle : il refuse d'autoriser une remédiation lorsque les conditions attendues ne sont pas démontrées. Sa limite principale est volontaire et architecturale : il ne déduit pas une cause racine nouvelle; il reconnaît des situations préalablement cataloguées.

Recommandations prioritaires :

1. Corriger la contradiction Kubernetes dans `PRODUCT_CONTRACT.md`, puis figer une matrice officielle des plateformes et providers supportés.
2. Relier les situations actuellement orphelines à des policies explicites, ou documenter clairement qu'elles sont informatives uniquement.
3. Ajouter une signature et une policy pour `REDIS_REPLICATION_BROKEN` si cet incident doit interdire une remédiation.
4. Ajouter des scénarios de décision complets pour CPU, mémoire, descripteurs, `mysql.read_only`, latence et santé Kubernetes.
5. Ajouter en CI la validation de toutes les sorties JSON E2E contre `schemas/diagnosis-result.schema.json`.
6. Maintenir les E2E Linux/Docker/Kubernetes/SSH et une vérification distincte des permissions, secrets, timeouts et chemins distants avant chaque release.
7. Déployer d'abord en mode observation ou `HUMAN_REVIEW`, avec métriques et runbooks, puis n'autoriser une automatisation limitée qu'après validation du harnais appelant.

**Avis final :** EvidenceTool fournit une typologie de production solide et traçable pour les domaines couverts, avec une chaîne de décision actuellement saine selon les contrôles exécutés. Il est **production-ready sous conditions et avec supervision**, mais pas “ready” au sens d'une plateforme universelle ou d'un agent autonome autorisé à agir sans revalidation. Toute lecture opérationnelle doit distinguer une situation cataloguée, une preuve observée et une décision effectivement supportée par la policy.
