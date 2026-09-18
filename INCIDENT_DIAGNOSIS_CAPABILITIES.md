# Rapport d'Analyse — Typologie des Incidents de Production Diagnostiqués par EvidenceTool (v1.0.2)

**Date** : 18 Septembre 2026  
**Version** : `v1.0.2` (Branche `dev`)  
**Périmètre** : 12 Providers Opérationnels (`nginx`, `tls`, `systemd`, `docker`, `filesystem`, `network`, `process`, `postgres`, `mysql`, `redis`, `dependency`, `k8s`)  
**Catalogues** : 8 Catalogues de Situations (`nginx`, `docker`, `network`, `process`, `data`, `kubernetes`, `distributed`, `system`) + 2 Catalogues Causaux (`distributed`, `kubernetes`)  
**Policies** : 8 Politiques Décisionnelles couvrant 100% des situations définies sans exception

---

## 1. Vue d'Ensemble & Positionnement

EvidenceTool est un moteur de raisonnement opérationnel et de diagnostic factuel en lecture seule (*Read-Only Operational Reasoning Engine & Safety Gateway*). Il ne prend pas d'initiative hasardeuse : **il collecte des preuves vérifiables sans effet de bord, corrèle les états du système en situations traçables, reconstruit le graphe de causalité déterministe, isole la cause racine et décide si une action corrective est sûre (`ALLOW`), interdite (`BLOCK`), ou requiert un arbitrage (`HUMAN_REVIEW`)**.

```
┌────────────────────────────────────────────────────────┐
│             INCIDENT DISTRIBUÉ MULTI-COUCHES           │
└───────────────────────────┬────────────────────────────┘
                            │
       ┌────────────────────┼────────────────────┐
       ▼                    ▼                    ▼
[ COUCHE APPLICATIVE ] [ COUCHE DONNÉES ]  [ COUCHE RÉSEAU/TRANSPORT ]
• API HTTP 500         • Postgres unreachable • TCP/5432 Refused/Timeout
• Latency SLA Violated • Pool Exhausted       • DNS / Host ping PASS
• Process/Container OK • Redis PONG (Sain)   • Route OK
• K8s Pod / Node State • MySQL Max Connections• TLS Handshake
       │                    │                    │
       └────────────────────┼────────────────────┘
                            │
                            ▼
              [ FAITS OBSERVABLES COLLECTÉS ]
            (12 Providers, Zero Mutation Guarantee)
                            │
                            ▼
          [ ÉVALUATION DE SITUATION LOCALE V1.0.2 ]
         (Incertitude locale : SituationEvaluation)
                            │
                            ▼
           [ MOTEUR DE CAUSALITÉ DÉTERMINISTE ]
          (Graphe DAG, Precluded Hypotheses, Tri-State)
                            │
                            ▼
              [ DÉCISION & EXPLICABILITÉ ]
               BLOCK > HUMAN_REVIEW > ALLOW
```

---

## 2. Typologie des Incidents Diagnostiqués par Domaine

### A. Incidents Web & Reverse Proxy (`nginx`, `systemd`)

| Incident de Production | Symptôme Observé | Preuves & Détection Technique | Décision & Règle de Sécurité |
| :--- | :--- | :--- | :---: |
| **Erreur de Syntaxe de Configuration** | Nginx refuse de démarrer après modification de `nginx.conf`. | Probe `nginx.config_valid` via `nginx -t -c <path>`. Filtre les faux positifs de droits de logs. | 🛑 **BLOCK** (`NGINX_CONFIG_INVALID`) |
| **Service Inactif Sans Panne** | Le service Nginx est arrêté alors que tout le système est nominal. | `systemd.service_active: FAIL` + `nginx.config_valid: PASS` + `tls.*: PASS`. | 🟢 **ALLOW** (`NGINX_SERVICE_DOWN`)<br>Redémarrage autorisé (`restart_nginx`). |
| **Service Non Installé / Manquant** | Demande de redémarrage d'un service inexistant. | `systemd.service_exists: FAIL` via `systemctl show -p LoadState`. | 🛑 **BLOCK** (`NGINX_SERVICE_NOT_INSTALLED`) |

---

### B. Incidents Cryptographiques & Certificats TLS (`tls`)

| Incident de Production | Symptôme Observé | Preuves & Détection Technique | Décision & Règle de Sécurité |
| :--- | :--- | :--- | :---: |
| **Certificat Expiré** | Erreurs SSL côté clients (`SEC_ERROR_EXPIRED_CERTIFICATE`). | Probe `tls.certificate_valid` extrait les dates de validité via ASN.1 / OpenSSL. | 🛑 **BLOCK** (`TLS_CERTIFICATE_EXPIRED`) |
| **Désynchronisation Clé / Certificat** | Nginx échoue : `key values mismatch`. | Probe `tls.key_matches_certificate` extrait les clés publiques universelles (RSA, ECDSA, Ed25519). | 🛑 **BLOCK** (`TLS_KEY_MISMATCH`) |
| **Fichier Certificat ou Clé Manquant** | Déploiement incomplet ou chemin erroné. | Probes `tls.certificate_exists` et `tls.private_key_exists`. | 🛑 **BLOCK** (`TLS_CERTIFICATE_MISSING`) |

---

### C. Incidents Conteneurs & Orchestration Docker (`docker`)

| Incident de Production | Symptôme Observé | Preuves & Détection Technique | Décision & Règle de Sécurité |
| :--- | :--- | :--- | :---: |
| **CrashLoopBackOff Conteneur** | Conteneur redémarre en boucle continue. | Probe `container.restarting: FAIL` (`State.Restarting == true`) avec logs masqués. | 🟢 **ALLOW** (`CONTAINER_CRASH_LOOP`) |
| **Échec de Healthcheck Applicatif** | L'application est figée ou en deadlock interne. | Probe `container.health: FAIL` (`State.Health.Status == 'unhealthy'`). | 🟢 **ALLOW** (`CONTAINER_UNHEALTHY`) |
| **Arrêt / Crash Inattendu** | Conteneur à l'arrêt (`Exited`). | Probe `container.exists: PASS` et `container.running: FAIL`. | 🟢 **ALLOW** (`CONTAINER_STOPPED`) |
| **Conteneur Inexistant** | Demande sur un conteneur supprimé. | Probe `container.exists: FAIL`. | 🛑 **BLOCK** (`CONTAINER_NOT_FOUND`) |

---

### D. Incidents Orchestration Kubernetes (`k8s`)

| Incident de Production | Symptôme Observé | Preuves & Détection Technique | Décision & Règle de Sécurité |
| :--- | :--- | :--- | :---: |
| **Pod CrashLoopBackOff** | Pod Kubernetes redémarre en boucle. | Probe `k8s.container_crashloop: FAIL` (`waiting.reason == 'CrashLoopBackOff'`). | 🛑 **BLOCK** (`K8S_CRASH_LOOP_BACKOFF`) |
| **Pod Tué par OOM Killer (Code 137)** | Conteneur tué par dépassement de limite mémoire. | Probe `k8s.container_oom_killed: FAIL` (`exitCode == 137` / `reason == 'OOMKilled'`). | 🛑 **BLOCK** (`K8S_OOM_KILLED`)<br>Ajustement de `limits.memory` requis. |
| **Échec de Pull d'Image (Registry)** | Pod bloqué `ImagePullBackOff` ou `ErrImagePull`. | Probe `k8s.image_pull_status: FAIL`. | 🛑 **BLOCK** (`K8S_IMAGE_PULL_FAILURE`) |
| **ConfigMap ou Secret Manquant** | Erreur `CreateContainerConfigError`. | Probe `k8s.config_secret_status: FAIL`. | 🛑 **BLOCK** (`K8S_CONFIG_OR_SECRET_MISSING`) |
| **Ressources Cluster Insuffisantes** | Pod bloqué en `Pending` / `Unschedulable`. | Probe `k8s.pod_scheduled: FAIL` (ex: `0/8 nodes available: Insufficient cpu`). | 🛑 **BLOCK** (`K8S_INSUFFICIENT_CLUSTER_RESOURCES`) |
| **Nœud en Panne ou Sous Pression** | Nœud Kubernetes en `NotReady` ou `MemoryPressure`. | Probe `k8s.node_ready: FAIL`. | 🛑 **BLOCK** (`K8S_NODE_NOT_READY_OR_PRESSURE`) |

> **Garanties et Invariants Kubernetes (`DES-02`, `DES-03`) :**
> - **Confinement de Namespace** : Contrôle strict via `KubernetesCapability`. Interdiction absolue sur les namespaces système (`kube-system`, `kube-public`, `kube-node-lease`).
> - **Distinction Erreur de Transport vs Défaut** : `403 Forbidden` ou timeout d'API `kubectl` dégradent en `UNKNOWN` (`transport_status="failed"`). L'absence de preuve n'est jamais assimilée à un pod en échec (`FAIL`).
> - **Zero Mutation** : Commandes `kubectl get/describe` exécutées sous forme de listes d'arguments sans shell. Aucune action modificatrice autorisée.

---

### E. Incidents Système, Processus Noyau Linux & Filesystem (`process`, `filesystem`)

| Incident de Production | Symptôme Observé | Preuves & Détection Technique | Décision & Règle de Sécurité |
| :--- | :--- | :--- | :---: |
| **Blocage I/O Noyau (État D)** | Processus figé en attente I/O disque non interruptible. | Probe `process.state: FAIL` détecte l'état noyau `D` (*uninterruptible sleep*). | 🛑 **BLOCK** (`PROCESS_IO_WAIT`) |
| **Processus Zombie** | Processus orphelin défunt dans `/proc`. | Probe `process.zombie: FAIL` (état `Z`). | ⚠️ (`PROCESS_ZOMBIE`) |
| **Saturation CPU / Pression Mémoire** | Processus consomme > 90% CPU ou RAM. | Probes `process.cpu_usage` et `process.memory_usage` avec seuils configurables. | 🛑 **BLOCK** (`PROCESS_CPU_SATURATION`, `PROCESS_MEMORY_PRESSURE`) |
| **Épuisement des Descripteurs (FD)** | Erreur `Too many open files`. | Probe `process.open_files` compare `/proc/<pid>/fd` aux limites `/proc/<pid>/limits`. | 🛑 **BLOCK** (`PROCESS_FD_EXHAUSTION`) |
| **Saturation / Disque Plein** | Incapacité d'écrire des logs ou des données. | Probes `filesystem.disk_space_available` et `filesystem.disk_pressure`. | 🛑 **BLOCK** (`DISK_FULL`, `DISK_PRESSURE`) |

---

### F. Incidents Données, Middleware & Cache (`postgres`, `mysql`, `redis`)

| Incident de Production | Symptôme Observé | Preuves & Détection Technique | Décision & Règle de Sécurité |
| :--- | :--- | :--- | :---: |
| **Saturation Pool PostgreSQL** | `FATAL: remaining connection slots are reserved` / `too many clients`. | Probe `postgres.pool_exhaustion: FAIL` via `pg_isready` ou sonde SSLRequest. | 🛑 **BLOCK** (`POSTGRES_POOL_EXHAUSTED`) |
| **Split-Brain / Réplica Read-Only PostgreSQL** | Erreurs d'écriture applicatives sur la base. | Probe `postgres.is_in_recovery: FAIL` (nœud standby alors que primaire attendu). | 🛑 **BLOCK** (`POSTGRES_READ_ONLY_REPLICA`) |
| **Saturation Connexions MySQL** | Erreur `1040 (HY000): Too many connections`. | Probe `mysql.max_connections: FAIL` via décodage du handshake packet. | 🛑 **BLOCK** (`MYSQL_TOO_MANY_CONNECTIONS`) |
| **Saturation Mémoire Redis (OOM)** | Écritures rejetées (`OOM command not allowed`). | Probe `redis.memory_pressure: FAIL` via analyse RESP de `INFO memory` (`used_memory / maxmemory`). | 🛑 **BLOCK** (`REDIS_OOM_MAXMEMORY`) |
| **Coupure Réplication Redis** | Replica désynchronisé du master. | Probe `redis.role: FAIL` (`master_link_status: down`). | 🛑 **BLOCK** (`REDIS_REPLICATION_BROKEN`) |
| **Erreur d'Authentification Redis** | Erreur `NOAUTH` ou `WRONGPASS`. | Probe `redis.auth: FAIL`. | 🛑 **BLOCK** (`REDIS_AUTH_FAILURE`) |

---

### G. Incidents Dépendances Microservices & Latence SLA (`dependency`)

| Incident de Production | Symptôme Observé | Preuves & Détection Technique | Décision & Règle de Sécurité |
| :--- | :--- | :--- | :---: |
| **Dégradation Latence / Violation SLA** | Temps de réponse > SLA budget (ex: > 250ms). | Probe `dependency.sla_budget: FAIL` (`latency_ms > sla_budget_ms`). | 🛑 **BLOCK** (`UPSTREAM_LATENCY_DEGRADATION`) |
| **Circuit Breaker / Throttling** | API amont renvoie HTTP 503, 429 ou 504. | Probe `dependency.circuit_breaker: FAIL`. | 🛑 **BLOCK** (`UPSTREAM_DEPENDENCY_DOWN`) |

---

### H. Incidents Distribués Multi-Signaux (`distributed`)

| Incident de Production | Signatures Multi-Domaines Corrélées | Cause Racine Isolée | Décision Métier |
| :--- | :--- | :--- | :---: |
| **`DATABASE_CONNECTIVITY_FAILURE`** | API 500 (`dependency.http_status: FAIL`) + DB unreachable (`postgres.reachable: FAIL`) + TCP 5432 FAIL + Redis PASS. | Port DB fermé ou SG bloquant (pas de panne réseau globale). | 🛑 **BLOCK restart_app** |
| **`DATABASE_POOL_EXHAUSTION_CASCADE`** | API latence spike + DB reachable + Pool exhausted (`postgres.pool_exhaustion: FAIL`) + Redis PASS. | Saturation des connexions DB. | 🛑 **BLOCK restart_app** |
| **`CACHE_FAILURE_DATABASE_OVERLOAD`** | Redis OOM / FAIL + DB latence dégradée. | Tempête de requêtes (*cache stampede*) sur PostgreSQL. | 🛑 **BLOCK restart_app** |
| **`UPSTREAM_MICROSERVICE_OUTAGE`** | API 503 / Circuit breaker FAIL + DB locale PASS + Redis PASS. | Panne de dépendance externe critique. | 🛑 **BLOCK restart_app** |
| **`TOTAL_NETWORK_PARTITION`** | Port 5432 FAIL + Postgres FAIL + Redis FAIL. | Partition réseau globale / perte de passerelle. | 🛑 **BLOCK restart_app** |
