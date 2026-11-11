[English](README.md) | **Français**

# EvidenceTool (V1.0.6 — Moteur Déterministe de Raisonnement Causal Opérationnel)

> EvidenceTool n'automatise pas les actions en premier. Il rend d'abord les décisions opérationnelles explicables.

**EvidenceTool** est un moteur de raisonnement opérationnel et une passerelle de sécurité (*Safety Gateway*) en lecture seule, piloté par des politiques. Il reconstruit des chaînes causales vérifiables d'incidents à partir de preuves multi-domaines et impose des frontières strictes de remédiation pour les agents IA autonomes et les équipes SRE.

---

## ⚠️ Ce qu'EvidenceTool N'EST PAS

> [!IMPORTANT]
> **EvidenceTool décide, il n'exécute jamais.**
> Un statut `HUMAN_REVIEW` traité silencieusement comme `ALLOW` par le système appelant détruit l'intégralité du modèle de sécurité.
> N'utilisez pas EvidenceTool pour exécuter directement des commandes destructrices. Il s'agit uniquement d'un observateur, classificateur et verrou de décision.
> Les agents autonomes appelant EvidenceTool DOIVENT valider l'intégrité de la décision de façon indépendante (voir le [Guide d'Intégration pour Harness d'Agent](docs/integrations/agent-harness.fr.md)).

---

## Plateformes & Environnements Supportés

EvidenceTool est testé et vérifié sur les environnements suivants :
- **Ubuntu 22.04 LTS** (systemd + Nginx)
- **Debian 12** (systemd + Nginx)
- **Environnements Docker** (inspection de conteneurs, crash loops, état de santé)
- **Clusters Kubernetes** (Pods, ContainerStatuses, OOMKilled, CrashLoopBackOff, ImagePull, Scheduling, Nodes)
- **Bases de données & Middleware** (PostgreSQL 14-17, MySQL 8 / MariaDB, Redis 6-7 RESP)
- **Dépendances Microservices Distribuées** (Budgets de latence SLA pour API HTTP, coupe-circuits)
- **OpenTelemetry & Observabilité** (Prometheus, Grafana Tempo, Jaeger, OpenTelemetry Collector)
- Toute distribution Linux basée sur systemd avec coreutils standards POSIX

---

## Fournisseurs de Diagnostic Natifs (13 Domaines Natifs)

| Fournisseur | Namespace | Vérifications / Observations | Périmètre |
| :--- | :--- | :--- | :--- |
| **Nginx** | `nginx` | `nginx.config_valid` | Syntaxe de configuration, résolution de modules, filtrage d'erreurs en lecture seule |
| **TLS** | `tls` | `tls.certificate_exists`, `tls.certificate_valid`, `tls.private_key_exists`, `tls.key_matches_certificate` | Expiration de certificat, présence, concordance de clé publique/privée RSA/EC |
| **Systemd** | `systemd` | `systemd.service_exists`, `systemd.service_active` | État de chargement de l'unité de service, statut du démon |
| **Docker** | `docker` / `container` | `container.exists`, `container.running`, `container.restarting`, `container.health`, `container.exit_code`, `container.logs` | Inspection stricte en lecture seule, contrôles de santé, boucles de crash et OOM |
| **Filesystem** | `filesystem` | `filesystem.disk_space_available`, `filesystem.disk_pressure` | Seuils d'espace disque disponible, alertes de saturation du stockage |
| **Network** | `network` | `network.dns_resolvable`, `network.route_exists`, `network.host_reachable`, `network.port_reachable`, `network.tls_handshake`, `network.http_reachable` | Chaîne de preuves réseau déterministe, distinction TCP refusé vs timeout |
| **Process** | `process` | `process.exists`, `process.running`, `process.state`, `process.zombie`, `process.cpu_usage`, `process.memory_usage`, `process.open_files`, `process.thread_count` | Inspection approfondie du noyau Linux (états R/S/D/Z, CPU, mémoire, limites de descripteurs de fichiers) |
| **PostgreSQL** | `postgres` | `postgres.reachable`, `postgres.accepting_connections`, `postgres.pool_exhaustion`, `postgres.is_in_recovery`, `postgres.latency_ms` | Disponibilité, saturation du pool de connexions, détection de réplica en lecture seule |
| **MySQL** | `mysql` | `mysql.reachable`, `mysql.ping`, `mysql.max_connections`, `mysql.read_only`, `mysql.latency_ms` | Analyse bornée des paquets de handshake, détection de l'erreur 1040 (max connections), statut lecture seule |
| **Redis** | `redis` | `redis.reachable`, `redis.ping`, `redis.auth`, `redis.memory_pressure`, `redis.role`, `redis.latency_ms` | Protocole RESP borné, PING/PONG, saturation mémoire (OOM), état du lien de réplication |
| **Dependency** | `dependency` | `dependency.http_status`, `dependency.latency_ms`, `dependency.sla_budget`, `dependency.circuit_breaker` | Budget de latence SLA pour API amont, détection coupe-circuit HTTP 503/429/504, curl avec max-time |
| **Kubernetes** | `k8s` / `kubernetes` | `k8s.pod_phase`, `k8s.containers_ready`, `k8s.container_crashloop`, `k8s.container_oom_killed`, `k8s.image_pull_status`, `k8s.config_secret_status`, `k8s.pod_scheduled`, `k8s.node_ready` | Inspection kubectl en lecture seule avec confinement d'espace de noms et gestion des pannes de transport |
| **OpenTelemetry** | `otel` | `otel.metrics_reachable`, `otel.traces_reachable`, `otel.http_error_rate_high`, `otel.p99_latency_high`, `otel.active_traces_failing` | Requêtes bornées et sécurisées contre SSRF vers Prometheus (métriques) et Tempo/Jaeger (traces distribuées) |

---

## Le Flux d'Exécution

```
Incident
   │
   ▼
Frontière Statique de Confiance des Providers (13 Natifs + Plugins Approuvés par SHA-256)
   │
   ▼
Collecte d'Observations    (Locale OU Distante sans agent via SSH avec ConnectTimeout)
   │
   ▼
Évaluation des Preuves     (PASS / FAIL / UNKNOWN, fraîcheur appliquée, exceptions capturées)
   │
   ▼
Corrélation d'États        (Mappe les signatures de preuves vers les Situations & SituationEvaluation locale)
   │
   ▼
Moteur de Raisonnement Causal (Reconstruction du DAG causal, cause racine primaire, hypothèses écartées)
   │
   ▼
Évaluation de Politique    (V2 Situationnelle : situations autorisées & explicitement bloquantes)
   │
   ▼
Moteur de Décision         (BLOCK > HUMAN_REVIEW > ALLOW, invariant d'incertitude locale)
   │
   ▼
Validation d'Intégrité     (validate_decision_integrity — vérification des invariants)
   │
   ▼
Recommandation             (Consultative uniquement — ne peut altérer la Décision)
```

Rien dans ce projet ne modifie le système qu'il inspecte.

## Installation

```bash
pip install -e ".[dev,test]"   # ou dans un environnement virtuel
```

## Exemples d'Utilisation en CLI

```bash
# 1. Diagnostic Nginx (Sortie lisible par un humain)
evidencetool diagnose nginx

# 2. Sortie JSON structurée (le contrat contractuel — voir PRODUCT_CONTRACT.md Section 8)
evidencetool diagnose nginx --output json

# 3. Diagnostic de conteneur Docker
evidencetool diagnose docker \
  --policy policies/docker.yaml \
  --catalog catalogs/docker.yaml \
  -a container=production_web_app

# 4. Diagnostic de Pod Kubernetes
evidencetool diagnose k8s \
  --policy policies/kubernetes.yaml \
  --catalog catalogs/kubernetes.yaml \
  -a pod=api-service-789 -a namespace=production

# 5. Diagnostic Multi-Signaux Distribué
evidencetool diagnose dependency \
  --policy policies/distributed.yaml \
  --catalog catalogs/distributed.yaml \
  -a url=http://127.0.0.1:8080/health \
  -a redis_host=127.0.0.1 -a redis_port=6379 \
  -a db_host=127.0.0.1 -a db_port=5432 \
  -a port=5432

# 6. Diagnostic Distant SSH sans agent
evidencetool diagnose nginx --host prod-web-01

# 7. Politique explicite, catalogue et métriques Prometheus
evidencetool diagnose nginx \
  --policy policies/nginx.yaml \
  --catalog catalogs/nginx.yaml \
  -a service=nginx \
  -a config_path=/etc/nginx/nginx.conf \
  -a certificate_path=/etc/letsencrypt/live/example.com/fullchain.pem \
  -a private_key_path=/etc/letsencrypt/live/example.com/privkey.pem \
  --metrics-file ./evidencetool.prom
```

Codes de sortie standards pour scripts et CI :
- `0` = ALLOW
- `1` = BLOCK
- `2` = HUMAN_REVIEW
- `3` = INTEGRITY_VIOLATION

---

## SDK Python pour Agents IA (`evidencetool.agent`)

Les agents IA autonomes (LangChain, AutoGen, CrewAI, contrôleurs Kubernetes) peuvent évaluer les actions de remédiation proposées via une passerelle de sécurité strictement typée avant d'exécuter quoi que ce soit :

```python
from evidencetool.agent import AgentSafetyGate, AgentDiagnosisRequest

# 1. Initialisation de la passerelle avec politiques de capacités, catalogues et règles
gate = AgentSafetyGate(
    capability_policy="capabilities/agent-restricted.yaml",
    catalog="catalogs/distributed.yaml",
    default_policy="policies/distributed.yaml",
)

# 2. Soumission de l'action envisagée par l'agent pour évaluation déterministe
request = AgentDiagnosisRequest(
    agent_id="remediation-bot-42",
    action="restart_application",
    target="orders-api",
    context={
        "url": "http://127.0.0.1:8080/health",
        "db_host": "127.0.0.1",
        "db_port": "5432",
        "redis_host": "127.0.0.1",
        "redis_port": "6379",
        "target": "127.0.0.1",
        "port": "5432",
    }
)

result = gate.evaluate(request)

if result.is_allowed:
    # L'action est autorisée en toute sécurité
    print(f"Action AUTORISÉE par EvidenceTool : {result.status}")
else:
    # Action bloquée avec cause racine explicable
    print(f"Action BLOQUÉE : {result.reason}")
    print(f"Preuve cause racine : {result.root_cause_evidence}")
    print(f"Recommandation : {result.recommendation}")
    if result.trace_id:
        print(f"OTel Trace ID : {result.trace_id}")
```

---

## La Boucle Fermée de Confiance Opérationnelle (Modes A, B et C)

EvidenceTool unifie l'observabilité applicative de haut niveau avec la vérification physique en profondeur de l'infrastructure à travers trois modes complémentaires :

```
┌────────────────────────────────────────────────────────────────────────┐
│                        MODE A : INBOUND TELEMETRY                      │
│    Ingestion OTel/Prometheus/Tempo (Métriques, Latence, Spans d'erreurs)│
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Symptômes de surface
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   MODE C : HYBRID CAUSAL REASONING                     │
│   Corrèle les symptômes de surface avec les sondes physiques natives   │
│   (Pools Postgres, RAM Redis, Syntaxe Nginx, Clés TLS, Process)        │
│   DAG Causal : Découverte cause racine & Hypothèses écartées           │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Décision Déterministe
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        MODE B : OUTBOUND TRACING                       │
│   Émet les traces OpenTelemetry W3C du pipeline de raisonnement        │
│   Auditabilité complète exportée vers Jaeger / Tempo / APM             │
└────────────────────────────────────────────────────────────────────────┘
```

- **Mode A (Inbound External Telemetry)** : Ingère les métriques Prometheus externes et les traces distribuées Tempo/Jaeger via le provider `otel`. Se limite strictement à observer les valeurs brutes et délègue l'évaluation des seuils aux politiques déclaratives. Inclut une protection anti-SSRF, le rejet des redirections, des charges utiles bornées et la désensibilisation des identifiants.
- **Mode B (Outbound Distributed Tracing)** : Émet des spans OpenTelemetry structurés pour chaque phase du pipeline (`provider`, `evaluation`, `correlation`, `causality`, `decision`), en propageant le contexte via W3C `traceparent` sans altérer le `TracerProvider` de l'application hôte. Fonctionne en Python standard pur avec zéro dépendance externe, ou avec le SDK officiel OTel.
- **Mode C (Hybrid Causal Reasoning & Durcissement Causal)** : Relie les symptômes de surface (ex: erreurs 503 ou pics de latence) aux sondes système profondes (ex: épuisement de pool de connexions, blocages de processus, clés TLS invalides) via un graphe causal déclaratif (`PROPAGATES_TO`, `PRECLUDES`, `REQUIRES`). Garantit la détection des cycles avant arbitrage (C7), la complétude topologique (C8), l'absence de départage arbitraire en cas d'égalité de priorité (C9, C9b), la conservation de l'ambiguïté non classée (C10), l'isolation d'incertitude locale (C11), la réfutation explicite d'hypothèse (C12), l'absence de corrélation implicite non déclarée (C13), l'isolation d'atteignabilité du sous-graphe causal (C14, C19), la sémantique de chemin continu sans hallucinations de ramification (C15), la préservation des règles multiples par source (C16), et la validation strictement fail-closed sans coercition silencieuse des catalogues (C17, C18, C20-C23). Voir [docs/causality/hybrid-causal-reasoning.fr.md](docs/causality/hybrid-causal-reasoning.fr.md).

---

## Tracing OpenTelemetry (Mode B Outbound)

EvidenceTool émet des traces OpenTelemetry distribuées et structurées, projetant l'intégralité de son pipeline décisionnel dans vos backends d'observabilité (Jaeger, Grafana Tempo, Datadog) :
- **Span Racine** : `evidencetool.diagnosis`
- **Spans Enfants** :
  - `evidencetool.provider.<namespace>` (durée de collecte et volume d'observations)
  - `evidencetool.evaluation` (distribution PASS / FAIL / UNKNOWN)
  - `evidencetool.correlation` (détection de situations multi-signaux)
  - `evidencetool.causality` (cause racine, chaîne causale de propagation, hypothèses écartées)
  - `evidencetool.decision` (verdict de gouvernance et preuves bloquantes)

### Options CLI de Traçage

```bash
# 1. Exporter la trace vers un collecteur OpenTelemetry via OTLP/HTTP JSON :
evidencetool diagnose nginx \
  --otel-endpoint http://localhost:4318/v1/traces

# 2. Corréler avec une trace distribuée amont (W3C traceparent) :
evidencetool diagnose nginx \
  --traceparent 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01 \
  --otel-endpoint http://localhost:4318/v1/traces

# 3. Exporter la trace dans un fichier JSON local pour audit ou inspection hors-ligne :
evidencetool diagnose nginx \
  --otel-trace-file /var/log/evidencetool/traces/diagnosis-01.json

# 4. Activation transparente via variables d'environnement standards :
export OTEL_EXPORTER_OTLP_ENDPOINT="http://tempo.monitoring:4318"
export OTEL_SERVICE_NAME="evidencetool-prod"
export TRACEPARENT="00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
evidencetool diagnose nginx
```

Voir [docs/observability/opentelemetry.fr.md](docs/observability/opentelemetry.fr.md) pour le guide d'intégration exhaustif et la recette Docker Compose Jaeger.

---

## Exemple de Sortie Console

```
? systemd.service_active
✗ nginx.config_valid
✓ tls.certificate_exists
✓ tls.certificate_valid
✓ tls.private_key_exists
✓ tls.key_matches_certificate
? filesystem.disk_space_available

Policy:
restart_nginx

Decision:
BLOCK

Reason:
Situation 'NGINX_CONFIG_INVALID' is explicitly blocked by policy.

Blocking evidence:
- nginx.config_valid

Recommendation:
Run `nginx -t` locally to see the exact syntax error, then fix nginx.conf
before retrying.
```

---

## Configuration en Moindre Privilège (Production)

EvidenceTool est conçu pour s'exécuter sans aucun accès `sudo`, en respectant scrupuleusement le principe du moindre privilège.
Il nécessite uniquement un accès en lecture à certains fichiers sensibles comme les clés privées TLS (`tls.key_matches_certificate`).
Au lieu d'accorder des droits `sudo`, créez un compte de service dédié et utilisez les listes de contrôle d'accès Linux (ACLs) :

```bash
# 1. Créer un utilisateur et un groupe système dédiés (sans shell, sans sudo)
sudo groupadd --system evidencetool
sudo useradd --system --gid evidencetool --shell /usr/sbin/nologin --no-create-home evidencetool

# 2. Accorder l'accès en lecture spécifiquement aux clés TLS via ACL
sudo apt install -y acl
sudo setfacl -m g:evidencetool:r /etc/nginx/ssl/nginx.key
sudo setfacl -m g:evidencetool:r /etc/nginx/ssl/nginx.crt

# 3. Pour l'inspection Docker, ajouter l'utilisateur au groupe docker :
sudo usermod -aG docker evidencetool
```

---

## Tests & Vérification CI
 
```bash
# Exécuter les 292 tests unitaires et d'intégration avec couverture complète
pytest tests/ -v --cov=evidencetool --cov-report=term

# Tests opérationnels de bout en bout (E2E)
./tests/e2e/run.sh

# Suite Qualité de Code & DevSecOps (100% conforme)
ruff check src/ tests/
mypy src/
bandit -r src/ -c pyproject.toml
pip-audit
```

L'ensemble des 292 tests est validé avec un typage strict sur 54 fichiers sources, zéro avertissement de linter et zéro vulnérabilité de sécurité.

---

## Déclaration d'une Politique

Une politique diagnostique explique comment les preuves influencent une décision.
Une politique de capacités contrôle ce que l'appelant est autorisé à observer.

```yaml
version: "1.0"
action: restart_nginx
risk: LOW
schema: "v2"

allow:
  - NGINX_SERVICE_DOWN

blocked_by:
  - TLS_CERTIFICATE_MISSING
  - TLS_CERTIFICATE_EXPIRED
  - TLS_KEY_MISSING
  - TLS_KEY_MISMATCH
  - NGINX_SERVICE_NOT_INSTALLED
  - DISK_FULL
  - NGINX_CONFIG_INVALID

required_evidence:
  - id: nginx.config_valid
    on_unknown: BLOCK
  - id: tls.certificate_exists
    on_unknown: BLOCK
  - id: tls.certificate_valid
    on_unknown: BLOCK
  - id: tls.private_key_exists
    on_unknown: BLOCK
  - id: tls.key_matches_certificate
    on_unknown: BLOCK
  - id: systemd.service_exists
    on_unknown: BLOCK
  - id: systemd.service_active
    on_unknown: IGNORE
  - id: filesystem.disk_space_available
    on_unknown: IGNORE

human_approval: false
```

La précédence de décision est absolue et non-configurable : `BLOCK > HUMAN_REVIEW > ALLOW`. Une preuve bloquante ou une situation bloquée l'emporte toujours, quel que soit le niveau de risque ou le flag `human_approval`.

---

## Limitations Connues

Aucune remédiation automatique / exécution directe (par conception), aucun LLM dans le chemin critique déterministe de décision, aucun dashboard web, aucun score arbitraire 0-100. Voir `PRODUCT_CONTRACT.md` Section 10 pour la liste complète et ses justifications.
